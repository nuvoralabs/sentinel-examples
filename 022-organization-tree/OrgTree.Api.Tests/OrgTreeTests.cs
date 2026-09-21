using System.Net;
using System.Text.Json;
using FluentAssertions;
using OrgTree.Api;
using Xunit;

namespace OrgTree.Api.Tests;

public class OrgTreeTests
{
    // -----------------------------------------------------------------------------------------
    // Token contract: org = tenant root, ou = acting node
    // -----------------------------------------------------------------------------------------

    [Fact]
    public async Task Login_lands_on_the_membership_node_and_mints_org_plus_ou()
    {
        await using var host = await OrgTreeTestHost.CreateAsync();

        // Mara is a member of North only: no node requested → she lands there.
        var token = await host.LoginAsync(OrgTreeWorld.PhysicianEmail);
        using (var claims = OrgTreeTestHost.Claims(token))
        {
            claims.RootElement.GetProperty("org").GetGuid().Should().Be(OrgTreeWorld.Group.Id, "org is the tenant root");
            claims.RootElement.GetProperty("ou").GetGuid().Should().Be(OrgTreeWorld.North.Id, "ou is the acting node");
        }

        var me = await host.SendAsync(HttpMethod.Get, "/profile/me", token);
        me.StatusCode.Should().Be(HttpStatusCode.OK);
        using var json = await OrgTreeTestHost.JsonOf(me);
        json.RootElement.GetProperty("organizationId").GetGuid().Should().Be(OrgTreeWorld.North.Id);
        json.RootElement.GetProperty("rootOrganizationId").GetGuid().Should().Be(OrgTreeWorld.Group.Id);
    }

    // -----------------------------------------------------------------------------------------
    // Cascade and node switch
    // -----------------------------------------------------------------------------------------

    [Fact]
    public async Task A_grant_at_the_region_reaches_its_clinics_but_not_another_region()
    {
        await using var host = await OrgTreeTestHost.CreateAsync();
        var north = await host.LoginAsync(OrgTreeWorld.PhysicianEmail);

        // Switching to Lakeside is allowed: it sits beneath the membership node.
        var switched = await host.SwitchAsync(north, OrgTreeWorld.Lakeside.Id);
        switched.StatusCode.Should().Be(HttpStatusCode.OK);
        string lakeside;
        using (var json = await OrgTreeTestHost.JsonOf(switched))
        {
            lakeside = json.RootElement.GetProperty("accessToken").GetString()!;
        }

        // The read grant sits at North with Inherit, so it applies at Lakeside.
        var charts = await host.SendAsync(HttpMethod.Get, "/charts", lakeside);
        charts.StatusCode.Should().Be(HttpStatusCode.OK);
        using (var json = await OrgTreeTestHost.JsonOf(charts))
        {
            json.RootElement.GetProperty("organizationId").GetGuid().Should().Be(OrgTreeWorld.Lakeside.Id);
            json.RootElement.GetProperty("rootOrganizationId").GetGuid().Should().Be(OrgTreeWorld.Group.Id);
        }

        // Bayview is in the other region: neither a membership nor beneath one.
        var sideways = await host.SwitchAsync(lakeside, OrgTreeWorld.Bayview.Id);
        sideways.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    // -----------------------------------------------------------------------------------------
    // Delegated admin on the tree
    // -----------------------------------------------------------------------------------------

    [Fact]
    public async Task Manage_at_a_node_covers_its_subtree_and_nothing_beside_it()
    {
        await using var host = await OrgTreeTestHost.CreateAsync();

        var director = await host.LoginAsync(OrgTreeWorld.RegionDirectorEmail);
        (await host.SendAsync(HttpMethod.Get, $"/sentinel-admin/orgs/{OrgTreeWorld.Lakeside.Id}/users", director))
            .StatusCode.Should().Be(HttpStatusCode.OK, "Lakeside is beneath North");
        (await host.SendAsync(HttpMethod.Get, $"/sentinel-admin/orgs/{OrgTreeWorld.Hillcrest.Id}/users", director))
            .StatusCode.Should().Be(HttpStatusCode.OK, "so is Hillcrest");
        var bayview = await host.SendAsync(HttpMethod.Get, $"/sentinel-admin/orgs/{OrgTreeWorld.Bayview.Id}/users", director);
        bayview.StatusCode.Should().Be(HttpStatusCode.Forbidden, "Bayview is in South");
        (await bayview.Content.ReadAsStringAsync()).Should().Contain("admin_scope");

        var clinicAdmin = await host.LoginAsync(OrgTreeWorld.ClinicAdminEmail);
        (await host.SendAsync(HttpMethod.Get, $"/sentinel-admin/orgs/{OrgTreeWorld.Lakeside.Id}/users", clinicAdmin))
            .StatusCode.Should().Be(HttpStatusCode.OK);
        (await host.SendAsync(HttpMethod.Get, $"/sentinel-admin/orgs/{OrgTreeWorld.Hillcrest.Id}/users", clinicAdmin))
            .StatusCode.Should().Be(HttpStatusCode.Forbidden, "a sibling clinic is out of reach");
        (await host.SendAsync(HttpMethod.Get, $"/sentinel-admin/orgs/{OrgTreeWorld.North.Id}/users", clinicAdmin))
            .StatusCode.Should().Be(HttpStatusCode.Forbidden, "and so is the parent");

        var groupAdmin = await host.LoginAsync(OrgTreeWorld.GroupAdminEmail);
        foreach (var node in new[] { OrgTreeWorld.North, OrgTreeWorld.South, OrgTreeWorld.Bayview })
        {
            (await host.SendAsync(HttpMethod.Get, $"/sentinel-admin/orgs/{node.Id}/users", groupAdmin))
                .StatusCode.Should().Be(HttpStatusCode.OK, "manage at the root covers the whole tree");
        }
    }

    [Fact]
    public async Task The_tree_is_browsable_with_the_tenant_level_labels()
    {
        await using var host = await OrgTreeTestHost.CreateAsync();
        var groupAdmin = await host.LoginAsync(OrgTreeWorld.GroupAdminEmail);

        var node = await host.SendAsync(HttpMethod.Get, $"/sentinel-admin/orgs/{OrgTreeWorld.Lakeside.Id}/node", groupAdmin);
        node.StatusCode.Should().Be(HttpStatusCode.OK);
        using (var json = await OrgTreeTestHost.JsonOf(node))
        {
            json.RootElement.GetProperty("label").GetString().Should().Be("Clinic");
            json.RootElement.GetProperty("node").GetProperty("pathKey").GetString().Should().Be("mercy/north/lakeside");
            json.RootElement.GetProperty("node").GetProperty("depth").GetInt32().Should().Be(2);
        }

        var ancestors = await host.SendAsync(HttpMethod.Get, $"/sentinel-admin/orgs/{OrgTreeWorld.Lakeside.Id}/ancestors", groupAdmin);
        using (var json = await OrgTreeTestHost.JsonOf(ancestors))
        {
            json.RootElement.EnumerateArray().Select(a => a.GetProperty("key").GetString())
                .Should().Equal("mercy", "north");
        }

        var users = await host.SendAsync(HttpMethod.Get,
            $"/sentinel-admin/orgs/{OrgTreeWorld.North.Id}/users?includeDescendants=true", groupAdmin);
        using (var json = await OrgTreeTestHost.JsonOf(users))
        {
            json.RootElement.GetProperty("items").EnumerateArray().Select(u => u.GetProperty("email").GetString())
                .Should().BeEquivalentTo(OrgTreeWorld.RegionDirectorEmail, OrgTreeWorld.ClinicAdminEmail, OrgTreeWorld.PhysicianEmail);
        }
    }

    // -----------------------------------------------------------------------------------------
    // Policies: tighten-only down the tree
    // -----------------------------------------------------------------------------------------

    [Fact]
    public async Task Policies_fold_down_the_tree_and_a_child_may_only_tighten()
    {
        await using var host = await OrgTreeTestHost.CreateAsync();
        var groupAdmin = await host.LoginAsync(OrgTreeWorld.GroupAdminEmail);

        // North set 60; the realm's 480 still applies in South.
        (await Effective(host, groupAdmin, OrgTreeWorld.Lakeside.Id)).Should().Be(60);
        (await Effective(host, groupAdmin, OrgTreeWorld.Bayview.Id)).Should().Be(480);

        // Loosening at Lakeside is refused with a stable reason, and nothing is written.
        var loosen = await host.SendAsync(HttpMethod.Put, $"/sentinel-admin/orgs/{OrgTreeWorld.Lakeside.Id}/policies", groupAdmin,
            new Dictionary<string, object> { ["session.idle_minutes"] = 120 });
        loosen.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await loosen.Content.ReadAsStringAsync()).Should().Contain("policy_loosens_parent");
        (await Effective(host, groupAdmin, OrgTreeWorld.Lakeside.Id)).Should().Be(60);

        // Tightening is fine.
        var tighten = await host.SendAsync(HttpMethod.Put, $"/sentinel-admin/orgs/{OrgTreeWorld.Lakeside.Id}/policies", groupAdmin,
            new Dictionary<string, object> { ["session.idle_minutes"] = 30 });
        tighten.StatusCode.Should().Be(HttpStatusCode.OK);
        (await Effective(host, groupAdmin, OrgTreeWorld.Lakeside.Id)).Should().Be(30);
        (await Effective(host, groupAdmin, OrgTreeWorld.Hillcrest.Id)).Should().Be(60, "a sibling is untouched");
    }

    private static async Task<double> Effective(OrgTreeTestHost host, string bearer, Guid nodeId)
    {
        var response = await host.SendAsync(HttpMethod.Get, $"/sentinel-admin/orgs/{nodeId}/policies/effective", bearer);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        using var json = await OrgTreeTestHost.JsonOf(response);
        return json.RootElement.GetProperty("session.idle_minutes").GetDouble();
    }

    // -----------------------------------------------------------------------------------------
    // Application assignment: allow at the root, deny at one clinic
    // -----------------------------------------------------------------------------------------

    [Fact]
    public async Task An_app_allowed_at_the_root_is_denied_at_one_clinic_only()
    {
        await using var host = await OrgTreeTestHost.CreateAsync();
        var north = await host.LoginAsync(OrgTreeWorld.PhysicianEmail);

        (await AppsOf(host, north)).Should().Equal([OrgTreeWorld.ChartsApp]);

        var lakeside = await Switched(host, north, OrgTreeWorld.Lakeside.Id);
        (await AppsOf(host, lakeside)).Should().Equal([OrgTreeWorld.ChartsApp], "inherited from the group");

        var hillcrest = await Switched(host, lakeside, OrgTreeWorld.Hillcrest.Id);
        (await AppsOf(host, hillcrest)).Should().BeEmpty("Hillcrest denies it, and deny wins");
    }

    private static async Task<string> Switched(OrgTreeTestHost host, string bearer, Guid nodeId)
    {
        var response = await host.SwitchAsync(bearer, nodeId);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        using var json = await OrgTreeTestHost.JsonOf(response);
        return json.RootElement.GetProperty("accessToken").GetString()!;
    }

    private static async Task<string[]> AppsOf(OrgTreeTestHost host, string bearer)
    {
        var response = await host.SendAsync(HttpMethod.Get, "/profile/me", bearer);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        using var json = await OrgTreeTestHost.JsonOf(response);
        return json.RootElement.GetProperty("apps").EnumerateArray().Select(a => a.GetString()!).ToArray();
    }
}
