using System.Net;
using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace MultiOrg.Api.Tests;

public class MultiOrgTests
{
    private static async Task<JsonDocument> ReadJsonAsync(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync());

    // -----------------------------------------------------------------------------------------
    // Org context & org switch
    // -----------------------------------------------------------------------------------------

    [Fact]
    public async Task Org_switch_changes_effective_permissions_without_reauthentication()
    {
        await using var host = await MultiOrgTestHost.CreateAsync();

        // Org context selected at token mint: mara logs in into Acme.
        var acmeToken = await host.LoginAsync(MultiOrgWorld.AnalystEmail, MultiOrgWorld.AcmeId);
        var acmeReports = await host.SendAsync(HttpMethod.Get, "/reports", acmeToken);
        acmeReports.StatusCode.Should().Be(HttpStatusCode.OK);
        using (var json = await ReadJsonAsync(acmeReports))
        {
            json.RootElement.GetProperty("organizationId").GetGuid().Should().Be(MultiOrgWorld.AcmeId);
        }

        // Switching to Globex re-mints WITHOUT re-authentication — the library's
        // /auth/org/switch endpoint (session repointed, refresh family rotated)…
        var switched = await host.SendAsync(HttpMethod.Post, "/auth/org/switch", acmeToken,
            new { organizationId = MultiOrgWorld.GlobexId });
        switched.StatusCode.Should().Be(HttpStatusCode.OK);
        string globexToken;
        using (var json = await ReadJsonAsync(switched))
        {
            globexToken = json.RootElement.GetProperty("accessToken").GetString()!;
        }

        globexToken.Should().NotBe(acmeToken);

        // …and the same user's snapshot in the new (user, org) context no longer carries the
        // Acme-restricted read grant (per-(user, org) snapshots, org fencing).
        var globexReports = await host.SendAsync(HttpMethod.Get, "/reports", globexToken);
        globexReports.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Switching_into_an_org_the_caller_does_not_belong_to_is_403()
    {
        await using var host = await MultiOrgTestHost.CreateAsync();
        var token = await host.LoginAsync(MultiOrgWorld.OrgAdminEmail, MultiOrgWorld.AcmeId);

        // diana is a member of Acme only.
        var response = await host.SendAsync(HttpMethod.Post, "/auth/org/switch", token,
            new { organizationId = MultiOrgWorld.GlobexId });

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Token_minted_without_org_context_has_no_org_scoped_permissions()
    {
        await using var host = await MultiOrgTestHost.CreateAsync();

        // No organizationId at login: realm-level token, org-scoped grant not applicable.
        var token = await host.LoginAsync(MultiOrgWorld.AnalystEmail);

        var response = await host.SendAsync(HttpMethod.Get, "/reports", token);
        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    // -----------------------------------------------------------------------------------------
    // Delegated admin fencing
    // -----------------------------------------------------------------------------------------

    [Fact]
    public async Task Org_admin_reads_their_own_org_and_403s_on_the_other()
    {
        await using var host = await MultiOrgTestHost.CreateAsync();
        var token = await host.LoginAsync(MultiOrgWorld.OrgAdminEmail, MultiOrgWorld.AcmeId);

        var acme = await host.SendAsync(
            HttpMethod.Get, $"/sentinel-admin/orgs/{MultiOrgWorld.AcmeId}/users", token);
        acme.StatusCode.Should().Be(HttpStatusCode.OK);
        using (var json = await ReadJsonAsync(acme))
        {
            json.RootElement.GetProperty("items").EnumerateArray()
                .Select(u => u.GetProperty("email").GetString())
                .Should().Contain([MultiOrgWorld.OrgAdminEmail, MultiOrgWorld.AnalystEmail]);
        }

        // The denial comes from the DOMAIN layer's per-resource scope check — a stable
        // admin_scope problem, structurally impossible to bypass at a controller.
        var globex = await host.SendAsync(
            HttpMethod.Get, $"/sentinel-admin/orgs/{MultiOrgWorld.GlobexId}/users", token);
        globex.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await globex.Content.ReadAsStringAsync()).Should().Contain("admin_scope");
    }

    [Fact]
    public async Task Org_admin_cannot_mutate_the_other_org()
    {
        await using var host = await MultiOrgTestHost.CreateAsync();
        var token = await host.LoginAsync(MultiOrgWorld.OrgAdminEmail, MultiOrgWorld.AcmeId);

        var rename = await host.SendAsync(
            HttpMethod.Patch, $"/sentinel-admin/orgs/{MultiOrgWorld.GlobexId}", token,
            new { displayName = "Hijacked" });
        rename.StatusCode.Should().Be(HttpStatusCode.Forbidden);

        var roleInGlobex = await host.SendAsync(HttpMethod.Post, "/sentinel-admin/roles", token,
            new { organizationId = MultiOrgWorld.GlobexId, key = "intruder", displayName = "Intruder" });
        roleInGlobex.StatusCode.Should().Be(HttpStatusCode.Forbidden,
            "creating a role in an unmanaged org is exactly the per-resource fence");
    }

    [Fact]
    public async Task Realm_admin_reaches_both_organizations()
    {
        await using var host = await MultiOrgTestHost.CreateAsync();
        var token = await host.LoginAsync(MultiOrgWorld.RealmAdminEmail);

        foreach (var orgId in new[] { MultiOrgWorld.AcmeId, MultiOrgWorld.GlobexId })
        {
            var response = await host.SendAsync(HttpMethod.Get, $"/sentinel-admin/orgs/{orgId}/users", token);
            response.StatusCode.Should().Be(
                HttpStatusCode.OK, "global manage is a distinct scope that spans orgs");
        }
    }

    [Fact]
    public async Task Admin_and_app_endpoints_require_authentication()
    {
        await using var host = await MultiOrgTestHost.CreateAsync();

        (await host.Client.GetAsync($"/sentinel-admin/orgs/{MultiOrgWorld.AcmeId}/users"))
            .StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await host.Client.GetAsync("/reports"))
            .StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }
}
