using System.Net;
using FluentAssertions;
using Nuvora.Nexus.Sentinel.Identity;
using Provisioning.Api;
using Xunit;

namespace Provisioning.Api.Tests;

/// <summary>
/// The article-009 walk, as executable assertions: sct_ bearer auth, Users + Groups CRUD
/// under /scim/v2, soft-delete, and the two org fences (isolation + realm-wide userName
/// uniqueness).
/// </summary>
public class ScimProvisioningTests
{
    private static object UserBody(string userName, string displayName, string? externalId = null) => new
    {
        schemas = new[] { "urn:ietf:params:scim:schemas:core:2.0:User" },
        userName,
        displayName,
        externalId,
    };

    // ---------------------------------------------------------------------------------------
    // Users: create, list, filter
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Created_user_appears_in_the_org_listing_and_answers_the_userName_filter()
    {
        await using var host = await ProvisioningTestHost.CreateAsync();

        var create = await host.Client.SendAsync(host.Request(
            HttpMethod.Post, "/scim/v2/Users",
            UserBody("grace@acme.sample", "Grace Hopper", externalId: "okta|00u1")));
        create.StatusCode.Should().Be(HttpStatusCode.Created);
        string id;
        using (var json = await ProvisioningTestHost.ReadJsonAsync(create))
        {
            json.RootElement.GetProperty("userName").GetString().Should().Be("grace@acme.sample");
            json.RootElement.GetProperty("externalId").GetString().Should().Be("okta|00u1");
            json.RootElement.GetProperty("active").GetBoolean().Should().BeTrue();
            id = json.RootElement.GetProperty("id").GetString()!;
        }

        // The org listing shows the pre-seeded employee plus the new user.
        var list = await host.Client.SendAsync(host.Request(HttpMethod.Get, "/scim/v2/Users"));
        using (var json = await ProvisioningTestHost.ReadJsonAsync(list))
        {
            json.RootElement.GetProperty("totalResults").GetInt32().Should().Be(2);
        }

        // The eq filter (the supported subset) finds exactly the new user.
        var filtered = await host.Client.SendAsync(host.Request(
            HttpMethod.Get, "/scim/v2/Users?filter=" + Uri.EscapeDataString("userName eq \"grace@acme.sample\"")));
        using (var json = await ProvisioningTestHost.ReadJsonAsync(filtered))
        {
            json.RootElement.GetProperty("totalResults").GetInt32().Should().Be(1);
            json.RootElement.GetProperty("Resources")[0].GetProperty("id").GetString().Should().Be(id);
        }
    }

    // ---------------------------------------------------------------------------------------
    // Soft delete
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Delete_deactivates_instead_of_erasing_and_patch_active_true_restores()
    {
        await using var host = await ProvisioningTestHost.CreateAsync();

        var create = await host.Client.SendAsync(host.Request(
            HttpMethod.Post, "/scim/v2/Users", UserBody("leaver@acme.sample", "Lea Ver")));
        string id;
        using (var json = await ProvisioningTestHost.ReadJsonAsync(create))
        {
            id = json.RootElement.GetProperty("id").GetString()!;
        }

        // SCIM DELETE answers 204 — but the row survives as Deactivated (users anchor
        // audit history; PII erasure is a separate flow).
        var delete = await host.Client.SendAsync(host.Request(HttpMethod.Delete, $"/scim/v2/Users/{id}"));
        delete.StatusCode.Should().Be(HttpStatusCode.NoContent);

        var get = await host.Client.SendAsync(host.Request(HttpMethod.Get, $"/scim/v2/Users/{id}"));
        get.StatusCode.Should().Be(HttpStatusCode.OK);
        using (var json = await ProvisioningTestHost.ReadJsonAsync(get))
        {
            json.RootElement.GetProperty("active").GetBoolean().Should().BeFalse();
        }

        (await host.Store.GetOrgUserAsync(ProvisioningWorld.AcmeId, Guid.Parse(id)))!
            .Status.Should().Be(UserStatus.Deactivated);

        // PATCH replace active:true is the symmetric restore (what Azure AD sends on rejoin).
        var patch = await host.Client.SendAsync(host.Request(HttpMethod.Patch, $"/scim/v2/Users/{id}", new
        {
            schemas = new[] { "urn:ietf:params:scim:api:messages:2.0:PatchOp" },
            Operations = new[] { new { op = "replace", path = "active", value = true } },
        }));
        patch.StatusCode.Should().Be(HttpStatusCode.OK);

        (await host.Store.GetOrgUserAsync(ProvisioningWorld.AcmeId, Guid.Parse(id)))!
            .Status.Should().Be(UserStatus.Active);
    }

    // ---------------------------------------------------------------------------------------
    // Groups
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Group_membership_flows_through_patch_add_and_remove()
    {
        await using var host = await ProvisioningTestHost.CreateAsync();

        var user = await host.Client.SendAsync(host.Request(
            HttpMethod.Post, "/scim/v2/Users", UserBody("member@acme.sample", "Mem Ber")));
        string userId;
        using (var json = await ProvisioningTestHost.ReadJsonAsync(user))
        {
            userId = json.RootElement.GetProperty("id").GetString()!;
        }

        var group = await host.Client.SendAsync(host.Request(HttpMethod.Post, "/scim/v2/Groups", new
        {
            schemas = new[] { "urn:ietf:params:scim:schemas:core:2.0:Group" },
            displayName = "Engineering",
        }));
        group.StatusCode.Should().Be(HttpStatusCode.Created);
        string groupId;
        using (var json = await ProvisioningTestHost.ReadJsonAsync(group))
        {
            groupId = json.RootElement.GetProperty("id").GetString()!;
        }

        // PATCH add: the shape Azure AD and Okta send.
        var add = await host.Client.SendAsync(host.Request(HttpMethod.Patch, $"/scim/v2/Groups/{groupId}", new
        {
            schemas = new[] { "urn:ietf:params:scim:api:messages:2.0:PatchOp" },
            Operations = new[] { new { op = "add", path = "members", value = new[] { new { value = userId } } } },
        }));
        add.StatusCode.Should().Be(HttpStatusCode.OK);
        using (var json = await ProvisioningTestHost.ReadJsonAsync(add))
        {
            json.RootElement.GetProperty("members")[0].GetProperty("value").GetString().Should().Be(userId);
        }

        // PATCH remove with the filtered path form.
        var remove = await host.Client.SendAsync(host.Request(HttpMethod.Patch, $"/scim/v2/Groups/{groupId}", new
        {
            schemas = new[] { "urn:ietf:params:scim:api:messages:2.0:PatchOp" },
            Operations = new[] { new { op = "remove", path = $"members[value eq \"{userId}\"]" } },
        }));
        remove.StatusCode.Should().Be(HttpStatusCode.OK);
        using (var json = await ProvisioningTestHost.ReadJsonAsync(remove))
        {
            json.RootElement.GetProperty("members").GetArrayLength().Should().Be(0, "the member set is empty again");
        }
    }

    // ---------------------------------------------------------------------------------------
    // Org isolation
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task A_foreign_org_token_sees_nothing_and_touches_nothing()
    {
        await using var host = await ProvisioningTestHost.CreateAsync();

        var create = await host.Client.SendAsync(host.Request(
            HttpMethod.Post, "/scim/v2/Users", UserBody("secret@acme.sample", "Acme Only")));
        string id;
        using (var json = await ProvisioningTestHost.ReadJsonAsync(create))
        {
            id = json.RootElement.GetProperty("id").GetString()!;
        }

        // Globex's token: the Acme user is 404 — deliberately not 403, so the id's very
        // existence is not confirmed cross-org.
        (await host.Client.SendAsync(host.Request(HttpMethod.Get, $"/scim/v2/Users/{id}", bearer: "globex")))
            .StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await host.Client.SendAsync(host.Request(HttpMethod.Delete, $"/scim/v2/Users/{id}", bearer: "globex")))
            .StatusCode.Should().Be(HttpStatusCode.NotFound);

        // Even an exact filter finds nothing outside the token's org.
        var filtered = await host.Client.SendAsync(host.Request(
            HttpMethod.Get,
            "/scim/v2/Users?filter=" + Uri.EscapeDataString("userName eq \"secret@acme.sample\""),
            bearer: "globex"));
        using (var json = await ProvisioningTestHost.ReadJsonAsync(filtered))
        {
            json.RootElement.GetProperty("totalResults").GetInt32().Should().Be(0);
        }
    }

    [Fact]
    public async Task UserName_uniqueness_is_realm_wide_so_an_identity_cannot_be_stolen_across_orgs()
    {
        await using var host = await ProvisioningTestHost.CreateAsync();

        // ada@acme.sample already exists in Acme (seeded, never SCIM-provisioned). Globex's
        // IdP trying to provision the same userName into ITS org is refused — otherwise a
        // compromised tenant IdP could capture an existing identity.
        var stolen = await host.Client.SendAsync(host.Request(
            HttpMethod.Post, "/scim/v2/Users",
            UserBody(ProvisioningWorld.ExistingEmail, "Not Ada"), bearer: "globex"));

        stolen.StatusCode.Should().Be(HttpStatusCode.Conflict);
        using var json = await ProvisioningTestHost.ReadJsonAsync(stolen);
        json.RootElement.GetProperty("scimType").GetString().Should().Be("uniqueness");
    }

    // ---------------------------------------------------------------------------------------
    // Token auth
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Missing_garbage_and_revoked_tokens_answer_an_identical_401()
    {
        await using var host = await ProvisioningTestHost.CreateAsync();

        var missing = await host.Client.SendAsync(host.Request(HttpMethod.Get, "/scim/v2/Users", bearer: null));
        var garbage = await host.Client.SendAsync(host.Request(HttpMethod.Get, "/scim/v2/Users", bearer: "sct_not-a-real-token"));

        // Revoke the Acme token, then replay it.
        await host.RevokeAsync(host.AcmeToken);
        var revoked = await host.Client.SendAsync(host.Request(HttpMethod.Get, "/scim/v2/Users", bearer: "acme"));

        foreach (var response in new[] { missing, garbage, revoked })
        {
            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
            response.Headers.WwwAuthenticate.ToString().Should().Contain("Bearer");
        }

        // Anti-enumeration: unknown and revoked tokens produce byte-identical bodies.
        (await garbage.Content.ReadAsStringAsync()).Should().Be(await revoked.Content.ReadAsStringAsync());
    }
}
