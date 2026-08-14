using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using Grammar.Api;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Grammar.Api.Tests;

/// <summary>
/// Golden-vector-style checks against the sample's HTTP surface: wildcard
/// allows, deny-overrides, ABAC conditions, team scope, and the visibility levels derived from
/// the same evaluation pass.
/// </summary>
public class PermissionGrammarTests
{
    // -----------------------------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------------------------

    /// <summary>Same composition as Program.cs, served through Microsoft.AspNetCore.TestHost.</summary>
    private static async Task<IHost> CreateHostAsync() => await new HostBuilder()
        .ConfigureWebHost(web => web
            .UseTestServer()
            .ConfigureServices(services => services.AddRouting())
            .Configure(app =>
            {
                app.UseRouting();
                app.UseEndpoints(endpoints => endpoints.MapGrammarEndpoints());
            }))
        .StartAsync();

    private static async Task<JsonDocument> PostAsync(HttpClient client, string path, object body)
    {
        var response = await client.PostAsJsonAsync(path, body);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync());
    }

    private static async Task<string> CheckOutcomeAsync(HttpClient client, object body)
    {
        using var json = await PostAsync(client, "/check", body);
        return json.RootElement.GetProperty("outcome").GetString()!;
    }

    private static async Task<string> VisibilityAsync(HttpClient client, string service, string action, string scope)
    {
        using var json = await PostAsync(client, "/visibility",
            new { subject = "dr-adams", service, action, scope });
        return json.RootElement.GetProperty("visibility").GetString()!;
    }

    // -----------------------------------------------------------------------------------------
    // Point checks
    // -----------------------------------------------------------------------------------------

    [Fact]
    public async Task Wildcard_grant_allows_any_action_in_its_segment()
    {
        using var host = await CreateHostAsync();
        using var client = host.GetTestClient();

        // records:org:* covers read...
        (await CheckOutcomeAsync(client, new { subject = "dr-adams", permission = "records:org:read" }))
            .Should().Be("allowed");

        // ...and actions published long after the grant was written.
        (await CheckOutcomeAsync(client, new { subject = "dr-adams", permission = "records:org:amend_diagnosis" }))
            .Should().Be("allowed");

        // But a wildcard is per-segment, not a prefix: other services stay default-denied.
        (await CheckOutcomeAsync(client, new { subject = "dr-adams", permission = "billing:org:read" }))
            .Should().Be("denied_by_default");
    }

    [Fact]
    public async Task Deny_overrides_the_wildcard_allow()
    {
        using var host = await CreateHostAsync();
        using var client = host.GetTestClient();

        // records:org:export matches BOTH the allow wildcard and the explicit deny — any
        // applicable deny wins over any number of allows.
        using var json = await PostAsync(client, "/check",
            new { subject = "dr-adams", permission = "records:org:export", trace = true });

        json.RootElement.GetProperty("outcome").GetString().Should().Be("denied_by_grant");
        json.RootElement.GetProperty("allowed").GetBoolean().Should().BeFalse();

        // The opt-in trace shows exactly which grant forced the deny and where it came from.
        var entries = json.RootElement.GetProperty("trace").EnumerateArray().ToArray();
        entries.Should().Contain(e =>
            e.GetProperty("outcome").GetString() == "denied"
            && e.GetProperty("source").GetString() == "policy:phi-lockdown");
    }

    [Fact]
    public async Task Abac_condition_gates_on_the_resource_attribute()
    {
        using var host = await CreateHostAsync();
        using var client = host.GetTestClient();

        // The labs grant carries a condition on resource.department.
        (await CheckOutcomeAsync(client, new
        {
            subject = "dr-adams",
            permission = "labs:org:view_results",
            resourceAttributes = new { department = "cardiology" },
        })).Should().Be("allowed");

        // Wrong department: the condition fails, the grant is inapplicable, default deny.
        (await CheckOutcomeAsync(client, new
        {
            subject = "dr-adams",
            permission = "labs:org:view_results",
            resourceAttributes = new { department = "oncology" },
        })).Should().Be("denied_by_default");

        // Missing attribute: conditions fail closed, never open.
        (await CheckOutcomeAsync(client, new { subject = "dr-adams", permission = "labs:org:view_results" }))
            .Should().Be("denied_by_default");
    }

    [Fact]
    public async Task Team_scope_requires_a_shared_team_and_fails_closed_without_one()
    {
        using var host = await CreateHostAsync();
        using var client = host.GetTestClient();
        var cardiology = GrammarDemo.CardiologyTeam;

        // Dr. Adams is on the cardiology team: a resource tagged with it is annotatable.
        (await CheckOutcomeAsync(client, new
        {
            subject = "dr-adams",
            permission = "records:team:annotate",
            resourceTeamIds = new[] { cardiology },
        })).Should().Be("allowed");

        // A team-scoped check WITHOUT resource teams fails closed.
        (await CheckOutcomeAsync(client, new { subject = "dr-adams", permission = "records:team:annotate" }))
            .Should().Be("denied_by_default");

        // Locum Jones holds the same grant but is on no team: no overlap, no access.
        (await CheckOutcomeAsync(client, new
        {
            subject = "locum-jones",
            permission = "records:team:annotate",
            resourceTeamIds = new[] { cardiology },
        })).Should().Be("denied_by_default");
    }

    // -----------------------------------------------------------------------------------------
    // Visibility — derived from the same pass
    // -----------------------------------------------------------------------------------------

    [Fact]
    public async Task Visibility_levels_mirror_the_point_check_semantics()
    {
        using var host = await CreateHostAsync();
        using var client = host.GetTestClient();

        // Unconditional allow, no matching deny ⇒ granted: list without row checks.
        (await VisibilityAsync(client, "records", "read", "org")).Should().Be("granted");

        // Unconditional deny ⇒ none: skip the query entirely.
        (await VisibilityAsync(client, "records", "export", "org")).Should().Be("none");

        // Conditioned allow ⇒ conditional: the caller must row-check with /check — visibility
        // can never be broader than evaluation because both are one pass.
        (await VisibilityAsync(client, "labs", "view_results", "org")).Should().Be("conditional");

        // No grant at all ⇒ none (default deny).
        (await VisibilityAsync(client, "billing", "read", "org")).Should().Be("none");
    }

    // -----------------------------------------------------------------------------------------
    // Input validation
    // -----------------------------------------------------------------------------------------

    [Fact]
    public async Task Malformed_permissions_and_unknown_subjects_are_400()
    {
        using var host = await CreateHostAsync();
        using var client = host.GetTestClient();

        // Not service:scope:action (the permission grammar).
        var badPermission = await client.PostAsJsonAsync("/check",
            new { subject = "dr-adams", permission = "records/read" });
        badPermission.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var badSubject = await client.PostAsJsonAsync("/check",
            new { subject = "dr-nobody", permission = "records:org:read" });
        badSubject.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }
}
