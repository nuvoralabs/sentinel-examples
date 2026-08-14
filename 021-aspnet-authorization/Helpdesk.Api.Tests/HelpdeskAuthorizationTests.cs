using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using Helpdesk.Api;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Helpdesk.Api.Tests;

/// <summary>
/// The walkthrough in the README, asserted. Each test is one line of that story: who gets in, who
/// does not, and what the caller is shown of a queue they can only partly see.
/// </summary>
public sealed class HelpdeskAuthorizationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private static readonly Guid NorthTicket = Guid.Parse("aaaaaaaa-0000-0000-0000-00000000000a");
    private static readonly Guid BillingTicket = Guid.Parse("bbbbbbbb-0000-0000-0000-00000000000b");
    private static readonly Guid SouthTicket = Guid.Parse("cccccccc-0000-0000-0000-00000000000c");

    private readonly WebApplicationFactory<Program> _factory;

    public HelpdeskAuthorizationTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
    }

    private async Task<HttpClient> SignInAsync(string email)
    {
        var client = _factory.CreateClient();
        var response = await client.PostAsJsonAsync("/auth/login", new { email, password = HelpdeskSeed.Password });
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", body.RootElement.GetProperty("accessToken").GetString());
        return client;
    }

    [Fact]
    public async Task An_agent_reads_their_own_organizations_tickets()
    {
        var client = await SignInAsync(HelpdeskSeed.Agent);

        var response = await client.GetAsync($"/api/orgs/{HelpdeskComposition.NorthOrg}/tickets");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task The_same_agent_is_refused_another_organizations_tickets()
    {
        var client = await SignInAsync(HelpdeskSeed.Agent);

        // The organization comes from the route, so the question is about the organization asked
        // for — not the one the caller happens to belong to.
        var response = await client.GetAsync($"/api/orgs/{HelpdeskComposition.SouthOrg}/tickets");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Notes_are_readable_only_for_the_team_that_handles_the_ticket()
    {
        var client = await SignInAsync(HelpdeskSeed.Agent);

        var ownTeam = await client.GetAsync($"/api/tickets/{NorthTicket}/notes");
        var anotherTeam = await client.GetAsync($"/api/tickets/{BillingTicket}/notes");

        ownTeam.StatusCode.Should().Be(HttpStatusCode.OK);
        anotherTeam.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Closing_a_ticket_is_checked_against_that_tickets_organization()
    {
        var client = await SignInAsync(HelpdeskSeed.Agent);

        var north = await client.PostAsync($"/api/tickets/{NorthTicket}/close", content: null);
        var south = await client.PostAsync($"/api/tickets/{SouthTicket}/close", content: null);

        north.StatusCode.Should().Be(HttpStatusCode.OK);
        south.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task A_ticket_that_does_not_exist_is_refused_rather_than_checked_unbound()
    {
        var client = await SignInAsync(HelpdeskSeed.Agent);

        var response = await client.PostAsync($"/api/tickets/{Guid.NewGuid()}/close", content: null);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task A_plain_policy_naming_a_permission_guards_the_report()
    {
        var supervisor = await SignInAsync(HelpdeskSeed.Supervisor);
        var agent = await SignInAsync(HelpdeskSeed.Agent);

        // The endpoint is guarded by [Authorize(Policy = "helpdesk:global:reports_read")] — the
        // attribute a codebase migrating from stock authorization already has.
        (await supervisor.GetAsync("/api/reports")).StatusCode.Should().Be(HttpStatusCode.OK);
        (await agent.GetAsync("/api/reports")).StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task The_queue_shows_only_what_the_caller_may_see()
    {
        var supervisor = await SignInAsync(HelpdeskSeed.Supervisor);

        var response = await supervisor.GetAsync("/api/queue");
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        // The supervisor holds no note-reading grant at all, so the queue is empty and the query is
        // never run — rather than fetched and filtered afterwards.
        body.RootElement.GetProperty("visibility").GetString().Should().Be("None");
        body.RootElement.GetProperty("tickets").EnumerateArray().Should().BeEmpty();
    }

    [Fact]
    public async Task An_account_with_no_grants_is_refused_everywhere()
    {
        var client = await SignInAsync(HelpdeskSeed.Outsider);

        (await client.GetAsync($"/api/orgs/{HelpdeskComposition.SouthOrg}/tickets"))
            .StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await client.GetAsync("/api/reports")).StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Signing_in_is_required()
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync($"/api/orgs/{HelpdeskComposition.NorthOrg}/tickets");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }
}
