using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Nuvora.Nexus.Sentinel.Relay.Middleware;
using Nuvora.Nexus.Relay.Tenancy;
using RelayBridge.Api;
using Xunit;

namespace RelayBridge.Api.Tests;

/// <summary>
/// The bridge over real HTTP: a Sentinel login token dispatches Relay commands;
/// [RequirePermission] is decided by Sentinel's evaluator (wildcards work, deny overrides,
/// default deny), and the handler observes the Sentinel subject + org as Relay's
/// AuthContext.UserId + TenantContext.
/// </summary>
public class RelayBridgeTests
{
    private sealed class Host : IAsyncDisposable
    {
        private readonly IHost _host;

        private Host(IHost host)
        {
            _host = host;
            Client = host.GetTestClient();
        }

        public HttpClient Client { get; }

        public static async Task<Host> CreateAsync()
        {
            var host = await new HostBuilder()
                .ConfigureWebHost(web => web
                    .UseTestServer()
                    .ConfigureServices(services =>
                    {
                        services.AddLogging();
                        services.AddRelayBridgeApi();
                    })
                    .Configure(app =>
                    {
                        app.UseRouting();
                        // Same pipeline order as Program.cs — the order IS the contract.
                        app.UseAuthentication();
                        app.UseSentinelRelayAuthContext();
                        app.UseRelayTenantContext();
                        app.UseEndpoints(e => e.MapRelayBridgeApi());
                    }))
                .StartAsync();
            await SentinelHost.InitializeAsync(host.Services); // same startup step as Program.cs
            return new Host(host);
        }

        public async Task<string> LoginAsync(string email)
        {
            var response = await Client.PostAsJsonAsync("/auth/login", new
            {
                email,
                password = RelayBridgeComposition.DemoPassword,
            });
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            var body = await response.Content.ReadFromJsonAsync<JsonElement>();
            return body.GetProperty("accessToken").GetString()!;
        }

        public async Task<HttpResponseMessage> DispatchAsync(string path, string? bearer)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, path);
            if (bearer is not null)
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            }

            return await Client.SendAsync(request);
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await _host.StopAsync();
            _host.Dispose();
        }
    }

    private static async Task<TicketObservation> ReadObservationAsync(HttpResponseMessage response) =>
        (await response.Content.ReadFromJsonAsync<TicketObservation>())!;

    [Fact]
    public async Task Command_executes_and_carries_the_sentinel_subject_and_tenant()
    {
        await using var host = await Host.CreateAsync();

        var response = await host.DispatchAsync(
            "/tickets/read", await host.LoginAsync(RelayBridgeComposition.RitaEmail));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var observed = await ReadObservationAsync(response);
        // The Guid v7 Sentinel subject IS Relay's AuthContext.UserId — no mapping table.
        observed.UserId.Should().Be(RelayBridgeComposition.RitaId);
        // The org claim minted into the token is the ambient Relay tenant.
        observed.TenantId.Should().Be(RelayBridgeComposition.SupportOrgId);
        observed.OrgClaim.Should().Be(RelayBridgeComposition.SupportOrgId.ToString("D"));
    }

    [Fact]
    public async Task Wildcard_grant_allows_because_the_engine_decides_not_string_equality()
    {
        await using var host = await Host.CreateAsync();

        // Rita's only grant is tickets:*:* — the literal "tickets:org:read" exists nowhere in
        // her grant set. Only Sentinel's pattern matching can conclude this is allowed.
        var read = await host.DispatchAsync(
            "/tickets/read", await host.LoginAsync(RelayBridgeComposition.RitaEmail));
        read.StatusCode.Should().Be(HttpStatusCode.OK);

        // The policy path (CloseTicketCommand) runs through the same evaluator.
        var close = await host.DispatchAsync(
            "/tickets/close", await host.LoginAsync(RelayBridgeComposition.RitaEmail));
        close.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ReadObservationAsync(close)).UserId.Should().Be(RelayBridgeComposition.RitaId);
    }

    [Fact]
    public async Task Missing_grant_is_forbidden_by_default_deny()
    {
        await using var host = await Host.CreateAsync();
        var ivan = await host.LoginAsync(RelayBridgeComposition.IvanEmail);

        (await host.DispatchAsync("/tickets/read", ivan)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await host.DispatchAsync("/tickets/close", ivan)).StatusCode
            .Should().Be(HttpStatusCode.Forbidden, "no grant covers tickets:org:close — default deny");
    }

    [Fact]
    public async Task Deny_grant_overrides_the_wildcard_allow()
    {
        await using var host = await Host.CreateAsync();
        var nadia = await host.LoginAsync(RelayBridgeComposition.NadiaEmail);

        (await host.DispatchAsync("/tickets/read", nadia)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await host.DispatchAsync("/tickets/close", nadia)).StatusCode
            .Should().Be(HttpStatusCode.Forbidden, "her explicit deny wins over her own tickets:*:*");
    }

    [Fact]
    public async Task Unauthenticated_dispatch_is_unauthorized()
    {
        await using var host = await Host.CreateAsync();

        (await host.DispatchAsync("/tickets/read", bearer: null)).StatusCode
            .Should().Be(HttpStatusCode.Unauthorized);
    }
}
