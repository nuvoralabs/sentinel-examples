using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using Governance.Api;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Nuvora.Nexus.Sentinel.Audit;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Xunit;

namespace Governance.Api.Tests;

/// <summary>
/// The governance loop over real HTTP: impersonation start → act token → banner →
/// end; consent mode holds the token until the target approves; a break-glass login rings the
/// alarms and evaluates capped; the drill marker flips the health check.
/// </summary>
public class GovernanceTests
{
    private sealed class Host : IAsyncDisposable
    {
        private readonly IHost _host;

        private Host(IHost host)
        {
            _host = host;
            Client = host.GetTestClient();
            Mailer = host.Services.GetRequiredService<RecordingMailer>();
        }

        public HttpClient Client { get; }

        public RecordingMailer Mailer { get; }

        public IServiceProvider Services => _host.Services;

        public static async Task<Host> CreateAsync(bool requireTargetConsent = false)
        {
            var host = await new HostBuilder()
                .ConfigureWebHost(web => web
                    .UseTestServer()
                    .ConfigureServices(services =>
                    {
                        services.AddLogging();
                        services.AddGovernanceApi(requireTargetConsent);
                    })
                    .Configure(app =>
                    {
                        app.UseRouting();
                        app.UseAuthentication();
                        app.UseEndpoints(e => e.MapGovernanceApi());
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
                password = GovernanceComposition.DemoPassword,
            });
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            var body = await response.Content.ReadFromJsonAsync<JsonElement>();
            return body.GetProperty("accessToken").GetString()!;
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await _host.StopAsync();
            _host.Dispose();
        }
    }

    private static HttpRequestMessage Authed(HttpMethod method, string url, string token, object? body = null)
    {
        var request = new HttpRequestMessage(method, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }

        return request;
    }

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response) =>
        await response.Content.ReadFromJsonAsync<JsonElement>();

    [Fact]
    public async Task Impersonation_start_mints_act_token_and_the_profile_carries_the_banner()
    {
        await using var host = await Host.CreateAsync();
        var adminToken = await host.LoginAsync(GovernanceComposition.AdminEmail);

        var start = await host.Client.SendAsync(Authed(
            HttpMethod.Post, "/sentinel-admin/impersonation/start", adminToken,
            new { targetUserId = GovernanceComposition.TargetId, reason = "support case 42" }));
        start.StatusCode.Should().Be(HttpStatusCode.OK);
        var started = await ReadJsonAsync(start);
        started.GetProperty("impersonation").GetProperty("status").GetString().Should().Be("active");
        var actToken = started.GetProperty("accessToken").GetString()!;

        // The impersonation token authenticates as the TARGET — with the banner block.
        var me = await host.Client.SendAsync(Authed(HttpMethod.Get, "/profile/me", actToken));
        me.StatusCode.Should().Be(HttpStatusCode.OK);
        var profile = await ReadJsonAsync(me);
        profile.GetProperty("id").GetGuid().Should().Be(GovernanceComposition.TargetId);
        profile.GetProperty("impersonation").GetProperty("actorId").GetGuid()
            .Should().Be(GovernanceComposition.AdminId, "the act claim names who is really behind the token");

        // An ordinary token carries no banner; ending the impersonation closes the record.
        var adminProfile = await ReadJsonAsync(
            await host.Client.SendAsync(Authed(HttpMethod.Get, "/profile/me", adminToken)));
        adminProfile.TryGetProperty("impersonation", out _).Should().BeFalse();

        var end = await host.Client.SendAsync(Authed(
            HttpMethod.Post, "/sentinel-admin/impersonation/end", adminToken));
        end.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ReadJsonAsync(end)).GetProperty("status").GetString().Should().Be("ended");
    }

    [Fact]
    public async Task Impersonation_without_the_grant_is_denied()
    {
        await using var host = await Host.CreateAsync();
        // The target holds no sentinel:*:impersonate grant — trying to impersonate the admin fails.
        var targetToken = await host.LoginAsync(GovernanceComposition.TargetEmail);

        var start = await host.Client.SendAsync(Authed(
            HttpMethod.Post, "/sentinel-admin/impersonation/start", targetToken,
            new { targetUserId = GovernanceComposition.AdminId, reason = "curiosity" }));

        start.StatusCode.Should().Be(HttpStatusCode.Forbidden, "the fence is the evaluator, not the UI");
    }

    [Fact]
    public async Task Consent_mode_holds_the_token_until_the_target_approves()
    {
        await using var host = await Host.CreateAsync(requireTargetConsent: true);
        var adminToken = await host.LoginAsync(GovernanceComposition.AdminEmail);

        // Start only REQUESTS: status pendingconsent, no token, and the target got the mail.
        var start = await host.Client.SendAsync(Authed(
            HttpMethod.Post, "/sentinel-admin/impersonation/start", adminToken,
            new { targetUserId = GovernanceComposition.TargetId, reason = "with consent" }));
        var started = await ReadJsonAsync(start);
        started.GetProperty("impersonation").GetProperty("status").GetString().Should().Be("pendingconsent");
        started.TryGetProperty("accessToken", out _).Should().BeFalse("no token before the target approves");

        var mail = host.Mailer.Sent.Should().ContainSingle(m =>
            m.To == GovernanceComposition.TargetEmail && m.Kind == "security_alert").Subject;
        var consentToken = mail.Data["token"];

        // The target approves through the public tokened endpoint (no session required).
        var approve = await host.Client.PostAsJsonAsync(
            "/sentinel-admin/impersonation/consent/approve", new { token = consentToken });
        approve.StatusCode.Should().Be(HttpStatusCode.OK);

        // Now the actor picks the token up from /active — and it works, banner included.
        var active = await ReadJsonAsync(await host.Client.SendAsync(
            Authed(HttpMethod.Get, "/sentinel-admin/impersonation/active", adminToken)));
        var actToken = active.GetProperty("accessToken").GetString()!;
        var profile = await ReadJsonAsync(
            await host.Client.SendAsync(Authed(HttpMethod.Get, "/profile/me", actToken)));
        profile.GetProperty("id").GetGuid().Should().Be(GovernanceComposition.TargetId);
        profile.GetProperty("impersonation").GetProperty("actorId").GetGuid()
            .Should().Be(GovernanceComposition.AdminId);
    }

    [Fact]
    public async Task Break_glass_login_alerts_operators_and_grants_evaluate_capped()
    {
        await using var host = await Host.CreateAsync();

        var token = await host.LoginAsync(GovernanceComposition.BreakGlassEmail);

        // Alarm on login: the configured operator got a security_alert mail…
        host.Mailer.Sent.Should().Contain(m =>
            m.To == "ops@clinic.sample" && m.Kind == "security_alert" && m.Data["alert"] == "breakglass_login");

        // …and the ledger has the login plus the mandatory-rotation flag.
        var audit = host.Services.GetRequiredService<IAuditStore>();
        var events = await audit.GetSecurityEventsForUserAsync(GovernanceComposition.BreakGlassId, 10);
        events.Select(e => e.Kind).Should().Contain(["breakglass.login", "breakglass.rotation_required"]);

        // The account's stored grant is *:*:* — but every evaluation path sees only the cap.
        var permissions = await ReadJsonAsync(await host.Client.SendAsync(
            Authed(HttpMethod.Get, "/profile/permissions", token)));
        var patterns = permissions.GetProperty("patterns").EnumerateArray()
            .Select(p => p.GetProperty("pattern").GetString())
            .ToArray();
        patterns.Should().BeEquivalentTo(
            ["sentinel:global:*", "records:global:read"],
            "the capping decorator intersects the broad grant with the policy's patterns");
    }

    [Fact]
    public async Task Drill_marker_flips_the_health_check_from_degraded_to_healthy()
    {
        await using var host = await Host.CreateAsync();
        // The break-glass account's capped sentinel:global:* covers sentinel:global:manage, so
        // the emergency session itself can read status and stamp the drill.
        var token = await host.LoginAsync(GovernanceComposition.BreakGlassEmail);

        // Never drilled → stale → the readiness surface degrades.
        var status = await ReadJsonAsync(await host.Client.SendAsync(
            Authed(HttpMethod.Get, "/sentinel-admin/break-glass/status", token)));
        status.GetProperty("drillStale").GetBoolean().Should().BeTrue();
        (await host.Client.GetStringAsync("/health")).Should().Be("Degraded");

        // Stamp the drill → healthy.
        var marker = await host.Client.SendAsync(Authed(
            HttpMethod.Post, "/sentinel-admin/break-glass/drill-login-marker", token));
        marker.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ReadJsonAsync(marker)).GetProperty("drillStale").GetBoolean().Should().BeFalse();
        (await host.Client.GetStringAsync("/health")).Should().Be("Healthy");
    }
}
