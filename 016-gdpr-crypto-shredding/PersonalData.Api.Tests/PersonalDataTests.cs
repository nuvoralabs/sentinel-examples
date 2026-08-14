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
using Nuvora.Nexus.Sentinel.Admin;
using Nuvora.Nexus.Sentinel.Audit;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Nuvora.Nexus.Sentinel.Ports;
using Nuvora.Nexus.Sentinel.Privacy;
using PersonalData.Api;
using Xunit;

namespace PersonalData.Api.Tests;

/// <summary>
/// The GDPR loop over real HTTP: export the bundle, erase with confirmation
/// (crypto-shred → anonymize → redact), prove login is impossible and the encrypted notes are
/// unrecoverable — and that the tamper-evident audit chain still verifies. Retention runs at
/// service level with a mutable clock, exactly as the library's own tests do.
/// </summary>
public class PersonalDataTests
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

        public IServiceProvider Services => _host.Services;

        public static async Task<Host> CreateAsync()
        {
            var host = await new HostBuilder()
                .ConfigureWebHost(web => web
                    .UseTestServer()
                    .ConfigureServices(services =>
                    {
                        services.AddLogging();
                        services.AddPersonalDataApi();
                    })
                    .Configure(app =>
                    {
                        app.UseRouting();
                        app.UseAuthentication();
                        app.UseEndpoints(e => e.MapPersonalDataApi());
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
                password = PersonalDataComposition.DemoPassword,
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
    public async Task Export_bundles_identity_sessions_and_history_for_the_dpo_only()
    {
        await using var host = await Host.CreateAsync();
        var admin = await host.LoginAsync(PersonalDataComposition.AdminEmail);
        var jane = await host.LoginAsync(PersonalDataComposition.JaneEmail); // session + login event

        var export = await host.Client.SendAsync(Authed(
            HttpMethod.Post, $"/sentinel-admin/privacy/export/{PersonalDataComposition.JaneId}", admin));
        export.StatusCode.Should().Be(HttpStatusCode.OK);
        var bundle = await ReadJsonAsync(export);
        bundle.GetProperty("user").GetProperty("email").GetString().Should().Be(PersonalDataComposition.JaneEmail);
        bundle.GetProperty("sessions").GetArrayLength().Should().BeGreaterThan(0);
        bundle.GetProperty("securityEvents").GetArrayLength()
            .Should().BeGreaterThan(0, "the login left history on the subject's ledger");

        // A non-admin gets a 403, never a partial bundle.
        (await host.Client.SendAsync(Authed(
            HttpMethod.Post, $"/sentinel-admin/privacy/export/{PersonalDataComposition.AdminId}", jane)))
            .StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Notes_encrypt_under_the_subject_key_and_decrypt_before_erasure()
    {
        await using var host = await Host.CreateAsync();
        var jane = await host.LoginAsync(PersonalDataComposition.JaneEmail);

        var stored = await host.Client.SendAsync(Authed(
            HttpMethod.Post, "/notes", jane, new { text = "allergy: penicillin" }));
        stored.StatusCode.Should().Be(HttpStatusCode.OK);

        // The vault only holds ciphertext; the shredder brings it back while the key exists.
        var notes = await ReadJsonAsync(await host.Client.GetAsync(
            $"/demo/notes/{PersonalDataComposition.JaneId}"));
        notes.GetProperty("notes").EnumerateArray().Select(n => n.GetString())
            .Should().ContainSingle().Which.Should().Be("allergy: penicillin");
    }

    [Fact]
    public async Task Erase_requires_confirmation_then_login_is_impossible()
    {
        await using var host = await Host.CreateAsync();
        var admin = await host.LoginAsync(PersonalDataComposition.AdminEmail);
        _ = await host.LoginAsync(PersonalDataComposition.JaneEmail);

        // Missing/wrong confirmation → 400, nothing happens.
        (await host.Client.SendAsync(Authed(
            HttpMethod.Post, $"/sentinel-admin/privacy/erase/{PersonalDataComposition.JaneId}", admin, new { })))
            .StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var erase = await host.Client.SendAsync(Authed(
            HttpMethod.Post, $"/sentinel-admin/privacy/erase/{PersonalDataComposition.JaneId}", admin,
            new { confirm = "erase" }));
        erase.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = await ReadJsonAsync(erase);
        result.GetProperty("userId").GetGuid().Should().Be(PersonalDataComposition.JaneId);
        result.GetProperty("sessionsRevoked").GetInt32().Should().BeGreaterThan(0);

        // The erased identity resolves to nobody — same anti-enumeration 401 as any unknown user.
        var login = await host.Client.PostAsJsonAsync("/auth/login", new
        {
            email = PersonalDataComposition.JaneEmail,
            password = PersonalDataComposition.DemoPassword,
        });
        login.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Erasure_shreds_the_key_redacts_history_and_the_chain_still_verifies()
    {
        await using var host = await Host.CreateAsync();
        var admin = await host.LoginAsync(PersonalDataComposition.AdminEmail);
        var jane = await host.LoginAsync(PersonalDataComposition.JaneEmail);
        await host.Client.SendAsync(Authed(HttpMethod.Post, "/notes", jane, new { text = "allergy: penicillin" }));

        var erase = await host.Client.SendAsync(Authed(
            HttpMethod.Post, $"/sentinel-admin/privacy/erase/{PersonalDataComposition.JaneId}", admin,
            new { confirm = "erase" }));
        erase.StatusCode.Should().Be(HttpStatusCode.OK);

        // 1. Crypto-shredded: the key is gone, so the note is unrecoverable — the ciphertext
        //    still sits in the vault, but nothing can ever read it again.
        var notes = await ReadJsonAsync(await host.Client.GetAsync(
            $"/demo/notes/{PersonalDataComposition.JaneId}"));
        notes.GetProperty("notes").EnumerateArray().Select(n => n.GetString())
            .Should().ContainSingle().Which.Should().Be("[unrecoverable]");

        // 2. History redacted, kinds kept: every event on Jane's ledger loses payload/IP/device.
        var audit = host.Services.GetRequiredService<IAuditStore>();
        var events = await audit.GetSecurityEventsForUserAsync(PersonalDataComposition.JaneId, 20);
        events.Should().NotBeEmpty("erasure redacts history, it does not rewrite it")
            .And.OnlyContain(e => e.DataJson == null && e.IpAddress == null && e.DeviceDescription == null);

        // 3. THE acceptance: the tamper-evident admin chain still verifies end to end.
        var verify = await ReadJsonAsync(await host.Client.GetAsync("/demo/audit/verify"));
        verify.GetProperty("firstBrokenSequence").ValueKind.Should().Be(JsonValueKind.Null);
    }

    [Fact]
    public async Task Retention_sweep_deletes_old_events_and_keeps_the_chain_intact()
    {
        // Service-level, with a mutable clock — the same composition the daily background
        // sweep (AddSentinelRetentionService) runs against.
        var clock = new MutableClock();
        var auditStore = new InMemoryAuditStore();
        var audit = new AuditService(auditStore, clock);
        var userId = Guid.NewGuid();

        await audit.RecordSecurityEventAsync(
            PersonalDataComposition.RealmId, "login.success", userId, ipAddress: "203.0.113.1");
        await audit.RecordAdminActionAsync(
            PersonalDataComposition.RealmId, Guid.NewGuid(), AdminActorKind.User,
            "user.suspended", "user", userId, after: new { Email = "old@clinic.sample" });

        clock.UtcNow += TimeSpan.FromDays(400);
        await audit.RecordSecurityEventAsync(
            PersonalDataComposition.RealmId, "login.success", userId, ipAddress: "203.0.113.2");

        var retention = new RetentionService(auditStore, clock, NoopEventSink.Instance,
            new SentinelRetentionOptions
            {
                SecurityEventRetention = TimeSpan.FromDays(365),
                AdminAuditRetention = TimeSpan.FromDays(365),
            });
        var result = await retention.RunOnceAsync();

        result.SecurityEventsDeleted.Should().Be(1, "only the 400-day-old event ages out");
        result.AuditPayloadsRedacted.Should().Be(1, "audit rows are never deleted — payloads age out");

        (await auditStore.GetSecurityEventsForUserAsync(userId, 10))
            .Should().ContainSingle().Which.IpAddress.Should().Be("203.0.113.2");
        (await audit.VerifyChainAsync(PersonalDataComposition.RealmId))
            .Should().BeNull("redaction must preserve chain integrity");
    }

    private sealed class MutableClock : ISentinelClock
    {
        public DateTimeOffset UtcNow { get; set; } = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);
    }
}
