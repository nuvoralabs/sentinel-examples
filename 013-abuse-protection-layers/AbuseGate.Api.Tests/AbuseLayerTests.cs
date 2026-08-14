using System.Net;
using System.Text.Json;
using AbuseGate.Api;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Nuvora.Nexus.Sentinel.Abuse;
using Nuvora.Nexus.Sentinel.Ports;
using Xunit;

namespace AbuseGate.Api.Tests;

/// <summary>
/// The article-013 walk, as executable assertions: each of the four layers in
/// isolation, the captcha band, and the two outage fail modes.
/// </summary>
public class AbuseLayerTests
{
    private static readonly AbuseLayerOptions Off = new() { Enabled = false };
    private static readonly AccountLockoutOptions LockoutOff = new() { Enabled = false };

    // ---------------------------------------------------------------------------------------
    // Layer 1: per-IP
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Layer1_per_ip_counts_all_attempts_and_blocks_the_ip_not_the_account()
    {
        await using var host = await GateTestHost.CreateAsync(new SentinelAbuseOptions
        {
            PerIp = new AbuseLayerOptions { Threshold = 3, Window = TimeSpan.FromMinutes(5) },
            PerIpAccount = Off, AccountLockout = LockoutOff, CredentialStuffing = Off,
        });

        // Three attempts from one IP — mixed accounts, mixed outcomes; the layer counts ALL.
        await host.AttemptAsync(GateWorld.AliceEmail, "wrong", ip: "203.0.113.9");
        await host.AttemptAsync(GateWorld.BobEmail, "wrong", ip: "203.0.113.9");
        await host.AttemptAsync(GateWorld.AliceEmail, "wrong", ip: "203.0.113.9");

        // The 4th attempt from that IP is refused BEFORE credentials are checked: the right
        // password gets the same 429.
        var blocked = await host.AttemptAsync(GateWorld.AliceEmail, GateWorld.Password, ip: "203.0.113.9");
        blocked.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);
        (await GateTestHost.ErrorCodeAsync(blocked)).Should().Be("blocked");

        // Same account, different IP: unaffected — the key is the address, not the user.
        var elsewhere = await host.AttemptAsync(GateWorld.AliceEmail, GateWorld.Password, ip: "198.51.100.7");
        elsewhere.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    // ---------------------------------------------------------------------------------------
    // Layer 2: per-IP-and-account
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Layer2_keys_on_the_ip_account_pair()
    {
        await using var host = await GateTestHost.CreateAsync(new SentinelAbuseOptions
        {
            PerIp = Off,
            PerIpAccount = new AbuseLayerOptions { Threshold = 2, Window = TimeSpan.FromMinutes(15) },
            AccountLockout = LockoutOff, CredentialStuffing = Off,
        });

        await host.AttemptAsync(GateWorld.AliceEmail, "wrong");
        await host.AttemptAsync(GateWorld.AliceEmail, "wrong");

        var blocked = await host.AttemptAsync(GateWorld.AliceEmail, GateWorld.Password);
        blocked.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);

        // Same IP, different account: a fresh pair, a fresh counter.
        var bob = await host.AttemptAsync(GateWorld.BobEmail, GateWorld.Password);
        bob.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    // ---------------------------------------------------------------------------------------
    // Layer 3: account lockout
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Layer3_locks_the_account_across_all_ips_and_expires_by_clock()
    {
        await using var host = await GateTestHost.CreateAsync(new SentinelAbuseOptions
        {
            PerIp = Off, PerIpAccount = Off, CredentialStuffing = Off,
            AccountLockout = new AccountLockoutOptions
            {
                Threshold = 2,
                Window = TimeSpan.FromMinutes(15),
                LockoutDuration = TimeSpan.FromMinutes(15),
            },
        });

        // Only FAILED verifications count here — and from any address.
        await host.AttemptAsync(GateWorld.AliceEmail, "wrong", ip: "203.0.113.1");
        await host.AttemptAsync(GateWorld.AliceEmail, "wrong", ip: "203.0.113.2");
        await host.AttemptAsync(GateWorld.AliceEmail, "wrong", ip: "203.0.113.3");

        // Locked: even the correct password from a brand-new IP is refused.
        var locked = await host.AttemptAsync(GateWorld.AliceEmail, GateWorld.Password, ip: "198.51.100.1");
        locked.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);
        (await GateTestHost.ErrorCodeAsync(locked)).Should().Be("blocked");

        // The lock is a TTL, not an operator ticket: advance the clock past LockoutDuration.
        host.Clock.UtcNow += TimeSpan.FromMinutes(16);
        var recovered = await host.AttemptAsync(GateWorld.AliceEmail, GateWorld.Password, ip: "198.51.100.1");
        recovered.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    // ---------------------------------------------------------------------------------------
    // Layer 4: credential stuffing
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Layer4_counts_distinct_identifiers_per_ip_not_raw_attempts()
    {
        await using var host = await GateTestHost.CreateAsync(new SentinelAbuseOptions
        {
            PerIp = Off, PerIpAccount = Off, AccountLockout = LockoutOff,
            CredentialStuffing = new AbuseLayerOptions { Threshold = 3, Window = TimeSpan.FromMinutes(10) },
        });

        // Three distinct identifiers from one IP (a stuffing run walks a breach list).
        await host.AttemptAsync("ghost1@example.com", "hunter2");
        await host.AttemptAsync("ghost2@example.com", "hunter2");
        await host.AttemptAsync("ghost3@example.com", "hunter2");

        // Re-trying a SEEN identifier does not advance the distinct count: still 401.
        var repeat = await host.AttemptAsync("ghost1@example.com", "hunter2");
        repeat.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        // The 4th DISTINCT identifier crosses the threshold.
        var blocked = await host.AttemptAsync("ghost4@example.com", "hunter2");
        blocked.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);
        (await GateTestHost.ErrorCodeAsync(blocked)).Should().Be("blocked");
    }

    // ---------------------------------------------------------------------------------------
    // The captcha band
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Past_half_the_threshold_humans_solve_a_captcha_and_proceed_bots_stall()
    {
        await using var host = await GateTestHost.CreateAsync(new SentinelAbuseOptions
        {
            CaptchaEnabled = true, // CaptchaFactor 0.5: threshold 6 ⇒ attempts 4-6 are the band
            PerIp = new AbuseLayerOptions { Threshold = 6, Window = TimeSpan.FromMinutes(5) },
            PerIpAccount = Off, AccountLockout = LockoutOff, CredentialStuffing = Off,
        });

        await host.AttemptAsync(GateWorld.AliceEmail, "wrong");
        await host.AttemptAsync(GateWorld.AliceEmail, "wrong");
        await host.AttemptAsync(GateWorld.AliceEmail, "wrong");

        // Attempt 4 enters the band: 429 captcha_required, carrying the public site key.
        var challenged = await host.AttemptAsync(GateWorld.AliceEmail, GateWorld.Password);
        challenged.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);
        using (var json = JsonDocument.Parse(await challenged.Content.ReadAsStringAsync()))
        {
            json.RootElement.GetProperty("error").GetString().Should().Be("captcha_required");
            json.RootElement.GetProperty("siteKey").GetString().Should().Be(GateWorld.CaptchaSiteKey);
        }

        // A wrong token is the same as no token: challenged again, never locked out.
        var wrongToken = await host.AttemptAsync(GateWorld.AliceEmail, GateWorld.Password, captchaToken: "nope");
        (await GateTestHost.ErrorCodeAsync(wrongToken)).Should().Be("captcha_required");

        // The solved captcha rides the SAME login request and the login completes.
        var solved = await host.AttemptAsync(
            GateWorld.AliceEmail, GateWorld.Password, captchaToken: GateWorld.CaptchaAnswer);
        solved.StatusCode.Should().Be(HttpStatusCode.OK);
        using (var json = JsonDocument.Parse(await solved.Content.ReadAsStringAsync()))
        {
            json.RootElement.GetProperty("status").GetString().Should().Be("ok");
        }
    }

    // ---------------------------------------------------------------------------------------
    // Fail modes
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task A_dead_counter_store_fails_open_or_closed_per_layer_policy()
    {
        // Fail-open (the default): the layer passes, the outage is an emitted event.
        await using (var open = await GateTestHost.CreateAsync(
            new SentinelAbuseOptions
            {
                PerIp = new AbuseLayerOptions
                {
                    Threshold = 3, Window = TimeSpan.FromMinutes(5),
                    FailureMode = AbuseFailureMode.FailOpen,
                },
                PerIpAccount = Off, AccountLockout = LockoutOff, CredentialStuffing = Off,
            },
            services => services.AddSingleton<IRateCounterStore>(new ThrowingCounterStore())))
        {
            var login = await open.AttemptAsync(GateWorld.AliceEmail, GateWorld.Password);
            login.StatusCode.Should().Be(HttpStatusCode.OK, "availability was chosen over protection");
        }

        // Fail-closed: the same outage refuses logins — indistinguishable from a real block.
        await using var closed = await GateTestHost.CreateAsync(
            new SentinelAbuseOptions
            {
                PerIp = new AbuseLayerOptions
                {
                    Threshold = 3, Window = TimeSpan.FromMinutes(5),
                    FailureMode = AbuseFailureMode.FailClosed,
                },
                PerIpAccount = Off, AccountLockout = LockoutOff, CredentialStuffing = Off,
            },
            services => services.AddSingleton<IRateCounterStore>(new ThrowingCounterStore()));

        var refused = await closed.AttemptAsync(GateWorld.AliceEmail, GateWorld.Password);
        refused.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);
        (await GateTestHost.ErrorCodeAsync(refused)).Should().Be("blocked");
    }

    /// <summary>Simulates a counter-store outage; per the port contract it throws, never decides policy.</summary>
    private sealed class ThrowingCounterStore : IRateCounterStore
    {
        public ValueTask<long> IncrementAsync(string key, TimeSpan window, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("counter store down");

        public ValueTask<long> GetAsync(string key, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("counter store down");

        public ValueTask ResetAsync(string key, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("counter store down");
    }
}
