using System.Net;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Nuvora.Nexus.Sentinel.Abuse;
using Nuvora.Nexus.Sentinel.AspNetCore;
using Nuvora.Nexus.Sentinel.AspNetCore.DependencyInjection;
using Nuvora.Nexus.Sentinel.AspNetCore.Endpoints;
using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Nuvora.Nexus.Sentinel.Login;
using Nuvora.Nexus.Sentinel.Tokens;

namespace AbuseGate.Api;

/// <summary>
/// The whole composition, shared by Program.cs and the test host. AddSentinel() wires
/// the abuse gate in front of every login by default — this sample only TUNES it, hands in
/// a captcha verifier, and (test hosts) swaps thresholds per scenario.
/// </summary>
public static class GateComposition
{
    /// <summary>
    /// Demo thresholds — small enough to trip with curl. Production keeps the defaults
    /// (per-IP 30/5m, per-IP+account 10/15m, lockout 5 fails/15m, stuffing 200 distinct/10m).
    /// </summary>
    public static SentinelAbuseOptions DemoOptions() => new()
    {
        CaptchaEnabled = true, // the soft band: past 50% of a threshold, humans may proceed
        PerIp = new AbuseLayerOptions { Threshold = 10, Window = TimeSpan.FromMinutes(5) },
        PerIpAccount = new AbuseLayerOptions { Threshold = 8, Window = TimeSpan.FromMinutes(15) },
        AccountLockout = new AccountLockoutOptions
        {
            Threshold = 5, Window = TimeSpan.FromMinutes(15), LockoutDuration = TimeSpan.FromMinutes(15),
        },
        CredentialStuffing = new AbuseLayerOptions { Threshold = 20, Window = TimeSpan.FromMinutes(10) },
    };

    public static IServiceCollection AddAbuseGateApi(
        this IServiceCollection services, SentinelAbuseOptions? abuse = null)
    {
        services.AddRouting();

        var identity = new InMemoryIdentityStore();
        services.AddSingleton(identity);
        services.AddSingleton<IUserStore>(identity);
        services.AddSingleton<IMfaStore>(identity);
        services.AddSingleton<ISessionStore>(identity);
        services.AddSingleton<ISubjectDataSource, GateSubjectSource>();

        services.Configure<SentinelTokenOptions>(o => o.Issuer = GateWorld.Issuer);
        services.AddSentinel(o =>
        {
            o.DefaultRealmId = GateWorld.RealmId;
            o.AllowDevelopmentDefaults = true; // ephemeral dev signing keys, explicit opt-in
        });
        services.AddSentinelAuthentication(o =>
        {
            o.Issuer = GateWorld.Issuer;
            o.Audience = GateWorld.Audience;
            o.DefaultRealmId = GateWorld.RealmId;
            o.Transport = SentinelTokenTransport.Bearer;
        });

        // Tuning: a concrete SentinelAbuseOptions registered AFTER AddSentinel wins over its
        // TryAdd of the IOptions-bound value (last registration wins in MS DI).
        services.AddSingleton(abuse ?? DemoOptions());

        // The captcha side of captcha_required: a verifier + the public site key the 429
        // carries. Real hosts call AddSentinelCaptcha (Turnstile/hCaptcha/reCAPTCHA); the
        // demo verifier accepts one fixed token so the flow is walkable offline.
        services.AddSingleton<ICaptchaVerifier>(new DemoCaptchaVerifier(GateWorld.CaptchaAnswer));
        services.Configure<SentinelCaptchaOptions>(o => o.SiteKey = GateWorld.CaptchaSiteKey);

        return services;
    }

    public static IEndpointRouteBuilder MapAbuseGateApi(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapSentinelAuth(); // POST /auth/login is the protected surface
        return endpoints;
    }

    /// <summary>
    /// Demo-only: adopt an <c>X-Demo-Ip</c> header as the client address so the per-IP
    /// layers are observable from one machine. A real deployment deletes this middleware and
    /// relies on the connection (or configured forwarded headers) — never a client header.
    /// </summary>
    public static IApplicationBuilder UseDemoClientIp(this IApplicationBuilder app) =>
        app.Use((context, next) =>
        {
            if (context.Request.Headers.TryGetValue("X-Demo-Ip", out var header)
                && IPAddress.TryParse(header.ToString(), out var ip))
            {
                context.Connection.RemoteIpAddress = ip;
            }

            return next(context);
        });
}

/// <summary>Accepts exactly one token — the offline stand-in for a real captcha provider.</summary>
public sealed class DemoCaptchaVerifier(string accepted) : ICaptchaVerifier
{
    public ValueTask<bool> VerifyAsync(
        string token, string? ip, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(token == accepted);
}
