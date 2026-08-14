using System.Net;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Nuvora.Nexus.Sentinel.AspNetCore;
using Nuvora.Nexus.Sentinel.AspNetCore.DependencyInjection;
using Nuvora.Nexus.Sentinel.AspNetCore.Endpoints;
using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Nuvora.Nexus.Sentinel.Login;
using Nuvora.Nexus.Sentinel.Ports;
using Nuvora.Nexus.Sentinel.Risk;
using Nuvora.Nexus.Sentinel.Tokens;

namespace StepUp.Api;

/// <summary>
/// The whole composition, shared by Program.cs and the test host. AddSentinel() wires
/// the risk gate into every login by default; this sample plugs the two ports that make it
/// bite (reputation + mailer), appends one custom signal, and keeps the default thresholds
/// (step-up at 40, block at 80).
/// </summary>
public static class StepUpComposition
{
    public static IServiceCollection AddStepUpApi(this IServiceCollection services)
    {
        services.AddRouting();

        var identity = new InMemoryIdentityStore();
        services.AddSingleton(identity);
        services.AddSingleton<IUserStore>(identity);
        services.AddSingleton<IMfaStore>(identity);
        services.AddSingleton<ISessionStore>(identity);
        services.AddSingleton<ISubjectDataSource, StepUpSubjectSource>();

        // The ports that arm the built-in signals — registered BEFORE AddSentinel so its
        // TryAdd noop defaults yield. Without a reputation source the ip_reputation signal is
        // inert; without a real mailer the email-OTP codes go nowhere (NoopMailer's posture).
        services.AddSingleton<IIpReputationProvider, DemoIpReputation>();
        services.AddSingleton<DemoMailer>();
        services.AddSingleton<ISentinelMailer>(sp => sp.GetRequiredService<DemoMailer>());

        // One custom signal joining the four built-ins (new_device 30, impossible_travel 40,
        // ip_reputation 50, velocity 25) in the same parallel evaluation.
        services.TryAddEnumerable(ServiceDescriptor.Scoped<IRiskSignal, WatchlistSignal>());

        services.Configure<SentinelTokenOptions>(o => o.Issuer = StepUpWorld.Issuer);
        services.AddSentinel(o =>
        {
            o.DefaultRealmId = StepUpWorld.RealmId;
            o.AllowDevelopmentDefaults = true; // ephemeral dev signing keys, explicit opt-in
        });
        services.AddSentinelAuthentication(o =>
        {
            o.Issuer = StepUpWorld.Issuer;
            o.Audience = StepUpWorld.Audience;
            o.DefaultRealmId = StepUpWorld.RealmId;
            o.Transport = SentinelTokenTransport.Bearer;
        });

        return services;
    }

    public static IEndpointRouteBuilder MapStepUpApi(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapSentinelAuth(); // /auth/login + /auth/mfa/verify carry the whole flow
        return endpoints;
    }

    /// <summary>
    /// Demo-only: adopt an <c>X-Demo-Ip</c> header as the client address so IP-driven
    /// signals are observable from one machine. A real deployment deletes this middleware and
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
