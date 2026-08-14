using Microsoft.Extensions.DependencyInjection;
using Nuvora.Nexus.Sentinel.AspNetCore;
using Nuvora.Nexus.Sentinel.AspNetCore.DependencyInjection;
using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Nuvora.Nexus.Sentinel.Login;
using Nuvora.Nexus.Sentinel.Tokens;

namespace Clinic.Login.Api;

public static class ClinicLoginServiceCollectionExtensions
{
    /// <summary>
    /// The whole Sentinel composition for an embedding app: the meta package's
    /// core services, the ASP.NET authentication handler, and explicit in-memory identity
    /// stores. Called by Program.cs and by the test host, so both run the exact same wiring.
    /// </summary>
    public static IServiceCollection AddClinicLoginApi(this IServiceCollection services)
    {
        services.AddRouting();

        // Identity stores are NOT defaulted by AddSentinel (silently running an IdP on
        // an in-memory user database is a footgun). This sample opts into the in-memory ones
        // explicitly; swap for AddSentinelEfCoreStores in a real deployment.
        var store = new InMemoryIdentityStore();
        services.AddSingleton(store);
        services.AddSingleton<IUserStore>(store);
        services.AddSingleton<IMfaStore>(store);
        services.AddSingleton<ISessionStore>(store);
        services.AddSingleton<ISubjectDataSource, ClinicSubjectSource>();

        // Access tokens are minted with this issuer and verified against it.
        services.Configure<SentinelTokenOptions>(o => o.Issuer = ClinicDemo.Issuer);

        services.AddSentinel(o =>
        {
            o.DefaultRealmId = ClinicDemo.Realm;
            // Ephemeral development signing keys: fine for a sample, fail-fast without
            // this flag outside Development — Sentinel's fix of the Node stack's worst default.
            o.AllowDevelopmentDefaults = true;
        });

        services.AddSentinelAuthentication(o =>
        {
            o.Issuer = ClinicDemo.Issuer;
            o.Audience = ClinicDemo.Audience;
            o.DefaultRealmId = ClinicDemo.Realm;
            // Cookie transport: tokens live in httpOnly cookies and never appear in the
            // JSON body — the cookie-first guidance for browser apps. State-changing requests
            // must echo the sentinel_csrf cookie in X-Sentinel-Csrf (double-submit).
            o.Transport = SentinelTokenTransport.Cookie;
        });

        return services;
    }
}
