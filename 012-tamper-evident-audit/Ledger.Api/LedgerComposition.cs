using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Nuvora.Nexus.Sentinel.Admin;
using Nuvora.Nexus.Sentinel.AspNetCore;
using Nuvora.Nexus.Sentinel.AspNetCore.DependencyInjection;
using Nuvora.Nexus.Sentinel.AspNetCore.Endpoints;
using Nuvora.Nexus.Sentinel.Audit;
using Nuvora.Nexus.Sentinel.Authentication;
using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Nuvora.Nexus.Sentinel.Login;
using Nuvora.Nexus.Sentinel.Tokens;

namespace Ledger.Api;

/// <summary>
/// The whole composition, shared verbatim by Program.cs and the test host: the login
/// stack, the delegated-admin surface whose mutations append to the hash chain, and an
/// explicitly registered audit store (so the tamper demo can reach the live entries).
/// </summary>
public static class LedgerComposition
{
    public static IServiceCollection AddLedgerApi(this IServiceCollection services)
    {
        services.AddRouting();

        var identity = new InMemoryIdentityStore();
        var admin = new InMemoryAdminStore();
        var directory = new LedgerDirectory();
        // Cheap argon2id parameters: this sample teaches the ledger, not KDF hardness.
        var hasher = new PasswordHasher(new Argon2idPasswordHashAlgorithm(memoryKib: 8, iterations: 1, parallelism: 1));
        LedgerWorld.Seed(identity, admin, directory, hasher);

        services.AddSingleton<IUserStore>(identity);
        services.AddSingleton<IMfaStore>(identity);
        services.AddSingleton<ISessionStore>(identity);
        services.AddSingleton<ISubjectDataSource>(directory);
        services.AddSingleton<IAdminStore>(admin);
        services.AddSingleton(hasher);

        // The chained ledger. AddSentinel would default this anyway (TryAdd); registering it
        // explicitly keeps the instance reachable — the tamper test mutates its live entries.
        services.AddSingleton<IAuditStore, InMemoryAuditStore>();

        services.Configure<SentinelTokenOptions>(o => o.Issuer = LedgerWorld.Issuer);
        services.AddSentinel(o =>
        {
            o.DefaultRealmId = LedgerWorld.RealmId;
            o.AllowDevelopmentDefaults = true; // ephemeral dev signing keys, explicit opt-in
        });
        services.AddSentinelAuthentication(o =>
        {
            o.Issuer = LedgerWorld.Issuer;
            o.Audience = LedgerWorld.Audience;
            o.DefaultRealmId = LedgerWorld.RealmId;
            o.Transport = SentinelTokenTransport.Bearer;
        });
        services.AddSentinelAdmin();

        return services;
    }

    public static IEndpointRouteBuilder MapLedgerApi(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapSentinelAuth();   // /auth/login — admin auth is an ordinary bearer token
        endpoints.MapSentinelAdmin();  // /sentinel-admin/* — mutations append, /audit reads
        return endpoints;
    }
}
