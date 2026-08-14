using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Nuvora.Nexus.Sentinel.Admin;
using Nuvora.Nexus.Sentinel.AspNetCore;
using Nuvora.Nexus.Sentinel.AspNetCore.DependencyInjection;
using Nuvora.Nexus.Sentinel.AspNetCore.Endpoints;
using Nuvora.Nexus.Sentinel.Authentication;
using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Nuvora.Nexus.Sentinel.Identity;
using Nuvora.Nexus.Sentinel.Login;
using Nuvora.Nexus.Sentinel.Permissions;
using Nuvora.Nexus.Sentinel.Ports;
using Nuvora.Nexus.Sentinel.Tokens;

namespace MultiOrg.Api;

/// <summary>
/// The whole sample composition in two extension methods, shared verbatim by Program.cs and the
/// test host — the point of the sample is that embedding Sentinel IS this composition:
/// embeddable and code-first.
/// </summary>
public static class MultiOrgComposition
{
    /// <summary>
    /// Store ports FIRST, then <c>AddSentinel()</c> — every AddSentinel registration is TryAdd,
    /// so the host's stores win and the meta package fills in the rest (login stack,
    /// key ring, snapshot cache, abuse gates).
    /// </summary>
    public static IServiceCollection AddMultiOrgApi(this IServiceCollection services)
    {
        var identity = new InMemoryIdentityStore();
        var admin = new InMemoryAdminStore();
        var directory = new MultiOrgDirectory(identity, MultiOrgWorld.RealmId);
        // Cheap argon2id parameters: this sample teaches wiring, not KDF hardness.
        var hasher = new PasswordHasher(new Argon2idPasswordHashAlgorithm(memoryKib: 8, iterations: 1, parallelism: 1));
        MultiOrgWorld.Seed(identity, admin, directory, hasher);

        // Identity store ports — deliberately NOT defaulted by AddSentinel: running an
        // IdP on an implicit in-memory user database is a footgun, so opting in is explicit.
        services.AddSingleton<IUserStore>(identity);
        services.AddSingleton<IMfaStore>(identity);
        services.AddSingleton<ISessionStore>(identity);
        services.AddSingleton<ISubjectDataSource>(directory);
        services.AddSingleton<IAdminStore>(admin);
        services.AddSingleton(hasher);

        services.Configure<SentinelTokenOptions>(o => o.Issuer = MultiOrgWorld.Issuer);
        services.AddSentinel(o =>
        {
            o.DefaultRealmId = MultiOrgWorld.RealmId;
            // Explicit opt-in to ephemeral development keys — a real deployment
            // configures a persisted key store instead and this line goes away.
            o.AllowDevelopmentDefaults = true;
        });
        services.AddSentinelAuthentication(o =>
        {
            o.Issuer = MultiOrgWorld.Issuer;
            o.Audience = MultiOrgWorld.Audience;
            o.DefaultRealmId = MultiOrgWorld.RealmId;
            // Bearer keeps the sample's curl walkthrough copy-pasteable; browser apps prefer
            // the cookie transport.
            o.Transport = SentinelTokenTransport.Bearer;
        });
        services.AddSentinelAdmin(); // the delegated-admin surface

        return services;
    }

    /// <summary>Mounts the Sentinel groups plus the sample's own endpoints.</summary>
    public static IEndpointRouteBuilder MapMultiOrgApi(this IEndpointRouteBuilder endpoints)
    {
        // /auth/login … — org context selected at token mint, and /auth/org/switch: the
        // library endpoint validates membership against the live store, repoints the session,
        // rotates the refresh family into the new org context and mints the new access token —
        // no re-authentication, nothing hand-rolled here.
        endpoints.MapSentinelAuth();
        endpoints.MapSentinelAdmin();  // /sentinel-admin/* — per-resource org fencing

        // -------------------------------------------------------------------------------------
        // An app endpoint whose answer depends on the token's org context: the authentication
        // handler resolved the per-(user, org) snapshot, and one evaluator call
        // decides — mara's read grant is Acme-tagged, so the same user gets 200 in an
        // Acme-context token and 403 in a Globex one.
        // -------------------------------------------------------------------------------------
        endpoints.MapGet("/reports", (HttpContext http) =>
        {
            var principal = http.GetSentinelPrincipal();
            if (principal is null)
            {
                return Results.Unauthorized();
            }

            var snapshot = http.GetSentinelSnapshot();
            if (snapshot is null || !AuthorizationEvaluator.Evaluate(
                    snapshot, new AccessCheck(PermissionId.Parse("reports:org:read"))).IsAllowed)
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status403Forbidden,
                    title: "reports:org:read is not granted in this org context.");
            }

            return Results.Ok(new
            {
                organizationId = principal.OrganizationId,
                reports = new[] { "monthly-intake", "referral-latency" },
            });
        });

        return endpoints;
    }
}
