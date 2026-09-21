using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Nuvora.Nexus.Sentinel.Admin;
using Nuvora.Nexus.Sentinel.AspNetCore;
using Nuvora.Nexus.Sentinel.AspNetCore.DependencyInjection;
using Nuvora.Nexus.Sentinel.AspNetCore.Endpoints;
using Nuvora.Nexus.Sentinel.Authentication;
using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.Definitions;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Nuvora.Nexus.Sentinel.Login;
using Nuvora.Nexus.Sentinel.Permissions;
using Nuvora.Nexus.Sentinel.Policies;
using Nuvora.Nexus.Sentinel.Ports;
using Nuvora.Nexus.Sentinel.Tokens;

namespace OrgTree.Api;

/// <summary>
/// The whole sample composition in two extension methods, shared verbatim by Program.cs and the
/// test host. Nothing here is tree-specific: the tree is data in the stores, and the login
/// stack, evaluator and admin surface read it through the same ports they always used.
/// </summary>
public static class OrgTreeComposition
{
    public static IServiceCollection AddOrgTreeApi(this IServiceCollection services)
    {
        var identity = new InMemoryIdentityStore();
        var admin = new InMemoryAdminStore();
        var directory = new OrgTreeDirectory(identity, OrgTreeWorld.RealmId);
        var policies = new InMemoryPolicyStore();
        var apps = new InMemoryApplicationAssignmentStore();
        // Cheap argon2id parameters: this sample teaches wiring, not KDF hardness.
        var hasher = new PasswordHasher(new Argon2idPasswordHashAlgorithm(memoryKib: 8, iterations: 1, parallelism: 1));
        OrgTreeWorld.Seed(identity, admin, directory, policies, apps, hasher);

        // Store ports FIRST — AddSentinel's registrations are TryAdd, so these win.
        services.AddSingleton<IUserStore>(identity);
        services.AddSingleton<IMfaStore>(identity);
        services.AddSingleton<ISessionStore>(identity);
        services.AddSingleton<ISubjectDataSource>(directory);
        services.AddSingleton<IAdminStore>(admin);
        services.AddSingleton<IPolicyStore>(policies);
        services.AddSingleton<IApplicationAssignmentStore>(apps);
        services.AddSingleton(hasher);

        services.Configure<SentinelTokenOptions>(o => o.Issuer = OrgTreeWorld.Issuer);
        services.AddSentinel(o =>
        {
            o.DefaultRealmId = OrgTreeWorld.RealmId;
            o.AllowDevelopmentDefaults = true; // ephemeral dev keys; real hosts persist a key store
        });
        services.AddSentinelAuthentication(o =>
        {
            o.Issuer = OrgTreeWorld.Issuer;
            o.Audience = OrgTreeWorld.Audience;
            o.DefaultRealmId = OrgTreeWorld.RealmId;
            o.Transport = SentinelTokenTransport.Bearer; // keeps the curl walkthrough copy-pasteable
        });
        services.AddSentinelAdmin();

        return services;
    }

    public static IEndpointRouteBuilder MapOrgTreeApi(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapSentinelAuth();    // /auth/login lands on a node; /auth/org/switch walks the tree
        endpoints.MapSentinelProfile(); // /profile/me carries organizationId (ou), rootOrganizationId (org), apps
        endpoints.MapSentinelAdmin();   // /sentinel-admin/* — fenced per node, subtree-aware

        // An app endpoint whose answer depends on the token's NODE: the physician's read grant
        // sits at North, so a Lakeside-context token (beneath North) is allowed and a Bayview one
        // (not beneath North) is not — same user, same session, different node.
        endpoints.MapGet("/charts", (HttpContext http) =>
        {
            var principal = http.GetSentinelPrincipal();
            if (principal is null)
            {
                return Results.Unauthorized();
            }

            var snapshot = http.GetSentinelSnapshot();
            if (snapshot is null || !AuthorizationEvaluator.Evaluate(
                    snapshot, new AccessCheck(PermissionId.Parse("charts:org:read"))).IsAllowed)
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status403Forbidden,
                    title: "charts:org:read is not granted at this node.");
            }

            return Results.Ok(new
            {
                organizationId = principal.OrganizationId,         // the acting node (ou)
                rootOrganizationId = principal.RootOrganizationId, // the tenant (org)
                charts = new[] { "admissions", "bed-occupancy" },
            });
        });

        return endpoints;
    }
}
