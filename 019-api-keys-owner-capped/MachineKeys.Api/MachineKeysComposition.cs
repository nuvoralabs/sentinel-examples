using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Nuvora.Nexus.Sentinel.AspNetCore;
using Nuvora.Nexus.Sentinel.AspNetCore.DependencyInjection;
using Nuvora.Nexus.Sentinel.AspNetCore.Endpoints;
using Nuvora.Nexus.Sentinel.Authentication;
using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Nuvora.Nexus.Sentinel.Identity;
using Nuvora.Nexus.Sentinel.Login;
using Nuvora.Nexus.Sentinel.Permissions;

namespace MachineKeys.Api;

/// <summary>
/// Owner-capped API keys: Maya mints an <c>snt_</c> key scoped to
/// <c>reports:org:*</c>; the key's effective permissions are her CURRENT grants intersected
/// with the key's scopes at every use — denies preserved, demotion shrinks the key, revocation
/// and expiry fail closed. Shared verbatim by Program.cs and the tests.
/// </summary>
public static class MachineKeysComposition
{
    public const string Issuer = "https://machinekeys.sample";
    public const string Audience = "reports-api";
    public const string DemoPassword = "machine-keys-demo-password";

    public static readonly Guid RealmId = Guid.Parse("00000000-0000-0000-0000-000000000019");
    public static readonly Guid RoboticsOrgId = Guid.Parse("00000019-0000-0000-0000-0000000000aa");
    public static readonly Guid MayaId = Guid.Parse("00000019-0000-0000-0000-00000000000a");

    public const string MayaEmail = "maya@robotics.sample";

    public static IServiceCollection AddMachineKeysApi(this IServiceCollection services)
    {
        services.AddRouting();

        var store = new InMemoryIdentityStore();
        var hasher = new PasswordHasher(
            new Argon2idPasswordHashAlgorithm(memoryKib: 8, iterations: 1, parallelism: 1)); // cheap: teaching code
        Seed(store, hasher);

        services.AddSingleton(store);
        services.AddSingleton<IUserStore>(store);
        services.AddSingleton<IMfaStore>(store);
        services.AddSingleton<ISessionStore>(store);
        services.AddSingleton(hasher);

        // Mutable grants source: the demotion demo edits Maya's grants at runtime and every
        // key she owns shrinks on its NEXT use — nothing on the key rows changes.
        services.AddSingleton<GrantDirectory>();
        services.AddSingleton<ISubjectDataSource>(sp => sp.GetRequiredService<GrantDirectory>());

        // Machine identity is opt-in like the other identity stores: without this registration
        // the authentication handler rejects every snt_ credential.
        services.AddSingleton<IMachineIdentityStore, InMemoryMachineIdentityStore>();

        services.Configure<SentinelTokenOptions>(o => o.Issuer = Issuer);
        services.AddSentinel(o =>
        {
            o.DefaultRealmId = RealmId;
            o.AllowDevelopmentDefaults = true; // sample-only ephemeral signing keys
        });
        services.AddSentinelAuthentication(o =>
        {
            o.Issuer = Issuer;
            o.Audience = Audience;
            o.DefaultRealmId = RealmId;
        });

        return services;
    }

    private static void Seed(InMemoryIdentityStore store, PasswordHasher hasher)
    {
        var maya = new User
        {
            Id = MayaId,
            RealmId = RealmId,
            Email = MayaEmail,
            EmailVerified = true,
            DisplayName = "Maya Owner",
        };
        store.AddUser(maya, new UserCredential
        {
            UserId = maya.Id,
            Algorithm = hasher.Current.Name,
            Hash = hasher.Hash(DemoPassword),
        });
        store.AddOrgMembership(maya.Id, RoboticsOrgId);
    }

    public static IEndpointRouteBuilder MapMachineKeysApi(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapSentinelAuth();     // POST /auth/login
        endpoints.MapSentinelProfile();  // GET /profile/permissions shows the CAPPED snapshot for a key

        // ------------------- key management (host-authored endpoints) -------------------
        // The library ships MachineAuthService + the handler-chain support; the management
        // HTTP surface is the host's to shape. These three endpoints are that surface here.

        // Mint a key for the CALLING USER: the caller is the owner, the key can never do
        // more than the owner can at the moment of use.
        endpoints.MapPost("/keys", async (
            HttpContext http, MachineAuthService machineAuth, CreateKeyRequest? request) =>
        {
            var principal = http.GetSentinelPrincipal();
            if (principal is null || principal.Kind != SentinelPrincipalKind.User)
            {
                return Results.Unauthorized(); // keys mint keys for nobody
            }

            if (request?.Scopes is not { Count: > 0 })
            {
                return Results.BadRequest(new { error = "at least one scope pattern is required" });
            }

            try
            {
                var created = await machineAuth.CreateApiKeyAsync(
                    principal.RealmId, principal.SubjectId, request.Scopes,
                    principal.OrganizationId,
                    request.ExpiresInMinutes is { } minutes
                        ? DateTimeOffset.UtcNow.AddMinutes(minutes)
                        : null);

                // The full token appears in this response and NOWHERE else — only its hash is stored.
                return Results.Ok(new
                {
                    created.Key.Id,
                    created.Key.Prefix,
                    created.Key.Scopes,
                    token = created.Token,
                });
            }
            catch (FormatException ex)
            {
                return Results.BadRequest(new { error = ex.Message });
            }
        });

        // List the caller's keys: prefixes and metadata, never tokens.
        endpoints.MapGet("/keys", async (HttpContext http, IMachineIdentityStore keys) =>
        {
            var principal = http.GetSentinelPrincipal();
            if (principal is null || principal.Kind != SentinelPrincipalKind.User)
            {
                return Results.Unauthorized();
            }

            var owned = await keys.ListApiKeysForOwnerAsync(principal.SubjectId);
            return Results.Ok(owned.Select(k => new
            {
                k.Id, k.Prefix, k.Scopes, k.CreatedAt, k.LastUsedAt, k.RevokedAt, k.ExpiresAt,
            }));
        });

        endpoints.MapPost("/keys/{id:guid}/revoke", async (
            Guid id, HttpContext http, IMachineIdentityStore keys, MachineAuthService machineAuth) =>
        {
            var principal = http.GetSentinelPrincipal();
            if (principal is null || principal.Kind != SentinelPrincipalKind.User)
            {
                return Results.Unauthorized();
            }

            var key = (await keys.ListApiKeysForOwnerAsync(principal.SubjectId)).FirstOrDefault(k => k.Id == id);
            if (key is null)
            {
                return Results.NotFound();
            }

            await machineAuth.RevokeApiKeyAsync(key);
            return Results.NoContent();
        });

        // ----------------------------- the protected API -----------------------------
        // Ordinary app endpoints; a key and a login token go through the SAME evaluator.
        endpoints.MapGet("/reports", (HttpContext http) =>
            Guard(http, "reports:org:read", () => Results.Ok(new { reports = new[] { "monthly", "weekly" } })));
        endpoints.MapGet("/reports/export", (HttpContext http) =>
            Guard(http, "reports:org:export", () => Results.Ok(new { exported = true })));
        endpoints.MapPost("/reports/purge", (HttpContext http) =>
            Guard(http, "reports:org:purge", () => Results.Ok(new { purged = true })));
        endpoints.MapGet("/billing", (HttpContext http) =>
            Guard(http, "billing:org:read", () => Results.Ok(new { invoices = 3 })));
        endpoints.MapGet("/admin", (HttpContext http) =>
            Guard(http, "admin:global:manage", () => Results.Ok(new { admin = true })));

        // The attribution split: an API-key principal's SubjectId is the CREDENTIAL id, the
        // human behind it rides along as OwnerUserId.
        endpoints.MapGet("/whoami", (HttpContext http) =>
        {
            var principal = http.GetSentinelPrincipal();
            return principal is null
                ? Results.Unauthorized()
                : Results.Ok(new
                {
                    kind = principal.Kind.ToString(),
                    subjectId = principal.SubjectId,
                    ownerUserId = principal.OwnerUserId,
                    organizationId = principal.OrganizationId,
                });
        });

        // SAMPLE-ONLY: demote Maya to read-only so the README/tests can show that every key
        // she owns shrinks on its next use. A real host demotes through its role model.
        endpoints.MapPost("/demo/demote-owner", (GrantDirectory grants) =>
        {
            grants.SetGrants(MayaId, [GrantDirectory.Allow("reports:org:read")]);
            return Results.Ok(new { demoted = MayaEmail, keptOnly = "reports:org:read" });
        });

        return endpoints;
    }

    private static IResult Guard(HttpContext http, string permission, Func<IResult> ok)
    {
        var snapshot = http.GetSentinelSnapshot();
        if (snapshot is null)
        {
            return Results.Unauthorized();
        }

        var check = new AccessCheck(PermissionId.Parse(permission));
        return AuthorizationEvaluator.Evaluate(snapshot, in check).IsAllowed
            ? ok()
            : Results.StatusCode(StatusCodes.Status403Forbidden);
    }
}

public sealed record CreateKeyRequest(List<string>? Scopes, int? ExpiresInMinutes);

/// <summary>
/// Maya's grants, mutable at runtime. Initially: everything on reports EXCEPT purge
/// (an explicit deny), plus billing — which her keys can only reach if a scope covers it.
/// </summary>
public sealed class GrantDirectory : ISubjectDataSource
{
    private readonly Dictionary<Guid, GrantData[]> _grants = new()
    {
        [MachineKeysComposition.MayaId] =
        [
            Allow("reports:org:*"),
            new GrantData("reports:org:purge", GrantEffect.Deny, null, null, null, "role:owner-demo"),
            Allow("billing:org:*"),
        ],
    };

    public static GrantData Allow(string pattern) =>
        new(pattern, GrantEffect.Allow, null, null, null, "role:owner-demo");

    public void SetGrants(Guid userId, GrantData[] grants)
    {
        lock (_grants)
        {
            _grants[userId] = grants;
        }
    }

    public ValueTask<SubjectData?> LoadAsync(
        Guid userId, Guid? organizationId, CancellationToken cancellationToken = default)
    {
        lock (_grants)
        {
            return ValueTask.FromResult<SubjectData?>(new SubjectData(
                userId,
                MachineKeysComposition.RealmId,
                organizationId,
                TeamMemberships: [],
                Grants: _grants.TryGetValue(userId, out var grants) ? grants : [],
                Attributes: null));
        }
    }
}
