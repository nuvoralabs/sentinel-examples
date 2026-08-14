using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Nuvora.Nexus.Sentinel.AspNetCore;
using Nuvora.Nexus.Sentinel.AspNetCore.DependencyInjection;
using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Nuvora.Nexus.Sentinel.Identity;
using Nuvora.Nexus.Sentinel.Login;
using Nuvora.Nexus.Sentinel.OidcServer.DependencyInjection;
using Nuvora.Nexus.Sentinel.OidcServer.Endpoints;
using Nuvora.Nexus.Sentinel.Ports;

namespace WorkloadExchange.Api;

/// <summary>
/// Secretless CI: a CI job exchanges its platform-issued OIDC token for a
/// Sentinel access token via a trust configuration — no Sentinel secret ever lives in the
/// pipeline. Shared verbatim by Program.cs and the tests.
/// </summary>
public static class WorkloadComposition
{
    public const string Issuer = "https://workload.sample";
    public const string Audience = "workload-api";

    public static readonly Guid RealmId = Guid.Parse("00000000-0000-0000-0000-000000000007");

    /// <summary>The service account exchanged tokens act as; fixed so tests and README agree.</summary>
    public static Guid ServiceAccountId { get; private set; }

    public static IServiceCollection AddWorkloadExchangeApi(this IServiceCollection services)
    {
        var idp = new FakeCiIdp();
        var trusts = new InMemoryWorkloadTrustStore();
        var machines = new InMemoryMachineIdentityStore();
        Seed(trusts, machines);

        services.AddSingleton(idp);
        // Registered BEFORE AddSentinelWorkloadFederation so its TryAdd defaults (HTTP-fetching
        // JWKS cache, empty trust store) never land: the fake IdP's JWKS document is
        // served straight from memory — exactly how the library's own federation tests wire it.
        services.AddSingleton<IWorkloadTrustStore>(trusts);
        services.AddSingleton<IMachineIdentityStore>(machines);
        services.AddSingleton<IRemoteJwksCache>(sp => new InMemoryRemoteJwksCache(
            (uri, _) => uri == FakeCiIdp.JwksUri
                ? Task.FromResult(idp.JwksDocument)
                : Task.FromException<string>(new InvalidOperationException($"No JWKS at {uri}.")),
            sp.GetRequiredService<ISentinelClock>()));

        services.Configure<SentinelTokenOptions>(o => o.Issuer = Issuer);
        services.AddSentinel(o =>
        {
            o.DefaultRealmId = RealmId;
            o.AllowDevelopmentDefaults = true; // sample-only ephemeral signing keys (production persists a real key)
        });
        services.AddSentinelAuthentication(o =>
        {
            o.Issuer = Issuer;
            o.Audience = Audience;
            o.DefaultRealmId = RealmId;
        });
        services.AddSentinelWorkloadFederation();

        // Machine principals only — no users, no login stack: a workload-exchange host needs
        // none of the browser machinery.
        services.AddSingleton<ISubjectDataSource>(new NoUsersSubjectSource());

        return services;
    }

    /// <summary>
    /// One service account + one trust: tokens from the fake CI issuer, minted for the
    /// federation audience, whose <c>sub</c> matches <c>repo:nuvoralabs/*</c> AND whose claims
    /// pass the rules (repo under the org, master branch only) act as "ci-deployer".
    /// </summary>
    private static void Seed(InMemoryWorkloadTrustStore trusts, InMemoryMachineIdentityStore machines)
    {
        var account = new ServiceAccount
        {
            RealmId = RealmId,
            Key = "ci-deployer",
            DisplayName = "CI Deployer",
            SecretHash = "unused",       // the whole point — no client secret in CI
            SecretAlgorithm = "argon2id",
            CreatedAt = DateTimeOffset.UtcNow,
        };
        machines.AddServiceAccountAsync(account).AsTask().GetAwaiter().GetResult();
        ServiceAccountId = account.Id;

        trusts.AddAsync(new WorkloadTrustConfig
        {
            RealmId = RealmId,
            ServiceAccountId = account.Id,
            Issuer = FakeCiIdp.Issuer,
            JwksUri = FakeCiIdp.JwksUri,
            Audience = FakeCiIdp.TrustAudience,
            SubjectPattern = "repo:nuvoralabs/*",
            ClaimRules =
            [
                new WorkloadClaimRule("repository", "nuvoralabs/*"),
                new WorkloadClaimRule("ref", "refs/heads/master"),
            ],
            CreatedAt = DateTimeOffset.UtcNow,
        }).AsTask().GetAwaiter().GetResult();
    }

    public static IEndpointRouteBuilder MapWorkloadExchangeApi(this IEndpointRouteBuilder endpoints)
    {
        // POST /oidc/workload/token — the RFC 8693-shaped exchange endpoint.
        endpoints.MapSentinelWorkloadFederation();

        // The API the CI job actually wants to call, protected by the ordinary Sentinel
        // authentication handler — an exchanged token is a first-class access token.
        endpoints.MapPost("/deployments", (HttpContext http) =>
        {
            var principal = http.GetSentinelPrincipal();
            if (principal is null)
            {
                return Results.Unauthorized();
            }

            // NOTE: principal.SubjectId is the service account's id. The exchanged
            // token is an ordinary access token, so principal.Kind reports User — the JWT
            // carries no principal-kind marker today (a gap worth knowing about).
            return Results.Ok(new
            {
                deployed = "v42",
                subjectId = principal.SubjectId,
            });
        });

        // SAMPLE-ONLY: stands in for the CI platform's own token endpoint so the README's curl
        // walkthrough can mint a workload token. A real deployment has no such endpoint — the
        // platform (GitHub, Kubernetes, the cloud) mints these.
        endpoints.MapPost("/fake-idp/token", (FakeCiIdp idp, FakeTokenRequest? request) =>
            Results.Ok(new
            {
                token = idp.IssueToken(
                    request?.Sub ?? "repo:nuvoralabs/nexus:ref:refs/heads/master",
                    request?.Repository ?? "nuvoralabs/nexus",
                    request?.Ref ?? "refs/heads/master",
                    request?.Aud ?? FakeCiIdp.TrustAudience),
            }));

        return endpoints;
    }
}

public sealed record FakeTokenRequest(string? Sub, string? Repository, string? Ref, string? Aud);

/// <summary>This host serves machine identities only; user snapshots never resolve.</summary>
public sealed class NoUsersSubjectSource : ISubjectDataSource
{
    public ValueTask<SubjectData?> LoadAsync(
        Guid userId, Guid? organizationId, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult<SubjectData?>(null);
}
