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
using Nuvora.Nexus.Sentinel.Ports;
using Nuvora.Nexus.Sentinel.Saml;
using Nuvora.Nexus.Sentinel.Saml.DependencyInjection;
using Nuvora.Nexus.Sentinel.Saml.Endpoints;
using Nuvora.Nexus.Sentinel.Tokens;

namespace SamlLoop.Api;

/// <summary>
/// One host that is BOTH a Sentinel SAML IdP and a Sentinel SAML SP — the loopback:
/// a single realm carries both connection records, and they point at each other on the same
/// origin. The SP-side <see cref="SamlIdpConnection"/> pins the IdP's signing certificate;
/// the IdP-side <see cref="SamlSpConnection"/> registers the SP's ACS. Shared verbatim by
/// Program.cs and the tests.
/// </summary>
public static class SamlLoopComposition
{
    public const string Issuer = "https://samlloop.sample";
    public const string Audience = "samlloop-api";

    /// <summary>Entity IDs are stable logical names — deliberately NOT the transport origin.</summary>
    public const string SpEntityId = "https://sp.samlloop.sample";

    public const string IdpEntityId = "https://idp.samlloop.sample";

    /// <summary>The SP-side connection key: /auth/saml/self/start begins the loop.</summary>
    public const string ConnectionKey = "self";

    public const string UserEmail = "alice@samlloop.sample";
    public const string UserPassword = "sample-password-1!";

    public static readonly Guid RealmId = Guid.Parse("00000000-0000-0000-0000-0000000000a1");

    public static IServiceCollection AddSamlLoopApi(this IServiceCollection services)
    {
        services.AddRouting();

        var identity = new InMemoryIdentityStore();
        var saml = new InMemorySamlStore(SystemClock.Instance);
        var federated = new InMemoryFederatedIdentityStore(identity);
        // Cheap argon2id parameters: this sample teaches protocol wiring, not KDF hardness.
        var hasher = new PasswordHasher(new Argon2idPasswordHashAlgorithm(memoryKib: 8, iterations: 1, parallelism: 1));
        SeedUsers(identity, hasher);

        services.AddSingleton(identity);
        services.AddSingleton<IUserStore>(identity);
        services.AddSingleton<IMfaStore>(identity);
        services.AddSingleton<ISessionStore>(identity);
        services.AddSingleton<ISubjectDataSource>(new AuthenticationOnlySource(RealmId));
        services.AddSingleton(hasher);

        // The federation stores the SAML flows write through — registered BEFORE
        // AddSentinelSaml so its TryAdd defaults yield, and kept reachable for the tests.
        services.AddSingleton(saml);
        services.AddSingleton<ISamlStore>(saml);
        services.AddSingleton(federated);
        services.AddSingleton<IFederatedIdentityStore>(federated);

        services.Configure<SentinelTokenOptions>(o => o.Issuer = Issuer);
        services.AddSentinel(o =>
        {
            o.DefaultRealmId = RealmId;
            o.AllowDevelopmentDefaults = true; // ephemeral dev signing keys, explicit opt-in
        });
        services.AddSentinelAuthentication(o =>
        {
            o.Issuer = Issuer;
            o.Audience = Audience;
            o.DefaultRealmId = RealmId;
            // Cookie transport: the ACS answers with a browser session, not JSON tokens.
            o.Transport = SentinelTokenTransport.Cookie;
        });

        // One call registers BOTH surfaces: SamlSpService and SamlIdpService.
        services.AddSentinelSaml(o =>
        {
            o.SpEntityId = SpEntityId;
            o.IdpEntityId = IdpEntityId;
            o.LoginPath = "/login"; // where the IdP SSO endpoint bounces an anonymous browser
        });

        return services;
    }

    public static IEndpointRouteBuilder MapSamlLoopApi(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapSentinelAuth(); // /auth/login — the cookie session the IdP side needs
        endpoints.MapSentinelSaml(); // /auth/saml/* (SP) + /saml/idp/* (IdP), both metadata docs

        // Interaction contract, host side (Sentinel ships no hosted pages): the IdP SSO
        // endpoint 302s an anonymous browser to /login?returnUrl={the SSO URL}; this page
        // authenticates (POST /auth/login sets the cookies) and bounces back.
        endpoints.MapGet("/login", (string? returnUrl) =>
        {
            var safeReturnUrl = returnUrl is ['/', not '/', ..] ? returnUrl : "/";
            return Results.Content($$"""
            <!doctype html>
            <title>Sign in — SamlLoop.Api</title>
            <h1>Sign in</h1>
            <form id="f">
              <input id="email" value="{{UserEmail}}" autocomplete="username">
              <input id="password" type="password" value="{{UserPassword}}" autocomplete="current-password">
              <button>Sign in</button>
            </form>
            <script>
              document.getElementById('f').addEventListener('submit', async (e) => {
                e.preventDefault();
                const r = await fetch('/auth/login', {
                  method: 'POST',
                  headers: { 'content-type': 'application/json' },
                  body: JSON.stringify({
                    email: document.getElementById('email').value,
                    password: document.getElementById('password').value,
                  }),
                });
                if (r.ok) location.assign({{System.Text.Json.JsonSerializer.Serialize(safeReturnUrl)}});
              });
            </script>
            """, "text/html");
        });

        // Where the SP-initiated loop lands after the ACS accepts the assertion.
        endpoints.MapGet("/welcome", (HttpContext http) =>
        {
            var principal = http.GetSentinelPrincipal();
            return principal is null
                ? Results.Unauthorized()
                : Results.Ok(new { message = "signed in via SAML", subjectId = principal.SubjectId });
        });

        return endpoints;
    }

    /// <summary>
    /// Seeds the two connection records AFTER the host is built: the pinned certificate
    /// is the IdP's live signing key wrapped in a self-signed cert, read off
    /// <see cref="SamlIdpService.SigningCertificate"/> (scoped service, hence the scope).
    /// Returns the SP-side connection so tests can re-pin it.
    /// </summary>
    public static async Task<SamlIdpConnection> SeedConnectionsAsync(IServiceProvider services, string origin)
    {
        await SentinelHost.InitializeAsync(services);

        string certificatePem;
        using (var scope = services.CreateScope())
        {
            certificatePem = scope.ServiceProvider.GetRequiredService<SamlIdpService>()
                .SigningCertificate.ExportCertificatePem();
        }

        var saml = services.GetRequiredService<InMemorySamlStore>();

        // SP side: "authenticate against THIS IdP" — entity id, SSO URL, and THE PIN.
        // Assertion signatures verify against this certificate and nothing else.
        var idpConnection = new SamlIdpConnection
        {
            RealmId = RealmId,
            Key = ConnectionKey,
            DisplayName = "Loopback IdP",
            IdpEntityId = IdpEntityId,
            IdpSsoUrl = origin + "/saml/idp/sso",
            IdpCertificatePem = certificatePem,
            SpEntityId = SpEntityId,
            CreatedAt = DateTimeOffset.UtcNow,
        };
        await saml.AddIdpConnectionAsync(idpConnection);

        // IdP side: "issue assertions to THIS SP" — routed by AuthnRequest issuer, delivered
        // only to the registered ACS.
        await saml.AddSpConnectionAsync(new SamlSpConnection
        {
            RealmId = RealmId,
            SpEntityId = SpEntityId,
            AcsUrl = origin + "/auth/saml/acs",
            Audience = SpEntityId,
            AttributeMappings =
            [
                new SamlAttributeMapping("email", "email"),
                new SamlAttributeMapping("name", "displayName"),
            ],
            CreatedAt = DateTimeOffset.UtcNow,
        });

        return idpConnection;
    }

    private static void SeedUsers(InMemoryIdentityStore identity, PasswordHasher hasher)
    {
        var alice = new User
        {
            RealmId = RealmId,
            Email = UserEmail,
            EmailVerified = true,
            DisplayName = "Alice Vault",
            CreatedAt = DateTimeOffset.UtcNow,
        };
        identity.AddUser(alice, new UserCredential
        {
            UserId = alice.Id,
            Algorithm = hasher.Current.Name,
            Hash = hasher.Hash(UserPassword),
        });
    }
}

/// <summary>This host authenticates users and runs SAML flows; it grants no app permissions.</summary>
public sealed class AuthenticationOnlySource(Guid realmId) : ISubjectDataSource
{
    public ValueTask<SubjectData?> LoadAsync(
        Guid userId, Guid? organizationId, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult<SubjectData?>(new SubjectData(userId, realmId, organizationId, [], [], null));
}
