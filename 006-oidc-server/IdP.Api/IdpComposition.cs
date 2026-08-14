using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Nuvora.Nexus.Sentinel.AspNetCore.DependencyInjection;
using Nuvora.Nexus.Sentinel.AspNetCore.Endpoints;
using Nuvora.Nexus.Sentinel.Authentication;
using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Nuvora.Nexus.Sentinel.Identity;
using Nuvora.Nexus.Sentinel.Login;
using Nuvora.Nexus.Sentinel.OidcServer.DependencyInjection;
using Nuvora.Nexus.Sentinel.OidcServer.Endpoints;

namespace IdP.Api;

/// <summary>
/// Sentinel as an OAuth2/OIDC authorization server: discovery, JWKS, authorize
/// (code + PKCE), token, userinfo — with the interaction contract: the authorize endpoint
/// delegates the login UI to THIS host app's /login page. Shared verbatim by Program.cs and the
/// tests.
/// </summary>
public static class IdpComposition
{
    public const string Issuer = "https://idp.sample";
    public const string Audience = "idp-api";
    public const string UserEmail = "ada@clinic.sample";
    public const string UserPassword = "sample-password-1!";

    /// <summary>The relying party's registration — must match Partner.Web's options.</summary>
    public const string PartnerClientId = "partner-web";
    public const string PartnerRedirectUri = "https://partner.sample/callback";

    /// <summary>Second registered redirect for the local two-app `dotnet run` walkthrough.</summary>
    public const string PartnerLocalRedirectUri = "http://localhost:5007/callback";

    public static readonly Guid RealmId = Guid.Parse("00000000-0000-0000-0000-000000000006");

    public static IServiceCollection AddIdpApi(this IServiceCollection services)
    {
        var identity = new InMemoryIdentityStore();
        var oidcStore = new InMemoryOidcStore();
        // Cheap argon2id parameters: this sample teaches protocol wiring, not KDF hardness.
        var hasher = new PasswordHasher(new Argon2idPasswordHashAlgorithm(memoryKib: 8, iterations: 1, parallelism: 1));
        Seed(identity, oidcStore, hasher);

        // Identity + client-registry store ports — deliberately NOT defaulted by AddSentinel /
        // AddSentinelOidcServer: an AS silently running on an in-memory registry is a
        // footgun, so opting in is explicit.
        services.AddSingleton<IUserStore>(identity);
        services.AddSingleton<IMfaStore>(identity);
        services.AddSingleton<ISessionStore>(identity);
        services.AddSingleton<IOidcStore>(oidcStore);
        // The token endpoint also serves client_credentials, whose service depends
        // on the machine-identity store — in-memory here, empty registry = no machine clients.
        services.AddSingleton<IMachineIdentityStore, InMemoryMachineIdentityStore>();
        services.AddSingleton<ISubjectDataSource>(new AuthenticationOnlySubjectSource(RealmId));
        services.AddSingleton(hasher);

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
            // Default BearerAndCookie transport: the COOKIE half is what carries the
            // login session into the authorize endpoint.
        });
        services.AddSentinelOidcServer(); // issuer falls back to SentinelTokenOptions.Issuer

        return services;
    }

    private static void Seed(InMemoryIdentityStore identity, InMemoryOidcStore oidcStore, PasswordHasher hasher)
    {
        var ada = new User
        {
            RealmId = RealmId,
            Email = UserEmail,
            EmailVerified = true,
            DisplayName = "Ada Lovelace",
            CreatedAt = DateTimeOffset.UtcNow,
        };
        identity.AddUser(ada, new UserCredential
        {
            UserId = ada.Id,
            Algorithm = hasher.Current.Name,
            Hash = hasher.Hash(UserPassword),
        });

        // A PUBLIC client (browser app — no secret it could keep), so PKCE is REQUIRED.
        // First-party: consent is skipped per the per-client consent policy.
        oidcStore.AddClient(new OidcClient
        {
            RealmId = RealmId,
            ClientId = PartnerClientId,
            ClientType = OidcClientType.Public,
            RedirectUris = [PartnerRedirectUri, PartnerLocalRedirectUri],
            AllowedScopes = ["openid", "profile", "email", "offline_access"],
            FirstParty = true,
            RequireConsent = false,
            CreatedAt = DateTimeOffset.UtcNow,
        });
    }

    public static IEndpointRouteBuilder MapIdpApi(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapSentinelAuth(); // /auth/login — establishes the cookie login session
        endpoints.MapSentinelOidc(); // /.well-known/openid-configuration, /oidc/*

        // -------------------------------------------------------------------------------------
        // Interaction contract, host side: an unauthenticated authorize request 302s to
        // /login?returnUrl={the exact authorize URL}. This page authenticates the user (POST
        // /auth/login sets the Sentinel cookies) and then sends the browser back to returnUrl,
        // which re-enters /oidc/authorize with a principal present. Login UI is app-owned
        // — Sentinel ships no hosted pages.
        // -------------------------------------------------------------------------------------
        endpoints.MapGet("/login", (string? returnUrl) =>
        {
            // Open-redirect guard: the returnUrl is always the site-relative authorize URL;
            // anything else (absolute, protocol-relative) is replaced with "/".
            var safeReturnUrl = returnUrl is ['/', not '/', ..] ? returnUrl : "/";
            return Results.Content($$"""
            <!doctype html>
            <title>Sign in — IdP.Api</title>
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
                // On success the Sentinel cookie session exists; bounce back into authorize.
                if (r.ok) location.assign({{System.Text.Json.JsonSerializer.Serialize(safeReturnUrl)}});
              });
            </script>
            """, "text/html");
        });

        return endpoints;
    }
}

/// <summary>This host authenticates users and runs OIDC flows; it grants no app permissions (authorization is sample 005's story).</summary>
public sealed class AuthenticationOnlySubjectSource(Guid realmId) : ISubjectDataSource
{
    public ValueTask<SubjectData?> LoadAsync(
        Guid userId, Guid? organizationId, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult<SubjectData?>(new SubjectData(userId, realmId, organizationId, [], [], Attributes: null));
}
