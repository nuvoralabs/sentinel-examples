using System.Security.Cryptography;
using System.Text;
using Nuvora.Nexus.Sentinel.Importers;
using AspNetPasswordHasher = Microsoft.AspNetCore.Identity.PasswordHasher<object>;

namespace IdentityImport.Api;

/// <summary>
/// The four systems being migrated away from, one export each — with REAL hashes,
/// produced by the actual algorithms (Identity V3, PBKDF2-SHA256, bcrypt, sha256 client
/// secrets), so hash coexistence and rotation-on-migration are exercised for real.
/// </summary>
public static class LegacyExports
{
    // The passwords behind the exported hashes — what users keep typing after the migration.
    public const string AlicePassword = "alices-identity-password-1";
    public const string KaraPassword = "karas-keycloak-password-2";
    public const string CarolPassword = "carols-auth0-password-3";

    public const string AliceEmail = "alice@legacy.sample";   // ASP.NET Core Identity
    public const string KaraEmail = "kara@legacy.sample";     // Keycloak
    public const string CarolEmail = "carol@legacy.sample";   // Auth0
    public const string DanEmail = "dan@legacy.sample";       // Auth0, blocked

    /// <summary>ASP.NET Core Identity: the AspNetUsers/Roles/UserRoles/UserClaims rows.</summary>
    public static IAspNetIdentitySource AspNetIdentity()
    {
        var hasher = new AspNetPasswordHasher();
        var target = new object();
        return new Rows
        {
            Users =
            [
                new AspNetUserRow("u-alice", "alice", AliceEmail, EmailConfirmed: true,
                    hasher.HashPassword(target, AlicePassword)),
            ],
            Roles = [new AspNetRoleRow("r-support", "Support Agent")],
            UserRoles = [new AspNetUserRoleRow("u-alice", "r-support")],
            UserClaims = [new AspNetUserClaimRow("u-alice", "department", "front-desk")],
        };
    }

    /// <summary>
    /// A Keycloak realm export (the JSON `kc.sh export` writes): realm roles, groups,
    /// users with pbkdf2-sha256 credentials, clients.
    /// </summary>
    public static string KeycloakRealmExport()
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        const int iterations = 27_500; // Keycloak's default
        var derived = Rfc2898DeriveBytes.Pbkdf2(KaraPassword, salt, iterations, HashAlgorithmName.SHA256, 32);

        return $$"""
        {
          "realm": "legacy",
          "roles": { "realm": [ { "name": "admin" } ] },
          "groups": [ { "name": "engineering", "path": "/engineering" } ],
          "users": [
            {
              "username": "kara",
              "email": "{{KaraEmail}}",
              "emailVerified": true,
              "enabled": true,
              "firstName": "Kara",
              "lastName": "Keycloak",
              "attributes": { "department": ["platform"] },
              "credentials": [
                {
                  "type": "password",
                  "algorithm": "pbkdf2-sha256",
                  "hashIterations": {{iterations}},
                  "salt": "{{Convert.ToBase64String(salt)}}",
                  "hashedSaltedValue": "{{Convert.ToBase64String(derived)}}"
                }
              ],
              "groups": ["/engineering"],
              "realmRoles": ["admin"]
            }
          ],
          "clients": [
            {
              "clientId": "legacy-spa",
              "publicClient": true,
              "enabled": true,
              "standardFlowEnabled": true,
              "consentRequired": false,
              "redirectUris": ["https://spa.legacy.sample/callback"],
              "defaultClientScopes": ["openid", "profile"]
            }
          ]
        }
        """;
    }

    /// <summary>Auth0 bulk export: newline-delimited JSON, bcrypt hashes travel verbatim.</summary>
    public static string Auth0Export()
    {
        var bcryptHash = BCrypt.Net.BCrypt.HashPassword(CarolPassword, workFactor: 4); // cheap: teaching code
        return $$"""
        {"email":"{{CarolEmail}}","email_verified":true,"name":"Carol Auth0","custom_password_hash":{"algorithm":"bcrypt","hash":{"value":"{{bcryptHash}}" } } }
        {"email":"{{DanEmail}}","email_verified":false,"blocked":true}
        """;
    }

    /// <summary>
    /// Duende/IdentityServer client config: secrets are stored as base64(sha256(secret)) —
    /// unrecoverable, which is what forces rotation-on-migration.
    /// </summary>
    public static string DuendeClientsExport()
    {
        var sha256Secret = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes("old-mvc-secret")));
        return $$"""
        [
          {
            "ClientId": "legacy-mvc",
            "ClientName": "Legacy MVC backend",
            "AllowedGrantTypes": ["authorization_code", "refresh_token"],
            "RequirePkce": true,
            "RedirectUris": ["https://mvc.legacy.sample/signin-oidc"],
            "AllowedScopes": ["openid", "profile", "api1"],
            "ClientSecrets": [ { "Value": "{{sha256Secret}}", "Type": "SharedSecret" } ]
          },
          {
            "ClientId": "legacy-public-spa",
            "RequireClientSecret": false,
            "AllowedGrantTypes": ["authorization_code"],
            "RequirePkce": true,
            "RedirectUris": ["https://spa2.legacy.sample/callback"],
            "AllowedScopes": ["openid"]
          }
        ]
        """;
    }

    private sealed class Rows : IAspNetIdentitySource
    {
        public List<AspNetUserRow> Users { get; init; } = [];

        public List<AspNetRoleRow> Roles { get; init; } = [];

        public List<AspNetUserRoleRow> UserRoles { get; init; } = [];

        public List<AspNetUserClaimRow> UserClaims { get; init; } = [];

        IEnumerable<AspNetUserRow> IAspNetIdentitySource.Users => Users;

        IEnumerable<AspNetRoleRow> IAspNetIdentitySource.Roles => Roles;

        IEnumerable<AspNetUserRoleRow> IAspNetIdentitySource.UserRoles => UserRoles;

        IEnumerable<AspNetUserClaimRow> IAspNetIdentitySource.UserClaims => UserClaims;
    }
}
