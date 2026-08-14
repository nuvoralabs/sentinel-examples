using Microsoft.Extensions.DependencyInjection;
using Nuvora.Nexus.Sentinel.Authentication;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Nuvora.Nexus.Sentinel.Identity;
using Nuvora.Nexus.Sentinel.Login;

namespace Passkeys.Api;

/// <summary>
/// Fixed demo identity. The user starts with a password credential only: passkey registration is
/// an AUTHENTICATED ceremony (a passkey is added to an existing account), so the
/// walk is password login → register passkey → passwordless login from then on.
/// </summary>
public static class PasskeyDemo
{
    public static readonly Guid Realm = Guid.Parse("00000000-0000-0000-0000-000000000001");
    public static readonly Guid Org = Guid.Parse("11111111-1111-1111-1111-111111111111");

    public const string Issuer = "https://passkeys.example";
    public const string Audience = "passkeys-demo";

    /// <summary>WebAuthn relying-party identity: authenticators bind credentials to this domain.</summary>
    public const string RpId = "passkeys.example";
    public const string Origin = "https://passkeys.example";

    public const string Email = "sam@passkeys.example";
    public const string Password = "passwords-are-so-2010";

    /// <summary>Fail-fast key check, then seed the one demo user.</summary>
    public static async Task SeedAsync(IServiceProvider services)
    {
        await SentinelHost.InitializeAsync(services);

        var store = services.GetRequiredService<InMemoryIdentityStore>();
        var hasher = services.GetRequiredService<PasswordHasher>();

        var user = new User
        {
            RealmId = Realm,
            Email = Email,
            EmailVerified = true,
            DisplayName = "Sam",
        };

        store.AddUser(user, new UserCredential
        {
            UserId = user.Id,
            Algorithm = hasher.Current.Name,
            Hash = hasher.Hash(Password),
        });
        store.AddOrgMembership(user.Id, Org);
    }
}
