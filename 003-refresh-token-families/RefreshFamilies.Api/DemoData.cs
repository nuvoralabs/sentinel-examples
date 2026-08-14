using Microsoft.Extensions.DependencyInjection;
using Nuvora.Nexus.Sentinel.Authentication;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Nuvora.Nexus.Sentinel.Identity;
using Nuvora.Nexus.Sentinel.Login;

namespace RefreshFamilies.Api;

/// <summary>Fixed demo identity: one user, password only (no MFA — this sample is about refresh tokens).</summary>
public static class DemoData
{
    public static readonly Guid Realm = Guid.Parse("00000000-0000-0000-0000-000000000001");
    public static readonly Guid Org = Guid.Parse("11111111-1111-1111-1111-111111111111");

    public const string Issuer = "https://refresh.example";
    public const string Audience = "refresh-demo";

    public const string Email = "casey@refresh.example";
    public const string Password = "rotate-early-rotate-often";

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
            DisplayName = "Casey",
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
