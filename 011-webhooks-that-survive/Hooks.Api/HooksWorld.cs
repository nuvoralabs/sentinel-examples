using Microsoft.Extensions.DependencyInjection;
using Nuvora.Nexus.Sentinel.Authentication;
using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Nuvora.Nexus.Sentinel.Identity;
using Nuvora.Nexus.Sentinel.Login;

namespace Hooks.Api;

/// <summary>
/// The seeded world: one realm, one operations admin who holds
/// <c>sentinel:global:manage</c> — the permission the webhook admin surface fences
/// realm-level subscriptions behind — and one ordinary user whose failed logins are the
/// event source the walkthrough subscribes to.
/// </summary>
public static class HooksWorld
{
    public static readonly Guid RealmId = Guid.Parse("00000000-0000-0000-0000-000000000001");

    public const string Issuer = "https://hooks.sample";
    public const string Audience = "hooks-api";

    public const string OpsEmail = "ops@hooks.sample";
    public const string UserEmail = "dana@hooks.sample";
    public const string Password = "sample-password-1!";

    public static Guid OpsId { get; private set; }

    public static async Task SeedAsync(IServiceProvider services)
    {
        await SentinelHost.InitializeAsync(services);

        var store = services.GetRequiredService<InMemoryIdentityStore>();
        var directory = services.GetRequiredService<HooksDirectory>();
        var hasher = services.GetRequiredService<PasswordHasher>();

        OpsId = AddUser(store, hasher, OpsEmail);
        AddUser(store, hasher, UserEmail);

        // Realm-level webhook administration rides sentinel:global:manage.
        directory.Grant(OpsId,
            new GrantData("sentinel:global:manage", GrantEffect.Allow, null, null, null, "role:ops-admin"));
    }

    private static Guid AddUser(InMemoryIdentityStore store, PasswordHasher hasher, string email)
    {
        var user = new User
        {
            RealmId = RealmId,
            Email = email,
            EmailVerified = true,
            DisplayName = email[..email.IndexOf('@')],
            CreatedAt = DateTimeOffset.UtcNow,
        };
        store.AddUser(user, new UserCredential
        {
            UserId = user.Id,
            Algorithm = hasher.Current.Name,
            Hash = hasher.Hash(Password),
        });
        return user.Id;
    }
}

/// <summary>Grant directory backing <see cref="ISubjectDataSource"/> (see sample 005).</summary>
public sealed class HooksDirectory : ISubjectDataSource
{
    private readonly Dictionary<Guid, GrantData[]> _grants = [];

    public void Grant(Guid userId, params GrantData[] grants) => _grants[userId] = grants;

    public ValueTask<SubjectData?> LoadAsync(
        Guid userId, Guid? organizationId, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult<SubjectData?>(new SubjectData(
            userId, HooksWorld.RealmId, organizationId, [],
            _grants.TryGetValue(userId, out var grants) ? grants : [], null));
}
