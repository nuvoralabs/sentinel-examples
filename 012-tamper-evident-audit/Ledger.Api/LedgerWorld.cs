using Nuvora.Nexus.Sentinel.Admin;
using Nuvora.Nexus.Sentinel.Authentication;
using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.Identity;
using Nuvora.Nexus.Sentinel.Login;

namespace Ledger.Api;

/// <summary>
/// The seeded world: one realm, one org, three personas — a realm admin whose
/// mutations feed the chain, an auditor who may only READ the ledger
/// (<c>sentinel:global:audit_read</c>), and a target user who gets suspended/reactivated to
/// generate entries.
/// </summary>
public static class LedgerWorld
{
    public const string Issuer = "https://ledger.sample";
    public const string Audience = "ledger-api";
    public const string Password = "sample-password-1!";

    public static readonly Guid RealmId = Guid.Parse("00000000-0000-0000-0000-000000000001");
    public static readonly Guid OrgId = Guid.Parse("11111111-1111-1111-1111-111111111111");

    public const string AdminEmail = "rita@ledger.sample";     // sentinel:global:manage
    public const string AuditorEmail = "vera@ledger.sample";   // sentinel:global:audit_read ONLY
    public const string TargetEmail = "sam@ledger.sample";     // the subject of the mutations

    public static Guid AdminId { get; private set; }

    public static Guid AuditorId { get; private set; }

    public static Guid TargetId { get; private set; }

    public static void Seed(
        InMemoryIdentityStore identity, InMemoryAdminStore admin,
        LedgerDirectory directory, PasswordHasher hasher)
    {
        admin.AddRealm(new Realm { Id = RealmId, Key = "default", DisplayName = "Ledger Realm" });
        admin.AddOrganization(new Organization
        {
            Id = OrgId, RealmId = RealmId, Key = "acme", DisplayName = "Acme Clinic",
        });

        AdminId = AddUser(identity, admin, hasher, AdminEmail);
        AuditorId = AddUser(identity, admin, hasher, AuditorEmail);
        TargetId = AddUser(identity, admin, hasher, TargetEmail, OrgId);

        directory.Grant(AdminId,
            new GrantData("sentinel:global:manage", GrantEffect.Allow, null, null, null, "role:realm-admin"));

        // Read-only ledger access: enough for GET /sentinel-admin/audit, not for mutations.
        directory.Grant(AuditorId,
            new GrantData("sentinel:global:audit_read", GrantEffect.Allow, null, null, null, "role:auditor"));
    }

    private static Guid AddUser(
        InMemoryIdentityStore identity, InMemoryAdminStore admin, PasswordHasher hasher,
        string email, params Guid[] orgs)
    {
        var user = new User
        {
            RealmId = RealmId,
            Email = email,
            EmailVerified = true,
            DisplayName = email[..email.IndexOf('@')],
            CreatedAt = DateTimeOffset.UtcNow,
        };
        identity.AddUser(user, new UserCredential
        {
            UserId = user.Id,
            Algorithm = hasher.Current.Name,
            Hash = hasher.Hash(Password),
        });
        admin.AddUser(user, orgs);
        foreach (var org in orgs)
        {
            identity.AddOrgMembership(user.Id, org);
        }

        return user.Id;
    }
}

/// <summary>Grant directory backing <see cref="ISubjectDataSource"/> (see sample 005).</summary>
public sealed class LedgerDirectory : ISubjectDataSource
{
    private readonly Dictionary<Guid, GrantData[]> _grants = [];

    public void Grant(Guid userId, params GrantData[] grants) => _grants[userId] = grants;

    public ValueTask<SubjectData?> LoadAsync(
        Guid userId, Guid? organizationId, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult<SubjectData?>(new SubjectData(
            userId, LedgerWorld.RealmId, organizationId, [],
            _grants.TryGetValue(userId, out var grants) ? grants : [], null));
}
