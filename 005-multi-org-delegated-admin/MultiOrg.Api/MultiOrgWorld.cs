using Nuvora.Nexus.Sentinel.Admin;
using Nuvora.Nexus.Sentinel.Authentication;
using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.Identity;
using Nuvora.Nexus.Sentinel.Login;

namespace MultiOrg.Api;

/// <summary>
/// The seeded world this sample runs in: one realm, two organizations, three
/// users. Everything is fixed GUIDs and known passwords so the README's curl walkthrough and the
/// tests speak the same language.
/// </summary>
public static class MultiOrgWorld
{
    public const string Issuer = "https://multiorg.sample";
    public const string Audience = "multiorg-api";
    public const string Password = "sample-password-1!";

    public static readonly Guid RealmId = Guid.Parse("00000000-0000-0000-0000-000000000001");

    /// <summary>Org A — "Acme Clinic".</summary>
    public static readonly Guid AcmeId = Guid.Parse("11111111-1111-1111-1111-111111111111");

    /// <summary>Org B — "Globex Health".</summary>
    public static readonly Guid GlobexId = Guid.Parse("22222222-2222-2222-2222-222222222222");

    public const string OrgAdminEmail = "diana@acme.sample";   // sentinel:org:manage on Acme ONLY
    public const string RealmAdminEmail = "rita@realm.sample"; // sentinel:global:manage (realm admin)
    public const string AnalystEmail = "mara@both.sample";     // member of BOTH orgs

    public static Guid OrgAdminId { get; private set; }

    public static Guid RealmAdminId { get; private set; }

    public static Guid AnalystId { get; private set; }

    /// <summary>
    /// Seeds identity + admin stores and the grant directory. Mara belongs to two orgs and
    /// her useful grant is restricted to Acme, so her effective permissions depend entirely on
    /// which org context her token was minted for.
    /// </summary>
    public static void Seed(
        InMemoryIdentityStore identity,
        InMemoryAdminStore admin,
        MultiOrgDirectory directory,
        PasswordHasher hasher)
    {
        admin.AddRealm(new Realm { Id = RealmId, Key = "default", DisplayName = "Sample Realm" });
        admin.AddOrganization(new Organization
        {
            Id = AcmeId, RealmId = RealmId, Key = "acme", DisplayName = "Acme Clinic",
        });
        admin.AddOrganization(new Organization
        {
            Id = GlobexId, RealmId = RealmId, Key = "globex", DisplayName = "Globex Health",
        });

        OrgAdminId = AddUser(identity, admin, hasher, OrgAdminEmail, AcmeId);
        RealmAdminId = AddUser(identity, admin, hasher, RealmAdminEmail);
        AnalystId = AddUser(identity, admin, hasher, AnalystEmail, AcmeId, GlobexId);

        // The org admin's manage grant is org-tagged — the admin surface resolves every
        // target's org and checks THIS scope against it, so Globex is structurally out of reach.
        directory.Grant(OrgAdminId,
            new GrantData("sentinel:org:manage", GrantEffect.Allow, AcmeId, null, null, "role:org-admin"));

        // Global (realm) admin is a distinct scope; it reaches every org.
        directory.Grant(RealmAdminId,
            new GrantData("sentinel:global:manage", GrantEffect.Allow, null, null, null, "role:realm-admin"));

        // The analyst may read reports only in Acme — the grant carries the org
        // restriction, so a Globex-context snapshot evaluates it as not applicable.
        directory.Grant(AnalystId,
            new GrantData("reports:org:read", GrantEffect.Allow, AcmeId, null, null, "role:acme-analyst"));
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
