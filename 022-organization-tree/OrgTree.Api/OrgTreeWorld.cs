using Nuvora.Nexus.Sentinel.Admin;
using Nuvora.Nexus.Sentinel.Authentication;
using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.Definitions;
using Nuvora.Nexus.Sentinel.Identity;
using Nuvora.Nexus.Sentinel.Login;
using Nuvora.Nexus.Sentinel.Policies;

namespace OrgTree.Api;

/// <summary>
/// The seeded world: one hospital group with two regions and three clinics.
/// <code>
/// mercy                (Group)     — Mercy Health Group
/// ├── north            (Region)
/// │   ├── lakeside     (Clinic)
/// │   └── hillcrest    (Clinic)
/// └── south            (Region)
///     └── bayview      (Clinic)
/// </code>
/// Fixed ids and one password so the README's curl walkthrough and the tests speak the same
/// language. Grants are placed at ONE node each; the tree does the rest.
/// </summary>
public static class OrgTreeWorld
{
    public const string Issuer = "https://orgtree.sample";
    public const string Audience = "orgtree-api";
    public const string Password = "sample-password-1!";

    public static readonly Guid RealmId = Guid.Parse("00000000-0000-0000-0000-000000000001");

    public static Organization Group { get; private set; } = null!;

    public static Organization North { get; private set; } = null!;

    public static Organization South { get; private set; } = null!;

    public static Organization Lakeside { get; private set; } = null!;

    public static Organization Hillcrest { get; private set; } = null!;

    public static Organization Bayview { get; private set; } = null!;

    public const string GroupAdminEmail = "rhea@mercy.sample";      // sentinel:org:manage at the group root
    public const string RegionDirectorEmail = "nadia@mercy.sample"; // sentinel:org:manage at north
    public const string ClinicAdminEmail = "leo@mercy.sample";      // sentinel:org:manage at lakeside
    public const string PhysicianEmail = "mara@mercy.sample";       // charts:org:read at north; member of north

    public static Guid GroupAdminId { get; private set; }

    public static Guid RegionDirectorId { get; private set; }

    public static Guid ClinicAdminId { get; private set; }

    public static Guid PhysicianId { get; private set; }

    /// <summary>The app key the sample's chart viewer is registered under (§4.9).</summary>
    public const string ChartsApp = "charts";

    public static void Seed(
        InMemoryIdentityStore identity,
        InMemoryAdminStore admin,
        OrgTreeDirectory directory,
        InMemoryPolicyStore policies,
        InMemoryApplicationAssignmentStore apps,
        PasswordHasher hasher)
    {
        admin.AddRealm(new Realm { Id = RealmId, Key = "default", DisplayName = "Sample Realm" });

        // The tree (§4.6). AddChildOrganization derives ParentId/RootId/Depth/Path/PathKey;
        // the identity store must see the SAME rows, since it doubles as the node directory
        // the login stack resolves nodes through.
        Group = new Organization { RealmId = RealmId, Key = "mercy", DisplayName = "Mercy Health Group" };
        admin.AddOrganization(Group);
        North = admin.AddChildOrganization(Group, "north", "North Region");
        South = admin.AddChildOrganization(Group, "south", "South Region");
        Lakeside = admin.AddChildOrganization(North, "lakeside", "Lakeside Clinic");
        Hillcrest = admin.AddChildOrganization(North, "hillcrest", "Hillcrest Clinic");
        Bayview = admin.AddChildOrganization(South, "bayview", "Bayview Clinic");
        foreach (var node in new[] { Group, North, South, Lakeside, Hillcrest, Bayview })
        {
            identity.AddOrganization(node);
        }

        // Level labels are per tenant (§4.6): what the admin UI calls each depth.
        admin.ReplaceOrganizationLevelsAsync(Group.Id,
        [
            new OrganizationLevel { RealmId = RealmId, RootId = Group.Id, Depth = 0, Label = "Group" },
            new OrganizationLevel { RealmId = RealmId, RootId = Group.Id, Depth = 1, Label = "Region" },
            new OrganizationLevel { RealmId = RealmId, RootId = Group.Id, Depth = 2, Label = "Clinic" },
        ]).GetAwaiter().GetResult();

        // Membership is per node (§4.8): a member of a node may act in it or beneath it.
        GroupAdminId = AddUser(identity, admin, hasher, GroupAdminEmail, Group.Id);
        RegionDirectorId = AddUser(identity, admin, hasher, RegionDirectorEmail, North.Id);
        ClinicAdminId = AddUser(identity, admin, hasher, ClinicAdminEmail, Lakeside.Id);
        PhysicianId = AddUser(identity, admin, hasher, PhysicianEmail, North.Id);

        // One grant each, at one node each. Inherit (default true) is what makes a grant at a
        // region reach its clinics (§4.7); a clinic-level grant never reaches a sibling clinic.
        directory.Grant(GroupAdminId,
            new GrantData("sentinel:org:manage", GrantEffect.Allow, Group.Id, null, null, "role:group-admin"));
        directory.Grant(RegionDirectorId,
            new GrantData("sentinel:org:manage", GrantEffect.Allow, North.Id, null, null, "role:region-director"));
        directory.Grant(ClinicAdminId,
            new GrantData("sentinel:org:manage", GrantEffect.Allow, Lakeside.Id, null, null, "role:clinic-admin"));
        directory.Grant(PhysicianId,
            new GrantData("charts:org:read", GrantEffect.Allow, North.Id, null, null, "role:physician"));

        // Policies (§12.2): the realm allows eight-hour idle sessions; North tightens to one
        // hour for every clinic beneath it. A clinic may tighten further, never loosen.
        Upsert(policies, PolicyLevelKind.Realm, RealmId, SentinelPolicyAttributes.SessionIdleMinutes, "480");
        Upsert(policies, PolicyLevelKind.Node, North.Id, SentinelPolicyAttributes.SessionIdleMinutes, "60");

        // Application assignment (§4.9): the chart viewer is allowed group-wide, and denied at
        // Hillcrest. Deny wins over an inherited allow.
        apps.UpsertAsync(new ApplicationAssignment
        {
            RealmId = RealmId, AppKey = ChartsApp, OrganizationId = Group.Id,
            Effect = ApplicationAssignmentEffect.Allow, Inherit = true, CreatedAt = DateTimeOffset.UtcNow,
        }).GetAwaiter().GetResult();
        apps.UpsertAsync(new ApplicationAssignment
        {
            RealmId = RealmId, AppKey = ChartsApp, OrganizationId = Hillcrest.Id,
            Effect = ApplicationAssignmentEffect.Deny, Inherit = false, CreatedAt = DateTimeOffset.UtcNow,
        }).GetAwaiter().GetResult();
    }

    private static void Upsert(InMemoryPolicyStore policies, PolicyLevelKind kind, Guid levelId, string key, string json) =>
        policies.UpsertAsync(new PolicyValue
        {
            RealmId = RealmId, LevelKind = kind, LevelId = levelId, AttributeKey = key, ValueJson = json,
            UpdatedAt = DateTimeOffset.UtcNow,
        }).GetAwaiter().GetResult();

    private static Guid AddUser(
        InMemoryIdentityStore identity, InMemoryAdminStore admin, PasswordHasher hasher,
        string email, params Guid[] nodes)
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
        admin.AddUser(user, nodes);
        foreach (var node in nodes)
        {
            identity.AddOrgMembership(user.Id, node);
        }

        return user.Id;
    }
}
