using Nuvora.Nexus.Sentinel.Importers;
using AspNetPasswordHasher = Microsoft.AspNetCore.Identity.PasswordHasher<object>;

namespace ShadowMigration.Api;

/// <summary>
/// The system being migrated away from: an ASP.NET-Core-Identity-shaped user database plus a
/// hardcoded role→permission table living in app code — the classic legacy pair the migration
/// pipeline exists for. Password hashes are REAL Identity V3 hashes (produced by the actual
/// Microsoft.AspNetCore.Identity hasher), so hash coexistence is exercised for real.
/// </summary>
public static class LegacySystem
{
    public const string AlicePassword = "alices-legacy-password-1";
    public const string BobPassword = "bobs-legacy-password-2";

    public const string AliceEmail = "alice@clinic.sample";
    public const string BobEmail = "bob@clinic.sample";

    /// <summary>The AspNetUsers/AspNetRoles/AspNetUserRoles/AspNetUserClaims rows the importer reads.</summary>
    public static IAspNetIdentitySource CreateSource()
    {
        var hasher = new AspNetPasswordHasher();
        var target = new object();
        return new Rows
        {
            Users =
            [
                new AspNetUserRow("u-alice", "alice", AliceEmail, EmailConfirmed: true,
                    hasher.HashPassword(target, AlicePassword)),
                new AspNetUserRow("u-bob", "bob", BobEmail, EmailConfirmed: true,
                    hasher.HashPassword(target, BobPassword)),
            ],
            Roles = [new AspNetRoleRow("r-support", "Support Agent")],
            UserRoles = [new AspNetUserRoleRow("u-alice", "r-support")],
            UserClaims = [new AspNetUserClaimRow("u-alice", "department", "front-desk")],
        };
    }

    /// <summary>
    /// The LEGACY authorizer — the if-ladder buried in the old app that shadow mode compares
    /// Sentinel against. It stays AUTHORITATIVE until cutover. "Support Agent" may read
    /// and close tickets; everyone else may do neither.
    /// </summary>
    public static bool Allows(string email, string permission) => permission switch
    {
        Permissions.ReadTickets or Permissions.CloseTickets =>
            string.Equals(email, AliceEmail, StringComparison.OrdinalIgnoreCase),
        _ => false,
    };

    /// <summary>The permission-grammar ids the NEW code checks; the legacy table above is keyed by the same strings.</summary>
    public static class Permissions
    {
        public const string ReadTickets = "tickets:global:read";
        public const string CloseTickets = "tickets:global:close";
    }

    private sealed class Rows : IAspNetIdentitySource
    {
        public required List<AspNetUserRow> Users { get; init; }

        public List<AspNetRoleRow> Roles { get; init; } = [];

        public List<AspNetUserRoleRow> UserRoles { get; init; } = [];

        public List<AspNetUserClaimRow> UserClaims { get; init; } = [];

        IEnumerable<AspNetUserRow> IAspNetIdentitySource.Users => Users;

        IEnumerable<AspNetRoleRow> IAspNetIdentitySource.Roles => Roles;

        IEnumerable<AspNetUserRoleRow> IAspNetIdentitySource.UserRoles => UserRoles;

        IEnumerable<AspNetUserClaimRow> IAspNetIdentitySource.UserClaims => UserClaims;
    }
}
