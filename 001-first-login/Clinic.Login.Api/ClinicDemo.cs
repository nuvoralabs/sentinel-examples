using Microsoft.Extensions.DependencyInjection;
using Nuvora.Nexus.Sentinel.Authentication;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Nuvora.Nexus.Sentinel.Identity;
using Nuvora.Nexus.Sentinel.Login;

namespace Clinic.Login.Api;

/// <summary>
/// The demo clinic's fixed identity data. A real host loads users from a store adapter
///; this sample seeds one clinician into the in-memory stores at startup so the
/// login flow is walkable with curl the moment the app is up.
/// </summary>
public static class ClinicDemo
{
    public static readonly Guid Realm = Guid.Parse("00000000-0000-0000-0000-000000000001");
    public static readonly Guid Org = Guid.Parse("11111111-1111-1111-1111-111111111111");

    public const string Issuer = "https://clinic.example";
    public const string Audience = "clinic-portal";

    public const string Email = "dr.riley@clinic.example";
    public const string Password = "correct-horse-battery-staple";

    /// <summary>
    /// Deterministic demo TOTP secret (base32 <c>JBSWY3DPEHPK3PXP</c>) so the README can say
    /// "add this to your authenticator app". Real enrollments call <see cref="Totp.GenerateSecret"/>.
    /// </summary>
    public const string TotpSecretBase32 = "JBSWY3DPEHPK3PXP";

    public static readonly byte[] TotpSecret = Base32.Decode(TotpSecretBase32);

    /// <summary>
    /// Startup init: fail-fast signing-key check (ephemeral dev keys were opted
    /// into in <see cref="ClinicLoginServiceCollectionExtensions"/>), then seed Dr. Riley with a
    /// password credential and a TOTP enrollment so every login is a two-factor login.
    /// </summary>
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
            DisplayName = "Dr. Riley",
        };

        // Credentials carry their hash algorithm tag — here the current default, argon2id.
        store.AddUser(user, new UserCredential
        {
            UserId = user.Id,
            Algorithm = hasher.Current.Name,
            Hash = hasher.Hash(Password),
        });
        store.AddOrgMembership(user.Id, Org);

        // With a TOTP enrollment present, password login answers mfa_required (the MFA step-up).
        store.AddTotp(new TotpEnrollment
        {
            UserId = user.Id,
            Secret = TotpSecret,
            Label = "Demo authenticator",
            EnrolledAt = DateTimeOffset.UtcNow,
        });
    }
}
