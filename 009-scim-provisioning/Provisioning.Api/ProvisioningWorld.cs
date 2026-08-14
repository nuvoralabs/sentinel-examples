using Microsoft.Extensions.DependencyInjection;
using Nuvora.Nexus.Sentinel.Identity;
using Nuvora.Nexus.Sentinel.Login;
using Nuvora.Nexus.Sentinel.Scim;

namespace Provisioning.Api;

/// <summary>
/// The fixed world this sample provisions into: one realm, two organizations, and one
/// employee who existed before any IdP showed up — so the walkthrough can demonstrate that a
/// SCIM token can't steal an existing identity into its own org (realm-wide userName
/// uniqueness answers 409).
/// </summary>
public static class ProvisioningWorld
{
    public static readonly Guid RealmId = Guid.Parse("00000000-0000-0000-0000-000000000001");

    /// <summary>Org A — "Acme Clinic". Its IdP gets one sct_ token.</summary>
    public static readonly Guid AcmeId = Guid.Parse("11111111-1111-1111-1111-111111111111");

    /// <summary>Org B — "Globex Health". A different IdP, a different token.</summary>
    public static readonly Guid GlobexId = Guid.Parse("22222222-2222-2222-2222-222222222222");

    /// <summary>Pre-existing (non-SCIM) Acme employee; realm-unique userName demo.</summary>
    public const string ExistingEmail = "ada@acme.sample";

    /// <summary>Seeds the store with the pre-existing employee.</summary>
    public static void Seed(InMemoryScimStore store)
    {
        store.AddUser(new User
        {
            RealmId = RealmId,
            Email = ExistingEmail,
            EmailVerified = true,
            DisplayName = "Ada Adminson",
            CreatedAt = DateTimeOffset.UtcNow,
        }, AcmeId);
    }

    /// <summary>
    /// Mints one provisioning token per organization. ScimTokenService is scoped (the
    /// EF-backed store is DbContext-bound), so minting happens inside a service scope. The
    /// secret in <see cref="ScimTokenCreated.Secret"/> is shown exactly once — only its
    /// SHA-256 digest is stored.
    /// </summary>
    public static async Task<(ScimTokenCreated Acme, ScimTokenCreated Globex)> MintTokensAsync(
        IServiceProvider services)
    {
        await using var scope = services.CreateAsyncScope();
        var tokens = scope.ServiceProvider.GetRequiredService<ScimTokenService>();
        var acme = await tokens.CreateAsync(RealmId, AcmeId, "acme-idp provisioning");
        var globex = await tokens.CreateAsync(RealmId, GlobexId, "globex-idp provisioning");
        return (acme, globex);
    }
}
