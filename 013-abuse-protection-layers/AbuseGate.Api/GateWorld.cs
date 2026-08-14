using Microsoft.Extensions.DependencyInjection;
using Nuvora.Nexus.Sentinel.Authentication;
using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Nuvora.Nexus.Sentinel.Identity;
using Nuvora.Nexus.Sentinel.Login;

namespace AbuseGate.Api;

/// <summary>
/// The seeded world: two ordinary users. The interesting behavior in this sample is
/// entirely in what happens BEFORE their credentials are even looked at.
/// </summary>
public static class GateWorld
{
    public static readonly Guid RealmId = Guid.Parse("00000000-0000-0000-0000-000000000001");

    public const string Issuer = "https://gate.sample";
    public const string Audience = "gate-api";

    public const string AliceEmail = "alice@gate.sample";
    public const string BobEmail = "bob@gate.sample";
    public const string Password = "sample-password-1!";

    /// <summary>The token the demo captcha verifier accepts (stands in for Turnstile et al.).</summary>
    public const string CaptchaAnswer = "let-me-in";

    public const string CaptchaSiteKey = "demo-site-key";

    public static async Task SeedAsync(IServiceProvider services)
    {
        await SentinelHost.InitializeAsync(services);

        var store = services.GetRequiredService<InMemoryIdentityStore>();
        var hasher = services.GetRequiredService<PasswordHasher>();

        AddUser(store, hasher, AliceEmail);
        AddUser(store, hasher, BobEmail);
    }

    private static void AddUser(InMemoryIdentityStore store, PasswordHasher hasher, string email)
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
    }
}

/// <summary>Minimal snapshot source — this sample needs no app permissions.</summary>
public sealed class GateSubjectSource : ISubjectDataSource
{
    public ValueTask<SubjectData?> LoadAsync(
        Guid userId, Guid? organizationId, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult<SubjectData?>(new SubjectData(
            userId, GateWorld.RealmId, organizationId, [], [], null));
}
