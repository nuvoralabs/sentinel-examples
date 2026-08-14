using Microsoft.Extensions.DependencyInjection;
using Nuvora.Nexus.Sentinel.Authentication;
using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Nuvora.Nexus.Sentinel.Identity;
using Nuvora.Nexus.Sentinel.Login;
using Nuvora.Nexus.Sentinel.Ports;
using Nuvora.Nexus.Sentinel.Risk;

namespace StepUp.Api;

/// <summary>
/// The seeded world: two users with passwords and NO TOTP enrollment — so when risk
/// demands step-up, the flow falls back to email OTP. Victor is on the app's fraud
/// watchlist (the custom signal); one address is on the reputation denylist.
/// </summary>
public static class StepUpWorld
{
    public static readonly Guid RealmId = Guid.Parse("00000000-0000-0000-0000-000000000001");

    public const string Issuer = "https://stepup.sample";
    public const string Audience = "stepup-api";

    public const string NoraEmail = "nora@stepup.sample";
    public const string VictorEmail = "victor@stepup.sample"; // watchlisted
    public const string Password = "sample-password-1!";

    /// <summary>An address the sample reputation provider lists (think TOR exit / botnet).</summary>
    public const string BadIp = "185.220.101.7";

    /// <summary>User ids the custom <see cref="WatchlistSignal"/> scores.</summary>
    public static readonly HashSet<Guid> Watchlist = [];

    public static Guid NoraId { get; private set; }

    public static Guid VictorId { get; private set; }

    public static async Task SeedAsync(IServiceProvider services)
    {
        await SentinelHost.InitializeAsync(services);

        var store = services.GetRequiredService<InMemoryIdentityStore>();
        var hasher = services.GetRequiredService<PasswordHasher>();

        NoraId = AddUser(store, hasher, NoraEmail);
        VictorId = AddUser(store, hasher, VictorEmail);

        Watchlist.Clear();
        Watchlist.Add(VictorId);
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

/// <summary>Minimal snapshot source — this sample needs no app permissions.</summary>
public sealed class StepUpSubjectSource : ISubjectDataSource
{
    public ValueTask<SubjectData?> LoadAsync(
        Guid userId, Guid? organizationId, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult<SubjectData?>(new SubjectData(
            userId, StepUpWorld.RealmId, organizationId, [], [], null));
}

/// <summary>
/// A custom signal — ten lines, and it joins the built-ins in the same parallel
/// evaluation. Deterministic and explainable: the reason string lands verbatim on the
/// <c>risk.evaluated</c> security event.
/// </summary>
public sealed class WatchlistSignal : IRiskSignal
{
    public const int Weight = 40;

    public string Name => "watchlist";

    public ValueTask<RiskContribution> AssessAsync(
        RiskContext context, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(StepUpWorld.Watchlist.Contains(context.UserId)
            ? new RiskContribution(Weight, "subject is on the fraud watchlist", Name)
            : RiskContribution.None(Name, "not watchlisted"));
}

/// <summary>The reputation port with one listed address. Real hosts call a denylist here.</summary>
public sealed class DemoIpReputation : IIpReputationProvider
{
    public ValueTask<bool> IsListedAsync(string ip, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(ip == StepUpWorld.BadIp);
}

/// <summary>
/// The mailer port, demo edition: records every mail (the tests read OTP codes out of
/// <see cref="Sent"/>) and prints it so the curl walkthrough can, too.
/// </summary>
public sealed class DemoMailer : ISentinelMailer
{
    private readonly Lock _gate = new();
    private readonly List<SentinelMail> _sent = [];

    public IReadOnlyList<SentinelMail> Sent
    {
        get
        {
            lock (_gate)
            {
                return _sent.ToList();
            }
        }
    }

    public ValueTask SendAsync(SentinelMail mail, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            _sent.Add(mail);
        }

        Console.WriteLine($"[mail] kind={mail.Kind} to={mail.To} " +
            string.Join(' ', mail.Data.Select(kv => $"{kv.Key}={kv.Value}")));
        return ValueTask.CompletedTask;
    }
}
