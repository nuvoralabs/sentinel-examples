using Nuvora.Nexus.Sentinel.Admin;
using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.Identity;
using Nuvora.Nexus.Sentinel.Privacy;

namespace PersonalData.Api;

/// <summary>
/// Grants: the DPO holds <c>sentinel:global:manage</c> — the fence on both export and
/// erasure. Jane is an ordinary user; her trying to export anyone is a 403, never a partial
/// bundle.
/// </summary>
public sealed class PersonalDataSubjectSource : ISubjectDataSource
{
    private static readonly Dictionary<Guid, GrantData[]> Grants = new()
    {
        [PersonalDataComposition.AdminId] =
        [
            new GrantData(SentinelSystemDefinitions.GlobalManage, GrantEffect.Allow, null, null, null, "role:dpo"),
        ],
        [PersonalDataComposition.JaneId] =
        [
            new GrantData("notes:self:write", GrantEffect.Allow, null, null, null, "role:member"),
        ],
    };

    public ValueTask<SubjectData?> LoadAsync(
        Guid userId, Guid? organizationId, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult<SubjectData?>(new SubjectData(
            userId,
            PersonalDataComposition.RealmId,
            organizationId,
            TeamMemberships: [],
            Grants: Grants.TryGetValue(userId, out var grants) ? grants : [],
            Attributes: null));
}

/// <summary>
/// The host's answer to "where do authenticators and federated links live?" — erasure
/// calls through this port to make the account unusable. The EF adapter implements it over the
/// real tables; this sample keeps a list of linked identities in memory.
/// </summary>
public sealed class InMemoryPersonalDataSource : IPersonalDataSource
{
    private readonly List<LinkedIdentity> _linked = [];

    public bool AuthenticatorsDeleted { get; private set; }

    public void AddLinkedIdentity(LinkedIdentity identity)
    {
        lock (_linked)
        {
            _linked.Add(identity);
        }
    }

    public ValueTask<IReadOnlyList<LinkedIdentity>> GetLinkedIdentitiesAsync(
        Guid userId, CancellationToken cancellationToken = default)
    {
        lock (_linked)
        {
            return ValueTask.FromResult<IReadOnlyList<LinkedIdentity>>(
                _linked.Where(l => l.UserId == userId).ToArray());
        }
    }

    public ValueTask DeleteAuthenticatorsAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        AuthenticatorsDeleted = true;
        return ValueTask.CompletedTask;
    }

    public ValueTask DeleteLinkedIdentitiesAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        lock (_linked)
        {
            _linked.RemoveAll(l => l.UserId == userId);
        }

        return ValueTask.CompletedTask;
    }

    public ValueTask UpdateUserAsync(User user, CancellationToken cancellationToken = default) =>
        // The in-memory identity store holds the same instance — the mutation IS the persist.
        ValueTask.CompletedTask;
}
