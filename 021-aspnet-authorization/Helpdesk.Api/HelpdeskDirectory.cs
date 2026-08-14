using Nuvora.Nexus.Sentinel.Authorization;

namespace Helpdesk.Api;

/// <summary>
/// Who works here and what they may do. A real deployment reads this from the identity stores;
/// a sample seeds it in memory so the article's walkthrough is reproducible.
/// </summary>
public sealed class HelpdeskDirectory : ISubjectDataSource
{
    private readonly Dictionary<Guid, (IReadOnlyList<Guid> Teams, IReadOnlyList<GrantData> Grants)> _staff = [];

    public void Grant(Guid userId, IReadOnlyList<Guid> teams, params GrantData[] grants) =>
        _staff[userId] = (teams, grants);

    public ValueTask<SubjectData?> LoadAsync(Guid userId, Guid? organizationId, CancellationToken cancellationToken = default)
    {
        var (teams, grants) = _staff.TryGetValue(userId, out var found)
            ? found
            : ((IReadOnlyList<Guid>)[], (IReadOnlyList<GrantData>)[]);

        return ValueTask.FromResult<SubjectData?>(
            new SubjectData(userId, HelpdeskComposition.Realm, organizationId, teams, grants, Attributes: null));
    }
}
