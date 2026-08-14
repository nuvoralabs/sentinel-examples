using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.Identity;
using Nuvora.Nexus.Sentinel.Login;

namespace MultiOrg.Api;

/// <summary>
/// The sample's <see cref="ISubjectDataSource"/> — the port a real host backs with its grant
/// tables (the EF adapter ships one). Permission snapshots are computed per (user, org):
/// the requested org context flows into the snapshot, and org-tagged grants are
/// fenced by the evaluator against exactly that context.
/// </summary>
public sealed class MultiOrgDirectory(InMemoryIdentityStore identity, Guid realmId) : ISubjectDataSource
{
    private readonly Dictionary<Guid, GrantData[]> _grants = [];

    public void Grant(Guid userId, params GrantData[] grants) => _grants[userId] = grants;

    public async ValueTask<SubjectData?> LoadAsync(
        Guid userId, Guid? organizationId, CancellationToken cancellationToken = default)
    {
        var user = await ((IUserStore)identity).GetAsync(userId, cancellationToken);
        if (user is null || user.Status != UserStatus.Active)
        {
            return null;
        }

        // Port contract: null when the user is not a member of the requested org — a token
        // minted for an org the user has left produces NO snapshot, not a realm-level one.
        if (organizationId is { } org)
        {
            var memberships = await ((IUserStore)identity).GetOrganizationIdsAsync(userId, cancellationToken);
            if (!memberships.Contains(org))
            {
                return null;
            }
        }

        var grants = _grants.TryGetValue(userId, out var configured) ? configured : [];
        return new SubjectData(userId, realmId, organizationId, [], grants, user.Attributes);
    }
}
