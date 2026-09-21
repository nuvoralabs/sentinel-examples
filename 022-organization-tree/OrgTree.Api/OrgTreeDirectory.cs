using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.Identity;
using Nuvora.Nexus.Sentinel.Login;

namespace OrgTree.Api;

/// <summary>
/// The sample's <see cref="ISubjectDataSource"/> — the port a real host backs with its grant
/// tables (the EF adapter ships one that does exactly this in SQL). On a tree the snapshot is
/// per (user, node): membership counts at the node or at an ancestor (§4.8), and the node's
/// ancestor path rides along so the evaluator can apply cascading grants (§4.7).
/// </summary>
public sealed class OrgTreeDirectory(InMemoryIdentityStore identity, Guid realmId) : ISubjectDataSource
{
    private readonly Dictionary<Guid, GrantData[]> _grants = [];

    public void Grant(Guid userId, params GrantData[] grants) => _grants[userId] = grants;

    public async ValueTask<SubjectData?> LoadAsync(
        Guid userId, Guid? organizationId, CancellationToken cancellationToken = default)
    {
        var users = (IUserStore)identity;
        var user = await users.GetAsync(userId, cancellationToken);
        if (user is null || user.Status != UserStatus.Active)
        {
            return null;
        }

        var grants = _grants.TryGetValue(userId, out var configured) ? configured : [];
        if (organizationId is not { } nodeId)
        {
            return new SubjectData(userId, realmId, null, [], grants, user.Attributes);
        }

        // The node and its ancestors, root first. The identity store doubles as the directory.
        var node = await ((IOrganizationDirectory)identity).GetAsync(nodeId, cancellationToken);
        if (node is null)
        {
            return null;
        }

        // Port contract: null when the user may not act here — a member of North may act in
        // Lakeside (beneath North); a member of Lakeside may not act in Hillcrest.
        var memberships = await users.GetOrganizationIdsAsync(userId, cancellationToken);
        if (!memberships.Contains(nodeId) && !node.Path.Any(memberships.Contains))
        {
            return null;
        }

        // Every grant rides along; the evaluator fences each one by node and Inherit. Real
        // adapters pre-filter to "at the node or a cascading ancestor" for size, not correctness.
        return new SubjectData(
            userId, realmId, nodeId, [], grants, user.Attributes,
            OrganizationPath: node.Path, RootOrganizationId: node.RootId);
    }
}
