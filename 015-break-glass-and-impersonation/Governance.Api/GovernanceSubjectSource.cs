using Nuvora.Nexus.Sentinel.Admin;
using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.Login;

namespace Governance.Api;

/// <summary>
/// Grants for the three seeded actors. In a real host the EF store adapter joins
/// roles/groups into this shape; a governance sample hardcodes it:
/// <list type="bullet">
/// <item>the admin holds <c>sentinel:global:impersonate</c> (the impersonation fence) and
/// <c>sentinel:global:manage</c> (break-glass status/drill);</item>
/// <item>the target holds ordinary app permissions;</item>
/// <item>the break-glass account holds <c>*:*:*</c> — on purpose. The
/// <c>BreakGlassCappingDataSource</c> decorator shrinks it to the policy's capped patterns at
/// snapshot-build time, so no evaluation path ever sees the raw grant.</item>
/// </list>
/// </summary>
public sealed class GovernanceSubjectSource(InMemoryIdentityStore store) : ISubjectDataSource
{
    private static readonly Dictionary<Guid, GrantData[]> Grants = new()
    {
        [GovernanceComposition.AdminId] =
        [
            Allow(SentinelSystemDefinitions.GlobalImpersonate),
            Allow(SentinelSystemDefinitions.GlobalManage),
        ],
        [GovernanceComposition.TargetId] =
        [
            Allow("records:org:read"),
        ],
        [GovernanceComposition.BreakGlassId] =
        [
            Allow("*:*:*"), // capped to sentinel:global:* + records:global:read by the decorator
        ],
    };

    private static GrantData Allow(string pattern) =>
        new(pattern, GrantEffect.Allow, null, null, null, "role:governance-demo");

    public async ValueTask<SubjectData?> LoadAsync(
        Guid userId, Guid? organizationId, CancellationToken cancellationToken = default)
    {
        // Attributes come from the user record so the break-glass flag reaches the
        // capping decorator — it keys off SubjectData.Attributes, not the store row.
        var user = await ((IUserStore)store).GetAsync(userId, cancellationToken);
        if (user is null)
        {
            return null;
        }

        return new SubjectData(
            userId,
            GovernanceComposition.RealmId,
            organizationId,
            TeamMemberships: [],
            Grants: Grants.TryGetValue(userId, out var grants) ? grants : [],
            Attributes: user.Attributes);
    }
}
