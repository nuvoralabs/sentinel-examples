using Nuvora.Nexus.Sentinel.Authorization;

namespace Clinic.Login.Api;

/// <summary>
/// Feeds the permission snapshot cache: every clinic user gets one allow grant,
/// attributed to a role (the <c>service:scope:action</c> grammar). In a real host the EF Core
/// store adapter joins roles/groups/policies into this shape; a sample with one user
/// hardcodes it — sample 002 is where the grammar itself is the subject.
/// </summary>
public sealed class ClinicSubjectSource : ISubjectDataSource
{
    public ValueTask<SubjectData?> LoadAsync(
        Guid userId, Guid? organizationId, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult<SubjectData?>(new SubjectData(
            userId,
            ClinicDemo.Realm,
            organizationId,
            TeamMemberships: [],
            Grants: [new GrantData("clinic:org:view_dashboard", GrantEffect.Allow, null, null, null, "role:clinician")],
            Attributes: null));
}
