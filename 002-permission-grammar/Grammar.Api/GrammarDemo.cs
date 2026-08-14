using Nuvora.Nexus.Sentinel.Authorization;

namespace Grammar.Api;

/// <summary>
/// A hardcoded grant catalog exercising every grammar construct: per-segment wildcards, an
/// explicit deny (deny-overrides), a team-scoped grant, and an ABAC condition over a resource
/// attribute. In a real host these rows come from the store adapter, already joined across
/// roles/groups/policies; the shape — <see cref="GrantData"/> compiled once by
/// <see cref="SubjectSnapshotBuilder"/> — is identical.
/// </summary>
public static class GrammarDemo
{
    public static readonly Guid Realm = Guid.Parse("00000000-0000-0000-0000-000000000001");
    public static readonly Guid Org = Guid.Parse("11111111-1111-1111-1111-111111111111");
    public static readonly Guid CardiologyTeam = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");

    public static readonly Guid DrAdams = Guid.Parse("99999999-9999-9999-9999-999999999999");
    public static readonly Guid LocumJones = Guid.Parse("88888888-8888-8888-8888-888888888888");

    /// <summary>
    /// Resolves a demo persona to its (user, org) subject data (snapshots are per
    /// (user, org) because org membership is many-to-many). Null for unknown names.
    /// </summary>
    public static SubjectData? Resolve(string? persona) => persona switch
    {
        // Dr. Adams: staff physician on the cardiology team.
        "dr-adams" => new SubjectData(
            DrAdams, Realm, Org,
            TeamMemberships: [CardiologyTeam],
            Grants:
            [
                // Per-segment wildcard: every org-scoped action on records — including
                // actions published after this grant was written.
                new GrantData("records:org:*", GrantEffect.Allow, null, null, null, "role:physician"),

                // Explicit deny: denies override any number of allows across the whole
                // subject, so the wildcard above can never re-open bulk export.
                new GrantData("records:org:export", GrantEffect.Deny, null, null, null, "policy:phi-lockdown"),

                // Team scope: applies only when the resource shares a team with the
                // subject — checks without resource teams fail closed.
                new GrantData("records:team:annotate", GrantEffect.Allow, null, null, null, "role:physician"),

                // ABAC condition: versioned JSON AST over resource.* attributes — lab
                // results are visible only within the physician's own department.
                new GrantData(
                    "labs:org:view_results", GrantEffect.Allow, null, null,
                    """{"version":1,"condition":{"op":"eq","attr":"resource.department","value":"cardiology"}}""",
                    "policy:department-abac"),
            ],
            Attributes: new Dictionary<string, object?> { ["department"] = "cardiology" }),

        // Locum Jones: fills in on records, belongs to NO team — team-scoped checks fail closed.
        "locum-jones" => new SubjectData(
            LocumJones, Realm, Org,
            TeamMemberships: [],
            Grants:
            [
                new GrantData("records:org:read", GrantEffect.Allow, null, null, null, "role:locum"),
                new GrantData("records:team:annotate", GrantEffect.Allow, null, null, null, "role:locum"),
            ],
            Attributes: null),

        _ => null,
    };

    /// <summary>
    /// Compiles the persona's rows into an evaluable snapshot: patterns and conditions
    /// parse ONCE here, never per check — that is what keeps the hot path allocation-free.
    /// </summary>
    public static SubjectSnapshot? Snapshot(string? persona) =>
        Resolve(persona) is { } data ? SubjectSnapshotBuilder.Build(data) : null;
}
