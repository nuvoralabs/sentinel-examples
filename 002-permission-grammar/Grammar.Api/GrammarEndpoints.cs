using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.Permissions;

namespace Grammar.Api;

// ---------------------------------------------------------------------------------------------
// Wire contracts. Attribute bags arrive as raw JSON and convert exactly like condition literals
// (numbers → double, cross-type comparisons are false, never coerced).
// ---------------------------------------------------------------------------------------------

public sealed record CheckRequest(
    string? Subject,
    string? Permission,
    Guid? ResourceOrgId,
    Guid[]? ResourceTeamIds,
    Guid? ResourceOwnerId,
    JsonElement? ResourceAttributes,
    JsonElement? ContextAttributes,
    bool Trace = false);

public sealed record TraceEntryView(string Pattern, string Effect, string Source, string Outcome);

public sealed record CheckResponse(string Outcome, bool Allowed, IReadOnlyList<TraceEntryView>? Trace);

public sealed record VisibilityRequest(string? Subject, string? Service, string? Action, string? Scope);

public sealed record VisibilityResponse(string Permission, string Visibility);

public static class GrammarEndpoints
{
    /// <summary>
    /// POST <c>/check</c> — one point decision; POST <c>/visibility</c> — list-visibility
    /// classification. Both run through the SAME single evaluation path:
    /// <see cref="AuthorizationEvaluator.VisibilityFor"/> shares the grant-matching primitives
    /// with <see cref="AuthorizationEvaluator.Evaluate"/>, so a list can never show more than
    /// row-by-row checks would allow.
    /// </summary>
    public static IEndpointRouteBuilder MapGrammarEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/check", (CheckRequest request) =>
        {
            if (GrammarDemo.Snapshot(request.Subject) is not { } subject)
            {
                return Results.BadRequest(new { error = "unknown_subject", known = new[] { "dr-adams", "locum-jones" } });
            }

            if (request.Permission is null || !PermissionId.TryParse(request.Permission, out var permission))
            {
                // The grammar is service:scope:action with scope ∈ global|org|team|self.
                return Results.BadRequest(new { error = "invalid_permission", expected = "service:scope:action" });
            }

            var check = new AccessCheck(
                permission,
                resourceOrganizationId: request.ResourceOrgId,
                resourceTeamIds: request.ResourceTeamIds,
                resourceOwnerId: request.ResourceOwnerId,
                resourceAttributes: ToBag(request.ResourceAttributes),
                contextAttributes: ToBag(request.ContextAttributes));

            // The trace is opt-in: production point-checks pay nothing for it; passing
            // one runs the full pass so every grant's outcome is visible (the admin /inspect
            // debugger works the same way).
            var trace = request.Trace ? new EvaluationTrace() : null;
            var decision = AuthorizationEvaluator.Evaluate(subject, in check, trace);

            return Results.Ok(new CheckResponse(
                OutcomeName(decision.Outcome),
                decision.IsAllowed,
                trace?.Entries.Select(e => new TraceEntryView(
                    e.Pattern.ToString()!,
                    e.Effect == GrantEffect.Allow ? "allow" : "deny",
                    e.Source,
                    TraceOutcomeName(e.Outcome))).ToArray()));
        });

        endpoints.MapPost("/visibility", (VisibilityRequest request) =>
        {
            if (GrammarDemo.Snapshot(request.Subject) is not { } subject)
            {
                return Results.BadRequest(new { error = "unknown_subject", known = new[] { "dr-adams", "locum-jones" } });
            }

            if (request.Service is null || request.Action is null
                || !PermissionScopes.TryParse(request.Scope ?? "", out var scope))
            {
                return Results.BadRequest(new { error = "invalid_request", expected = "service, action, scope (global|org|team|self)" });
            }

            // Derived from the same pass as point checks: granted ⇒ list freely,
            // none ⇒ skip the query, conditional ⇒ filter by team/owner or row-check each item.
            var visibility = AuthorizationEvaluator.VisibilityFor(subject, request.Service, request.Action, scope);

            return Results.Ok(new VisibilityResponse(
                $"{request.Service}:{scope.Name()}:{request.Action}",
                visibility switch
                {
                    VisibilityLevel.Granted => "granted",
                    VisibilityLevel.Conditional => "conditional",
                    _ => "none",
                }));
        });

        return endpoints;
    }

    /// <summary>Same outcome names as the cross-language golden vectors.</summary>
    private static string OutcomeName(AccessOutcome outcome) => outcome switch
    {
        AccessOutcome.Allowed => "allowed",
        AccessOutcome.DeniedByGrant => "denied_by_grant",
        _ => "denied_by_default",
    };

    private static string TraceOutcomeName(EvaluationTrace.GrantOutcome outcome) => outcome switch
    {
        EvaluationTrace.GrantOutcome.PatternMismatch => "pattern_mismatch",
        EvaluationTrace.GrantOutcome.ScopeNotApplicable => "scope_not_applicable",
        EvaluationTrace.GrantOutcome.ConditionFailed => "condition_failed",
        EvaluationTrace.GrantOutcome.Allowed => "allowed",
        _ => "denied",
    };

    /// <summary>JSON → attribute bag, mirroring the golden-vector conversion: numbers become doubles, nested objects nested bags.</summary>
    private static IReadOnlyDictionary<string, object?>? ToBag(JsonElement? element)
    {
        if (element is not { ValueKind: JsonValueKind.Object } bag)
        {
            return null;
        }

        var result = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var property in bag.EnumerateObject())
        {
            result[property.Name] = Convert(property.Value);
        }

        return result;

        static object? Convert(JsonElement value) => value.ValueKind switch
        {
            JsonValueKind.Null => null,
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Number => value.GetDouble(),
            JsonValueKind.Array => value.EnumerateArray().Select(Convert).ToArray(),
            _ => value.EnumerateObject().ToDictionary(p => p.Name, p => Convert(p.Value)),
        };
    }
}
