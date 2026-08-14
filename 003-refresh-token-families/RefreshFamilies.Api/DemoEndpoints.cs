using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace RefreshFamilies.Api;

public static class DemoEndpoints
{
    /// <summary>
    /// Serves the recorded security events so the rotation-and-reuse walk is observable with
    /// curl: after replaying a consumed refresh token, <c>token.refresh_reuse_detected</c> shows
    /// up here. A real host forwards the sink to alerting/webhooks instead of exposing it.
    /// </summary>
    public static IEndpointRouteBuilder MapSecurityEvents(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/security/events", (RecordingEventSink sink) =>
            Results.Ok(sink.Snapshot().Select(e => new
            {
                kind = e.Kind,
                occurredAt = e.OccurredAt,
                subjectId = e.SubjectId,
            })));

        return endpoints;
    }
}
