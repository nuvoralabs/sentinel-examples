using Nuvora.Nexus.Sentinel.Ports;

namespace RefreshFamilies.Api;

/// <summary>
/// In-process event sink: Sentinel emits security events (login.success,
/// token.refresh_reuse_detected, ...) through this port; hosts bridge them to their own
/// alerting/brokers. This sample records them in memory and serves them back over
/// GET /security/events so the reuse-detection walk is observable end to end.
/// </summary>
public sealed class RecordingEventSink : ISentinelEventSink
{
    private readonly List<SentinelEvent> _events = [];

    public IReadOnlyList<SentinelEvent> Snapshot()
    {
        lock (_events)
        {
            return [.. _events];
        }
    }

    public ValueTask EmitAsync(SentinelEvent evt, CancellationToken cancellationToken = default)
    {
        lock (_events)
        {
            _events.Add(evt);
        }

        return ValueTask.CompletedTask;
    }
}
