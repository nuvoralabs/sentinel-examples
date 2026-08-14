using Nuvora.Nexus.Sentinel.Ports;

namespace Passkeys.Api;

/// <summary>
/// In-process event sink recording Sentinel's security events —
/// <c>passkey.registered</c>, <c>login.success</c>, and the clone-detection signal
/// <c>passkey.signcount_regression</c> — so the sample (and its tests) can observe what the wire
/// deliberately keeps generic.
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
