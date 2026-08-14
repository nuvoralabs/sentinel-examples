using Nuvora.Nexus.Sentinel.Importers;
using Nuvora.Nexus.Sentinel.Ports;

namespace ShadowMigration.Api;

public enum MigrationMode
{
    /// <summary>The legacy authorizer stays authoritative; Sentinel runs alongside and divergences are recorded.</summary>
    Shadow,

    /// <summary>Sentinel's evaluator is the only decision path — the migration is done.</summary>
    CutOver,
}

/// <summary>
/// The host-side switchboard for the shadow rollout: which engine is authoritative, and
/// the current shadow window's <see cref="ShadowAuthzRecorder"/>. Resetting the window starts a
/// fresh recorder — after fixing a divergent grant mapping, the gate should be judged on clean
/// traffic, not on the historical disagreement that led to the fix.
/// </summary>
public sealed class MigrationState(ISentinelEventSink events)
{
    public MigrationMode Mode { get; private set; } = MigrationMode.Shadow;

    public ShadowAuthzRecorder Recorder { get; private set; } = new(events);

    public void ResetWindow() => Recorder = new ShadowAuthzRecorder(events);

    /// <summary>Only callable when the cutover gate is open: zero divergences over a non-empty sample.</summary>
    public bool TryCutOver()
    {
        if (!Recorder.Report().ReadyForCutover)
        {
            return false;
        }

        Mode = MigrationMode.CutOver;
        return true;
    }
}
