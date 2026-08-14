using Microsoft.Extensions.Logging;
using Nuvora.Nexus.Sentinel.Ports;

namespace Governance.Api;

/// <summary>
/// Sample mailer: records every mail (the tests read consent tokens and break-glass
/// alerts out of it) and logs a redacted line so `dotnet run` shows the alarms firing. A real
/// host implements <see cref="ISentinelMailer"/> over its mail provider.
/// </summary>
public sealed class RecordingMailer(ILogger<RecordingMailer> logger) : ISentinelMailer
{
    private readonly List<SentinelMail> _sent = [];

    public IReadOnlyList<SentinelMail> Sent
    {
        get
        {
            lock (_sent)
            {
                return [.. _sent];
            }
        }
    }

    public ValueTask SendAsync(SentinelMail mail, CancellationToken cancellationToken = default)
    {
        lock (_sent)
        {
            _sent.Add(mail);
        }

        // Never log token values — the "alert" data key is enough to see what fired.
        logger.LogInformation(
            "MAIL {Kind} -> {To} ({Alert})",
            mail.Kind, mail.To, mail.Data.TryGetValue("alert", out var alert) ? alert : "-");
        return ValueTask.CompletedTask;
    }
}
