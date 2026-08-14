using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Nuvora.Nexus.Sentinel.Audit;
using Nuvora.Nexus.Sentinel.Ports;
using StepUp.Api;

namespace StepUp.Api.Tests;

/// <summary>
/// In-memory host for the sample: the SAME composition as Program.cs, plus a recording
/// event sink (registered before AddStepUpApi so the TryAdd default yields) — the
/// risk.evaluated / risk.stepup / risk.blocked stream is half the story.
/// </summary>
internal sealed class StepUpTestHost : IAsyncDisposable
{
    private readonly IHost _host;

    private StepUpTestHost(
        IHost host, HttpClient client, DemoMailer mailer, RecordingEventSink events, IAuditStore audit)
    {
        _host = host;
        Client = client;
        Mailer = mailer;
        Events = events;
        AuditStore = audit;
    }

    public HttpClient Client { get; }

    public DemoMailer Mailer { get; }

    public RecordingEventSink Events { get; }

    /// <summary>The security ledger — risk.evaluated rows land here, not on the sink.</summary>
    public IAuditStore AuditStore { get; }

    public static async Task<StepUpTestHost> CreateAsync()
    {
        var events = new RecordingEventSink();

        var host = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddSingleton<ISentinelEventSink>(events);
                    services.AddStepUpApi();
                })
                .Configure(app =>
                {
                    app.UseDemoClientIp();
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseEndpoints(endpoints => endpoints.MapStepUpApi());
                }))
            .StartAsync();

        await StepUpWorld.SeedAsync(host.Services);
        return new StepUpTestHost(
            host, host.GetTestClient(), host.Services.GetRequiredService<DemoMailer>(), events,
            host.Services.GetRequiredService<IAuditStore>());
    }

    /// <summary>One login attempt; IP and device fingerprint are the risk inputs.</summary>
    public async Task<HttpResponseMessage> LoginAsync(
        string email, string password, string ip = "192.0.2.10", string? deviceFingerprint = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/auth/login")
        {
            Content = JsonContent.Create(new { email, password, deviceFingerprint }),
        };
        request.Headers.Add("X-Demo-Ip", ip);
        return await Client.SendAsync(request);
    }

    /// <summary>Completes an email-OTP step-up.</summary>
    public async Task<HttpResponseMessage> VerifyEmailOtpAsync(
        string mfaPendingToken, string code, string? deviceFingerprint = null)
    {
        return await Client.PostAsJsonAsync("/auth/mfa/verify", new
        {
            mfaPendingToken,
            code,
            kind = "email_otp",
            deviceFingerprint,
        });
    }

    public static async Task<JsonDocument> ReadJsonAsync(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync());

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _host.StopAsync();
        _host.Dispose();
    }
}

/// <summary>Captures the security-event stream for assertions.</summary>
internal sealed class RecordingEventSink : ISentinelEventSink
{
    private readonly Lock _gate = new();
    private readonly List<SentinelEvent> _events = [];

    public IReadOnlyList<SentinelEvent> Events
    {
        get
        {
            lock (_gate)
            {
                return _events.ToList();
            }
        }
    }

    public ValueTask EmitAsync(SentinelEvent evt, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            _events.Add(evt);
        }

        return ValueTask.CompletedTask;
    }
}
