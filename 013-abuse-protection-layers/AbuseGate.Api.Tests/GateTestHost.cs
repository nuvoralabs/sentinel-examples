using System.Net.Http.Json;
using System.Text.Json;
using AbuseGate.Api;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Nuvora.Nexus.Sentinel.Abuse;
using Nuvora.Nexus.Sentinel.Ports;

namespace AbuseGate.Api.Tests;

/// <summary>
/// In-memory host for the sample: the SAME composition as Program.cs, with the abuse
/// thresholds injectable per scenario (each test isolates one layer, the way the tuning
/// section of the article recommends reasoning about them) and the clock replaceable so
/// lockout expiry is time-travel, not Task.Delay.
/// </summary>
internal sealed class GateTestHost : IAsyncDisposable
{
    private readonly IHost _host;

    private GateTestHost(IHost host, HttpClient client, MutableClock clock)
    {
        _host = host;
        Client = client;
        Clock = clock;
    }

    public HttpClient Client { get; }

    public MutableClock Clock { get; }

    public static async Task<GateTestHost> CreateAsync(
        SentinelAbuseOptions options, Action<IServiceCollection>? configure = null)
    {
        var clock = new MutableClock(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000));

        var host = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddAbuseGateApi(options);
                    // Registered AFTER AddSentinel's TryAdd of SystemClock: last one wins.
                    services.AddSingleton<ISentinelClock>(clock);
                    configure?.Invoke(services);
                })
                .Configure(app =>
                {
                    app.UseDemoClientIp();
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseEndpoints(endpoints => endpoints.MapAbuseGateApi());
                }))
            .StartAsync();

        await GateWorld.SeedAsync(host.Services);
        return new GateTestHost(host, host.GetTestClient(), clock);
    }

    /// <summary>One login attempt from a given (simulated) client IP.</summary>
    public async Task<HttpResponseMessage> AttemptAsync(
        string email, string password, string ip = "10.0.0.1", string? captchaToken = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/auth/login")
        {
            Content = JsonContent.Create(new { email, password, captchaToken }),
        };
        request.Headers.Add("X-Demo-Ip", ip);
        return await Client.SendAsync(request);
    }

    public static async Task<string?> ErrorCodeAsync(HttpResponseMessage response)
    {
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.TryGetProperty("error", out var error) ? error.GetString() : null;
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _host.StopAsync();
        _host.Dispose();
    }
}

/// <summary>Settable clock so lockout windows elapse without real waiting.</summary>
internal sealed class MutableClock(DateTimeOffset now) : ISentinelClock
{
    public DateTimeOffset UtcNow { get; set; } = now;
}
