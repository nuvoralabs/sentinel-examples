using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Ledger.Api;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Nuvora.Nexus.Sentinel.Audit;
using Nuvora.Nexus.Sentinel.DependencyInjection;

namespace Ledger.Api.Tests;

/// <summary>
/// In-memory host for the sample: the SAME composition as Program.cs, plus direct
/// access to the live <see cref="InMemoryAuditStore"/> — its reads return the stored entry
/// instances, which is exactly what the tamper demonstrations need.
/// </summary>
internal sealed class LedgerTestHost : IAsyncDisposable
{
    private readonly IHost _host;

    private LedgerTestHost(IHost host, HttpClient client, InMemoryAuditStore auditStore)
    {
        _host = host;
        Client = client;
        AuditStore = auditStore;
    }

    public HttpClient Client { get; }

    public InMemoryAuditStore AuditStore { get; }

    public static async Task<LedgerTestHost> CreateAsync()
    {
        var host = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services => services.AddLedgerApi())
                .Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseEndpoints(endpoints => endpoints.MapLedgerApi());
                }))
            .StartAsync();

        await SentinelHost.InitializeAsync(host.Services);

        return new LedgerTestHost(
            host, host.GetTestClient(),
            (InMemoryAuditStore)host.Services.GetRequiredService<IAuditStore>());
    }

    /// <summary>Password login; returns the bearer access token.</summary>
    public async Task<string> LoginAsync(string email)
    {
        var response = await Client.PostAsJsonAsync("/auth/login",
            new { email, password = LedgerWorld.Password });
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("accessToken").GetString()!;
    }

    /// <summary>Sends an authenticated request.</summary>
    public async Task<HttpResponseMessage> SendAsync(
        string bearer, HttpMethod method, string path, object? body = null)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }

        return await Client.SendAsync(request);
    }

    /// <summary>Suspend + reactivate the target user: two chained mutations.</summary>
    public async Task MutateTwiceAsync(string adminBearer)
    {
        (await SendAsync(adminBearer, HttpMethod.Post,
            $"/sentinel-admin/orgs/{LedgerWorld.OrgId}/users/{LedgerWorld.TargetId}/suspend"))
            .EnsureSuccessStatusCode();
        (await SendAsync(adminBearer, HttpMethod.Post,
            $"/sentinel-admin/orgs/{LedgerWorld.OrgId}/users/{LedgerWorld.TargetId}/reactivate"))
            .EnsureSuccessStatusCode();
    }

    public async Task<JsonDocument> GetAuditAsync(string bearer)
    {
        var response = await SendAsync(bearer, HttpMethod.Get, "/sentinel-admin/audit?fromSequence=1&limit=50");
        response.EnsureSuccessStatusCode();
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync());
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _host.StopAsync();
        _host.Dispose();
    }
}
