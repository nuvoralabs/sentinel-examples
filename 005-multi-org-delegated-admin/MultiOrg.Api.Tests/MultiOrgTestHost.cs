using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using MultiOrg.Api;
using Nuvora.Nexus.Sentinel.DependencyInjection;

namespace MultiOrg.Api.Tests;

/// <summary>
/// Real-HTTP host over TestServer using EXACTLY the composition Program.cs uses — the test proves
/// the sample, not a parallel wiring. Each test creates its own host so state never bleeds.
/// </summary>
public sealed class MultiOrgTestHost : IAsyncDisposable
{
    private readonly IHost _host;

    private MultiOrgTestHost(IHost host)
    {
        _host = host;
        Client = host.GetTestClient();
    }

    public HttpClient Client { get; }

    public static async Task<MultiOrgTestHost> CreateAsync()
    {
        var host = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddLogging();
                    services.AddRouting();
                    services.AddMultiOrgApi();
                })
                .Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseEndpoints(e => e.MapMultiOrgApi());
                }))
            .StartAsync();

        // Same startup step as Program.cs.
        await SentinelHost.InitializeAsync(host.Services);
        return new MultiOrgTestHost(host);
    }

    /// <summary>Password login, optionally selecting the org context at token mint.</summary>
    public async Task<string> LoginAsync(string email, Guid? organizationId = null)
    {
        var response = await Client.PostAsJsonAsync("/auth/login", new
        {
            email,
            password = MultiOrgWorld.Password,
            organizationId,
        });
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("accessToken").GetString()!;
    }

    public async Task<HttpResponseMessage> SendAsync(
        HttpMethod method, string path, string bearer, object? body = null)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }

        return await Client.SendAsync(request);
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _host.StopAsync();
        _host.Dispose();
    }
}
