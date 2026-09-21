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
using Nuvora.Nexus.Sentinel.DependencyInjection;
using OrgTree.Api;

namespace OrgTree.Api.Tests;

/// <summary>Real-HTTP host over TestServer using EXACTLY the composition Program.cs uses.</summary>
public sealed class OrgTreeTestHost : IAsyncDisposable
{
    private readonly IHost _host;

    private OrgTreeTestHost(IHost host)
    {
        _host = host;
        Client = host.GetTestClient();
    }

    public HttpClient Client { get; }

    public static async Task<OrgTreeTestHost> CreateAsync()
    {
        var host = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddLogging();
                    services.AddRouting();
                    services.AddOrgTreeApi();
                })
                .Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseEndpoints(e => e.MapOrgTreeApi());
                }))
            .StartAsync();

        await SentinelHost.InitializeAsync(host.Services);
        return new OrgTreeTestHost(host);
    }

    /// <summary>Password login, optionally selecting the node at token mint; returns the access token.</summary>
    public async Task<string> LoginAsync(string email, Guid? organizationId = null)
    {
        var response = await Client.PostAsJsonAsync("/auth/login", new
        {
            email,
            password = OrgTreeWorld.Password,
            organizationId,
        });
        response.StatusCode.Should().Be(HttpStatusCode.OK, await response.Content.ReadAsStringAsync());
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("accessToken").GetString()!;
    }

    /// <summary>Re-mints the session at another node (a membership or anything beneath one).</summary>
    public async Task<HttpResponseMessage> SwitchAsync(string bearer, Guid organizationId) =>
        await SendAsync(HttpMethod.Post, "/auth/org/switch", bearer, new { organizationId });

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

    public static async Task<JsonDocument> JsonOf(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync());

    /// <summary>The JWT payload — for reading the <c>org</c>/<c>ou</c> claims (§4.6).</summary>
    public static JsonDocument Claims(string jwt)
    {
        var payload = jwt.Split('.')[1].Replace('-', '+').Replace('_', '/');
        payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
        return JsonDocument.Parse(Convert.FromBase64String(payload));
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _host.StopAsync();
        _host.Dispose();
    }
}
