using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Nuvora.Nexus.Sentinel.Login;
using Nuvora.Nexus.Sentinel.Scim;
using Provisioning.Api;

namespace Provisioning.Api.Tests;

/// <summary>
/// In-memory host for the sample: the SAME composition as Program.cs
/// (<see cref="ProvisioningComposition.AddProvisioningApi"/>), served through TestHost, with the
/// two per-org sct_ tokens minted exactly the way the app mints them at startup.
/// </summary>
internal sealed class ProvisioningTestHost : IAsyncDisposable
{
    private readonly IHost _host;

    private ProvisioningTestHost(
        IHost host, HttpClient client, InMemoryScimStore store,
        ScimTokenCreated acme, ScimTokenCreated globex)
    {
        _host = host;
        Client = client;
        Store = store;
        AcmeToken = acme;
        GlobexToken = globex;
    }

    public HttpClient Client { get; }

    public InMemoryScimStore Store { get; }

    /// <summary>Provisioning token scoped to Acme Clinic.</summary>
    public ScimTokenCreated AcmeToken { get; }

    /// <summary>Provisioning token scoped to Globex Health.</summary>
    public ScimTokenCreated GlobexToken { get; }

    public static async Task<ProvisioningTestHost> CreateAsync()
    {
        var host = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services => services.AddProvisioningApi())
                .Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints => endpoints.MapProvisioningApi());
                }))
            .StartAsync();

        var (acme, globex) = await ProvisioningWorld.MintTokensAsync(host.Services);
        return new ProvisioningTestHost(
            host, host.GetTestClient(),
            host.Services.GetRequiredService<InMemoryScimStore>(), acme, globex);
    }

    /// <summary>
    /// Builds a SCIM request. <paramref name="bearer"/>: "acme"/"globex" pick the minted
    /// tokens, any other string is sent verbatim, null sends no Authorization header.
    /// </summary>
    public HttpRequestMessage Request(HttpMethod method, string path, object? body = null, string? bearer = "acme")
    {
        var request = new HttpRequestMessage(method, path);
        if (bearer is not null)
        {
            var secret = bearer switch
            {
                "acme" => AcmeToken.Secret,
                "globex" => GlobexToken.Secret,
                _ => bearer,
            };
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", secret);
        }

        if (body is not null)
        {
            request.Content = new StringContent(
                JsonSerializer.Serialize(body), Encoding.UTF8, ScimConstants.MediaType);
        }

        return request;
    }

    public static async Task<JsonDocument> ReadJsonAsync(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync());

    /// <summary>Revokes a minted token (ScimTokenService is scoped, hence the scope).</summary>
    public async Task RevokeAsync(ScimTokenCreated token)
    {
        await using var scope = _host.Services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<ScimTokenService>().RevokeAsync(token.Token.Id);
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _host.StopAsync();
        _host.Dispose();
    }
}
