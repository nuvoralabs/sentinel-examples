using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using IdP.Api;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Partner.Web;

namespace Sso.Tests;

/// <summary>
/// Manual cookie jar: TestServer's HttpClient does no cookie handling, which is what we want —
/// the tests play the browser, so every Set-Cookie is inspected and replayed on purpose.
/// </summary>
public sealed class CookieJar
{
    private readonly Dictionary<string, string> _cookies = new(StringComparer.Ordinal);

    public string? this[string name] => _cookies.TryGetValue(name, out var value) ? value : null;

    public void Update(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var headers))
        {
            return;
        }

        foreach (var header in headers)
        {
            var pair = header.Split(';')[0];
            var eq = pair.IndexOf('=');
            var name = pair[..eq];
            var value = pair[(eq + 1)..];
            if (value.Length == 0)
            {
                _cookies.Remove(name);
            }
            else
            {
                _cookies[name] = value;
            }
        }
    }

    public void Apply(HttpRequestMessage request)
    {
        if (_cookies.Count > 0)
        {
            request.Headers.Add("Cookie", string.Join("; ", _cookies.Select(kv => $"{kv.Key}={kv.Value}")));
        }
    }
}

/// <summary>
/// Both sample apps on TestServers, wired the way the real world wires them: the BROWSER
/// (the test, with two cookie jars) travels between them via redirects; Partner.Web's
/// back-channel "idp" HttpClient is pointed at the IdP TestServer's handler.
/// </summary>
public sealed class SsoTestWorld : IAsyncDisposable
{
    private readonly IHost _idpHost;
    private readonly IHost _partnerHost;

    private SsoTestWorld(IHost idpHost, IHost partnerHost)
    {
        _idpHost = idpHost;
        _partnerHost = partnerHost;
        IdpClient = idpHost.GetTestClient();
        PartnerClient = partnerHost.GetTestClient();
        IdpJar = new CookieJar();
        PartnerJar = new CookieJar();
    }

    public HttpClient IdpClient { get; }

    public HttpClient PartnerClient { get; }

    /// <summary>The browser's cookies at the IdP origin (the Sentinel login session).</summary>
    public CookieJar IdpJar { get; }

    /// <summary>The browser's cookies at the partner origin (state + session cookies).</summary>
    public CookieJar PartnerJar { get; }

    public static async Task<SsoTestWorld> CreateAsync()
    {
        var idpHost = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddLogging();
                    services.AddRouting();
                    services.AddIdpApi();
                })
                .Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseEndpoints(e => e.MapIdpApi());
                }))
            .StartAsync();
        await SentinelHost.InitializeAsync(idpHost.Services); // same startup step as Program.cs

        var idpServer = idpHost.GetTestServer();
        var partnerHost = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddLogging();
                    services.AddRouting();
                    services.AddPartnerWeb(o =>
                    {
                        o.IdpAuthority = IdpComposition.Issuer;               // browser-facing base
                        o.RedirectUri = IdpComposition.PartnerRedirectUri;    // registered verbatim (exact match)
                    });
                    // Back-channel calls land on the IdP TestServer instead of the network.
                    services.AddHttpClient(PartnerComposition.IdpHttpClient)
                        .ConfigurePrimaryHttpMessageHandler(() => idpServer.CreateHandler());
                })
                .Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(e => e.MapPartnerWeb());
                }))
            .StartAsync();

        return new SsoTestWorld(idpHost, partnerHost);
    }

    /// <summary>GET on the given app, replaying and capturing that origin's cookies — one browser navigation.</summary>
    public async Task<HttpResponseMessage> NavigateAsync(HttpClient client, CookieJar jar, string url)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        jar.Apply(request);
        var response = await client.SendAsync(request);
        jar.Update(response);
        return response;
    }

    /// <summary>Establishes the Sentinel cookie session at the IdP — what the /login page's form does.</summary>
    public async Task LoginAtIdpAsync()
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/auth/login")
        {
            Content = JsonContent.Create(new
            {
                email = IdpComposition.UserEmail,
                password = IdpComposition.UserPassword,
            }),
        };
        IdpJar.Apply(request);
        var response = await IdpClient.SendAsync(request);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        IdpJar.Update(response);
        IdpJar["sentinel_at"].Should().NotBeNullOrEmpty("login must establish the cookie session");
    }

    public async ValueTask DisposeAsync()
    {
        IdpClient.Dispose();
        PartnerClient.Dispose();
        await _idpHost.StopAsync();
        await _partnerHost.StopAsync();
        _idpHost.Dispose();
        _partnerHost.Dispose();
    }
}
