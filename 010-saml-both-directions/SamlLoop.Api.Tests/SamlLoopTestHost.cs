using System.Net;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Nuvora.Nexus.Sentinel.Identity;
using Nuvora.Nexus.Sentinel.Login;
using Nuvora.Nexus.Sentinel.Ports;
using SamlLoop.Api;

namespace SamlLoop.Api.Tests;

/// <summary>
/// In-memory host for the sample: the SAME composition as Program.cs — TestServer's
/// synthesized origin is <c>http://localhost</c>, so the connections are seeded with exactly
/// that (the endpoints compare URLs ordinally). A recording event sink captures the
/// saml.* stream, including the denial reasons the wire deliberately never carries.
/// </summary>
internal sealed class SamlLoopTestHost : IAsyncDisposable
{
    public const string Origin = "http://localhost";

    private readonly IHost _host;

    private SamlLoopTestHost(
        IHost host, HttpClient client, RecordingEventSink events,
        InMemoryFederatedIdentityStore federated, SamlIdpConnection idpConnection)
    {
        _host = host;
        Client = client;
        Events = events;
        Federated = federated;
        IdpConnection = idpConnection;
    }

    public HttpClient Client { get; }

    public RecordingEventSink Events { get; }

    public InMemoryFederatedIdentityStore Federated { get; }

    /// <summary>The live SP-side connection record — tests re-pin its certificate.</summary>
    public SamlIdpConnection IdpConnection { get; }

    public static async Task<SamlLoopTestHost> CreateAsync()
    {
        var events = new RecordingEventSink();

        var host = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddSingleton<ISentinelEventSink>(events);
                    services.AddSamlLoopApi();
                })
                .Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseEndpoints(endpoints => endpoints.MapSamlLoopApi());
                }))
            .StartAsync();

        var connection = await SamlLoopComposition.SeedConnectionsAsync(host.Services, Origin);
        return new SamlLoopTestHost(
            host, host.GetTestClient(), events,
            host.Services.GetRequiredService<InMemoryFederatedIdentityStore>(), connection);
    }

    // -------------------------------------------------------------------------------------
    // Flow helpers
    // -------------------------------------------------------------------------------------

    /// <summary>Password login into the loop host; returns the populated cookie jar.</summary>
    public async Task<CookieJar> LoginAsync()
    {
        var jar = new CookieJar();
        var response = await SendAsync(HttpMethod.Post, "/auth/login", jar,
            body: new { email = SamlLoopComposition.UserEmail, password = SamlLoopComposition.UserPassword });
        response.EnsureSuccessStatusCode();
        return jar;
    }

    /// <summary>
    /// The SP-initiated round trip up to (not including) the ACS post: start → 302 to the
    /// IdP SSO → authenticated GET → auto-post form → parsed (RelayState, SAMLResponse).
    /// The caller posts the ACS itself, so it can tamper first.
    /// </summary>
    public async Task<(CookieJar Jar, string RelayState, string SamlResponse)> DriveToAcsAsync(
        string returnUri = "/welcome")
    {
        var jar = await LoginAsync();

        var start = await SendAsync(HttpMethod.Get,
            $"/auth/saml/{SamlLoopComposition.ConnectionKey}/start?redirect_uri={Uri.EscapeDataString(returnUri)}", jar);
        if (start.StatusCode != HttpStatusCode.Redirect)
        {
            throw new InvalidOperationException($"start answered {(int)start.StatusCode}");
        }

        var sso = await SendAsync(HttpMethod.Get, start.Headers.Location!.ToString(), jar);
        var html = await sso.Content.ReadAsStringAsync();
        var samlResponse = HiddenField(html, "SAMLResponse")
            ?? throw new InvalidOperationException("no SAMLResponse form field");
        var relayState = HiddenField(html, "RelayState")
            ?? throw new InvalidOperationException("no RelayState form field");
        return (jar, relayState, samlResponse);
    }

    /// <summary>Posts the auto-submit form's payload to the ACS the way a browser would.</summary>
    public async Task<HttpResponseMessage> PostAcsAsync(string samlResponse, string? relayState, CookieJar jar)
    {
        var fields = new Dictionary<string, string> { ["SAMLResponse"] = samlResponse };
        if (relayState is not null)
        {
            fields["RelayState"] = relayState;
        }

        var request = new HttpRequestMessage(HttpMethod.Post, "/auth/saml/acs")
        {
            Content = new FormUrlEncodedContent(fields),
        };
        jar.Apply(request);
        var response = await Client.SendAsync(request);
        jar.Update(response);
        return response;
    }

    /// <summary>The reason on the last saml.login_denied event (the wire only says saml_failed).</summary>
    public string? LastDenialReason() => Events.Events
        .LastOrDefault(e => e.Kind == "saml.login_denied")?.Data?["reason"]?.ToString();

    private async Task<HttpResponseMessage> SendAsync(
        HttpMethod method, string path, CookieJar jar, object? body = null)
    {
        var request = new HttpRequestMessage(method, path);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }

        jar.Apply(request);
        var response = await Client.SendAsync(request);
        jar.Update(response);
        return response;
    }

    private static string? HiddenField(string html, string name)
    {
        var match = new Regex($"name=\"{Regex.Escape(name)}\"[^>]*value=\"([^\"]*)\"",
            RegexOptions.IgnoreCase).Match(html);
        return match.Success ? WebUtility.HtmlDecode(match.Groups[1].Value) : null;
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _host.StopAsync();
        _host.Dispose();
    }
}

/// <summary>Manual cookie jar (TestServer's HttpClient does no cookie handling).</summary>
internal sealed class CookieJar
{
    private readonly Dictionary<string, string> _cookies = new(StringComparer.Ordinal);

    public string? this[string name] => _cookies.TryGetValue(name, out var value) ? value : null;

    public IReadOnlyCollection<string> Names => _cookies.Keys;

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
