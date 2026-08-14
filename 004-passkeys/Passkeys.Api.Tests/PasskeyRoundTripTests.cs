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
using Nuvora.Nexus.Sentinel.AspNetCore.Endpoints;
using Nuvora.Nexus.Sentinel.Login;
using Passkeys.Api;
using Xunit;

namespace Passkeys.Api.Tests;

/// <summary>
/// The WebAuthn round trip over real HTTP: register with an authenticated ceremony, then
/// log in passwordless — driven by <see cref="FakeAuthenticator"/> through the genuine
/// Fido2NetLib verification path (rpIdHash, origin, challenge, signature, sign count).
/// </summary>
public class PasskeyRoundTripTests
{
    // -----------------------------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------------------------

    /// <summary>Same composition as Program.cs: services from AddPasskeysApi, same endpoint groups.</summary>
    private static async Task<IHost> CreateHostAsync()
    {
        var host = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services => services.AddPasskeysApi())
                .Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapSentinelAuth();
                        endpoints.MapSentinelProfile();
                        endpoints.MapSentinelPasskeys();
                    });
                }))
            .StartAsync();

        await PasskeyDemo.SeedAsync(host.Services);
        return host;
    }

    private static async Task<HttpResponseMessage> SendAsync(
        HttpClient client, HttpMethod method, string path, object? body = null, string? bearer = null)
    {
        var request = new HttpRequestMessage(method, path);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }

        if (bearer is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        }

        return await client.SendAsync(request);
    }

    private static async Task<JsonDocument> ReadJsonAsync(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync());

    private static async Task<string> PasswordLoginAsync(HttpClient client)
    {
        var response = await SendAsync(client, HttpMethod.Post, "/auth/login",
            new { email = PasskeyDemo.Email, password = PasskeyDemo.Password });
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        using var json = await ReadJsonAsync(response);
        return json.RootElement.GetProperty("accessToken").GetString()!;
    }

    /// <summary>Starts a ceremony and returns (ceremonyId, options element) from the response.</summary>
    private static async Task<(string CeremonyId, JsonElement Options)> BeginAsync(
        HttpClient client, string path, string? bearer = null)
    {
        var response = await SendAsync(client, HttpMethod.Post, path, body: new { }, bearer: bearer);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        using var json = await ReadJsonAsync(response);
        return (
            json.RootElement.GetProperty("ceremonyId").GetString()!,
            json.RootElement.GetProperty("options").Clone());
    }

    /// <summary>The full authenticated registration ceremony: options → attestation → verify.</summary>
    private static async Task<HttpResponseMessage> RegisterAsync(
        HttpClient client, FakeAuthenticator authenticator, string bearer, string? label = null)
    {
        var (ceremonyId, options) = await BeginAsync(client, "/auth/passkey/register/options", bearer);
        return await SendAsync(client, HttpMethod.Post, "/auth/passkey/register",
            new { ceremonyId, label, response = authenticator.CreateAttestation(options) }, bearer);
    }

    /// <summary>The usernameless passwordless login ceremony: options → assertion → tokens.</summary>
    private static async Task<HttpResponseMessage> PasskeyLoginAsync(
        HttpClient client, FakeAuthenticator authenticator)
    {
        var (ceremonyId, options) = await BeginAsync(client, "/auth/passkey/login/options");
        return await SendAsync(client, HttpMethod.Post, "/auth/passkey/login",
            new { ceremonyId, response = authenticator.CreateAssertion(options) });
    }

    // -----------------------------------------------------------------------------------------
    // Register, then log in without a password
    // -----------------------------------------------------------------------------------------

    [Fact]
    public async Task Register_then_passwordless_login_round_trip()
    {
        using var host = await CreateHostAsync();
        using var client = host.GetTestClient();
        using var authenticator = new FakeAuthenticator(PasskeyDemo.RpId, PasskeyDemo.Origin);

        // Registration is an authenticated ceremony: password first, passkey added to the account.
        var bearer = await PasswordLoginAsync(client);
        var registered = await RegisterAsync(client, authenticator, bearer, label: "Sam's security key");
        registered.StatusCode.Should().Be(HttpStatusCode.OK);
        using (var json = await ReadJsonAsync(registered))
        {
            json.RootElement.GetProperty("status").GetString().Should().Be("ok");
            json.RootElement.GetProperty("uvCapable").GetBoolean().Should().BeTrue(
                "a user-verifying passkey may act as a passwordless first factor");
            json.RootElement.GetProperty("label").GetString().Should().Be("Sam's security key");
        }

        // From here on: no password anywhere. The assertion alone mints a full session.
        authenticator.SignCount = 1;
        var login = await PasskeyLoginAsync(client, authenticator);
        login.StatusCode.Should().Be(HttpStatusCode.OK);
        string accessToken;
        using (var json = await ReadJsonAsync(login))
        {
            json.RootElement.GetProperty("status").GetString().Should().Be("ok");
            accessToken = json.RootElement.GetProperty("accessToken").GetString()!;
            json.RootElement.GetProperty("refreshToken").GetString().Should().StartWith("srt_");
        }

        // The minted token is a real access token: the profile surface accepts it.
        var me = await SendAsync(client, HttpMethod.Get, "/profile/me", bearer: accessToken);
        me.StatusCode.Should().Be(HttpStatusCode.OK);
        using (var json = await ReadJsonAsync(me))
        {
            json.RootElement.GetProperty("email").GetString().Should().Be(PasskeyDemo.Email);
        }

        // The security events tell the same story through the sink.
        host.Services.GetRequiredService<RecordingEventSink>().Snapshot()
            .Should().Contain(e => e.Kind == "passkey.registered")
            .And.Contain(e => e.Kind == "login.success");
    }

    // -----------------------------------------------------------------------------------------
    // Clone detection: sign-count regression
    // -----------------------------------------------------------------------------------------

    [Fact]
    public async Task Sign_count_regression_is_rejected_and_raises_a_security_event()
    {
        using var host = await CreateHostAsync();
        using var client = host.GetTestClient();
        using var authenticator = new FakeAuthenticator(PasskeyDemo.RpId, PasskeyDemo.Origin);
        var bearer = await PasswordLoginAsync(client);
        (await RegisterAsync(client, authenticator, bearer)).StatusCode.Should().Be(HttpStatusCode.OK);

        // A healthy login moves the stored counter to 5...
        authenticator.SignCount = 5;
        (await PasskeyLoginAsync(client, authenticator)).StatusCode.Should().Be(HttpStatusCode.OK);

        // ...so a "cloned" authenticator presenting a stale counter is caught, even though its
        // signature is cryptographically valid.
        authenticator.SignCount = 3;
        var cloned = await PasskeyLoginAsync(client, authenticator);

        cloned.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await cloned.Content.ReadAsStringAsync()).Should().Contain(
            "invalid_credentials", "the wire answer stays generic; the event carries the signal");
        host.Services.GetRequiredService<RecordingEventSink>().Snapshot()
            .Should().Contain(e => e.Kind == "passkey.signcount_regression");
    }

    // -----------------------------------------------------------------------------------------
    // Origin binding: the phishing resistance itself
    // -----------------------------------------------------------------------------------------

    [Fact]
    public async Task Attestation_from_a_foreign_origin_is_rejected()
    {
        using var host = await CreateHostAsync();
        using var client = host.GetTestClient();
        var bearer = await PasswordLoginAsync(client);

        // An authenticator on a phishing page: clientDataJSON carries the page's real origin,
        // which is not in the host's configured allowlist — Fido2 verification fails closed.
        using var phished = new FakeAuthenticator(PasskeyDemo.RpId, "https://evil.example");
        var registered = await RegisterAsync(client, phished, bearer);

        registered.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await registered.Content.ReadAsStringAsync()).Should().Contain("passkey_registration_failed");

        // Nothing was stored: the account has no passkeys.
        var list = await SendAsync(client, HttpMethod.Get, "/auth/passkey/", bearer: bearer);
        using var listJson = await ReadJsonAsync(list);
        listJson.RootElement.EnumerateArray().Should().BeEmpty();
    }

    [Fact]
    public async Task Garbage_assertions_are_401_not_500()
    {
        using var host = await CreateHostAsync();
        using var client = host.GetTestClient();

        // Structurally invalid response object against a bogus ceremony: still a clean 401
        // problem+json, never an unhandled exception (the standard error mapping).
        var garbage = await SendAsync(client, HttpMethod.Post, "/auth/passkey/login",
            new { ceremonyId = "pkc_bogus", response = new { nonsense = 42 } });

        garbage.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        garbage.Content.Headers.ContentType!.MediaType.Should().Be("application/problem+json");
        (await garbage.Content.ReadAsStringAsync()).Should().Contain("invalid_credentials");
    }
}
