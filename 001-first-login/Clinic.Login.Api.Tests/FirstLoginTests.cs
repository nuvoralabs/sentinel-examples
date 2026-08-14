using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Clinic.Login.Api;
using FluentAssertions;
using Microsoft.AspNetCore.TestHost;
using Nuvora.Nexus.Sentinel.Authentication;
using Xunit;

namespace Clinic.Login.Api.Tests;

/// <summary>
/// The article-001 walk, as executable assertions: password → mfa_required → TOTP verify →
/// cookie session → protected endpoint.
/// </summary>
public class FirstLoginTests
{
    // -----------------------------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------------------------

    private static async Task<HttpResponseMessage> SendAsync(
        HttpClient client, HttpMethod method, string path, object? body = null,
        CookieJar? jar = null, (string Name, string Value)? header = null)
    {
        var request = new HttpRequestMessage(method, path);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }

        jar?.Apply(request);
        if (header is { } h)
        {
            request.Headers.Add(h.Name, h.Value);
        }

        var response = await client.SendAsync(request);
        jar?.Update(response);
        return response;
    }

    private static async Task<JsonDocument> ReadJsonAsync(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync());

    /// <summary>Runs the full two-factor login and returns the populated cookie jar.</summary>
    private static async Task<CookieJar> LoginFullyAsync(HttpClient client)
    {
        var jar = new CookieJar();

        var login = await SendAsync(client, HttpMethod.Post, "/auth/login",
            new { email = ClinicDemo.Email, password = ClinicDemo.Password }, jar);
        login.StatusCode.Should().Be(HttpStatusCode.OK);
        string pending;
        using (var json = await ReadJsonAsync(login))
        {
            json.RootElement.GetProperty("status").GetString().Should().Be("mfa_required");
            pending = json.RootElement.GetProperty("mfaPendingToken").GetString()!;
        }

        var verify = await SendAsync(client, HttpMethod.Post, "/auth/mfa/verify",
            new
            {
                mfaPendingToken = pending,
                code = Totp.ComputeCode(ClinicDemo.TotpSecret, DateTimeOffset.UtcNow),
                kind = "totp",
            }, jar);
        verify.StatusCode.Should().Be(HttpStatusCode.OK);
        return jar;
    }

    // -----------------------------------------------------------------------------------------
    // The happy path (MFA step-up + cookie transport)
    // -----------------------------------------------------------------------------------------

    [Fact]
    public async Task Password_then_totp_establishes_a_cookie_session_and_opens_the_dashboard()
    {
        using var host = await ClinicTestHost.CreateAsync();
        using var client = host.GetTestClient();
        var jar = new CookieJar();

        // First factor: correct password answers mfa_required — and hands out NO tokens.
        var login = await SendAsync(client, HttpMethod.Post, "/auth/login",
            new { email = ClinicDemo.Email, password = ClinicDemo.Password }, jar);
        login.StatusCode.Should().Be(HttpStatusCode.OK);
        string pending;
        using (var json = await ReadJsonAsync(login))
        {
            json.RootElement.GetProperty("status").GetString().Should().Be("mfa_required");
            json.RootElement.TryGetProperty("accessToken", out _)
                .Should().BeFalse("no tokens before the second factor");
            pending = json.RootElement.GetProperty("mfaPendingToken").GetString()!;
        }

        jar.Names.Should().BeEmpty("no session cookies before the second factor");

        // Second factor: the current TOTP code completes the login; the session arrives as
        // httpOnly cookies and the body stays token-free (cookie transport).
        var verify = await SendAsync(client, HttpMethod.Post, "/auth/mfa/verify",
            new
            {
                mfaPendingToken = pending,
                code = Totp.ComputeCode(ClinicDemo.TotpSecret, DateTimeOffset.UtcNow),
                kind = "totp",
            }, jar);
        verify.StatusCode.Should().Be(HttpStatusCode.OK);
        using (var json = await ReadJsonAsync(verify))
        {
            json.RootElement.GetProperty("status").GetString().Should().Be("ok");
            json.RootElement.TryGetProperty("accessToken", out _)
                .Should().BeFalse("cookie transport never exposes tokens to script");
        }

        jar.Names.Should().Contain(["sentinel_at", "sentinel_rt", "sentinel_csrf"]);

        // The cookie session opens the protected app endpoint...
        var dashboard = await SendAsync(client, HttpMethod.Get, "/clinic/dashboard", jar: jar);
        dashboard.StatusCode.Should().Be(HttpStatusCode.OK);
        using (var json = await ReadJsonAsync(dashboard))
        {
            json.RootElement.GetProperty("appointments").GetArrayLength().Should().Be(3);
            json.RootElement.GetProperty("organizationId").GetGuid().Should().Be(ClinicDemo.Org);
        }

        // ...and without cookies the same endpoint stays closed.
        (await SendAsync(client, HttpMethod.Get, "/clinic/dashboard"))
            .StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    // -----------------------------------------------------------------------------------------
    // Failure paths
    // -----------------------------------------------------------------------------------------

    [Fact]
    public async Task Wrong_password_is_401_and_indistinguishable_from_unknown_user()
    {
        using var host = await ClinicTestHost.CreateAsync();
        using var client = host.GetTestClient();

        var wrongPassword = await SendAsync(client, HttpMethod.Post, "/auth/login",
            new { email = ClinicDemo.Email, password = "not-the-password" });
        var unknownUser = await SendAsync(client, HttpMethod.Post, "/auth/login",
            new { email = "ghost@clinic.example", password = "not-the-password" });

        wrongPassword.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        wrongPassword.Content.Headers.ContentType!.MediaType.Should().Be("application/problem+json");

        // Anti-enumeration: both failures answer with byte-identical bodies.
        var bodyA = await wrongPassword.Content.ReadAsStringAsync();
        var bodyB = await unknownUser.Content.ReadAsStringAsync();
        bodyA.Should().Be(bodyB).And.Contain("invalid_credentials");
    }

    [Fact]
    public async Task Wrong_totp_code_does_not_complete_the_login()
    {
        using var host = await ClinicTestHost.CreateAsync();
        using var client = host.GetTestClient();

        var login = await SendAsync(client, HttpMethod.Post, "/auth/login",
            new { email = ClinicDemo.Email, password = ClinicDemo.Password });
        string pending;
        using (var json = await ReadJsonAsync(login))
        {
            pending = json.RootElement.GetProperty("mfaPendingToken").GetString()!;
        }

        var verify = await SendAsync(client, HttpMethod.Post, "/auth/mfa/verify",
            new { mfaPendingToken = pending, code = "000000", kind = "totp" });

        verify.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await verify.Content.ReadAsStringAsync()).Should().Contain("invalid_credentials");
    }

    // -----------------------------------------------------------------------------------------
    // CSRF double-submit
    // -----------------------------------------------------------------------------------------

    [Fact]
    public async Task State_changing_requests_require_the_csrf_double_submit_header()
    {
        using var host = await ClinicTestHost.CreateAsync();
        using var client = host.GetTestClient();
        var jar = await LoginFullyAsync(client);

        // Cookies alone must NOT authenticate an unsafe method — that is exactly the request a
        // cross-site attacker can forge.
        var noHeader = await SendAsync(client, HttpMethod.Post, "/auth/logout", jar: jar);
        noHeader.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        var wrongHeader = await SendAsync(client, HttpMethod.Post, "/auth/logout", jar: jar,
            header: ("X-Sentinel-Csrf", "not-the-cookie-value"));
        wrongHeader.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        // Same-origin script can read the (non-httpOnly) CSRF cookie and echo it — the double
        // submit. With it, the logout goes through and clears the session cookies.
        var withHeader = await SendAsync(client, HttpMethod.Post, "/auth/logout", jar: jar,
            header: ("X-Sentinel-Csrf", jar["sentinel_csrf"]!));
        withHeader.StatusCode.Should().Be(HttpStatusCode.NoContent);
        jar.Names.Should().NotContain("sentinel_at").And.NotContain("sentinel_rt");
    }
}
