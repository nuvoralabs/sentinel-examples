using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using IdP.Api;
using Microsoft.AspNetCore.WebUtilities;
using Xunit;
using Base64Url = System.Buffers.Text.Base64Url;

namespace Sso.Tests;

/// <summary>
/// The full SSO dance over two TestHost apps: the test plays the browser between
/// Partner.Web (relying party) and IdP.Api (Sentinel authorization server) — discovery,
/// authorize → host login → code → back-channel token exchange (PKCE) → userinfo, plus
/// the PKCE and single-use-code rules and the refresh grant.
/// </summary>
public class SsoFlowTests
{
    private static Dictionary<string, string> LocationQuery(HttpResponseMessage response)
    {
        var location = response.Headers.Location!.ToString();
        return QueryHelpers.ParseQuery(location[location.IndexOf('?')..])
            .ToDictionary(kv => kv.Key, kv => kv.Value.ToString(), StringComparer.Ordinal);
    }

    /// <summary>Turns an absolute URL at a sample origin into the path+query the TestServer client expects.</summary>
    private static string AsRelative(Uri absolute) => absolute.PathAndQuery;

    private static async Task<JsonDocument> ReadJsonAsync(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync());

    // -----------------------------------------------------------------------------------------
    // Discovery
    // -----------------------------------------------------------------------------------------

    [Fact]
    public async Task Discovery_document_advertises_the_endpoints_the_partner_uses()
    {
        await using var world = await SsoTestWorld.CreateAsync();

        var response = await world.IdpClient.GetAsync("/.well-known/openid-configuration");
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        using var json = await ReadJsonAsync(response);
        var root = json.RootElement;
        root.GetProperty("issuer").GetString().Should().Be(IdpComposition.Issuer);
        root.GetProperty("authorization_endpoint").GetString().Should().Be($"{IdpComposition.Issuer}/oidc/authorize");
        root.GetProperty("token_endpoint").GetString().Should().Be($"{IdpComposition.Issuer}/oidc/token");
        root.GetProperty("userinfo_endpoint").GetString().Should().Be($"{IdpComposition.Issuer}/oidc/userinfo");
        root.GetProperty("jwks_uri").GetString().Should().Be($"{IdpComposition.Issuer}/oidc/jwks");
        root.GetProperty("code_challenge_methods_supported").EnumerateArray()
            .Select(e => e.GetString()).Should().BeEquivalentTo(["S256"]);
    }

    // -----------------------------------------------------------------------------------------
    // The full dance
    // -----------------------------------------------------------------------------------------

    [Fact]
    public async Task Full_sso_dance_signs_the_user_into_the_partner_app()
    {
        await using var world = await SsoTestWorld.CreateAsync();

        // 1) Browser hits the partner's sign-in: 302 to the IdP authorize endpoint with PKCE.
        var signin = await world.NavigateAsync(world.PartnerClient, world.PartnerJar, "/signin");
        signin.StatusCode.Should().Be(HttpStatusCode.Redirect);
        var authorizeUrl = signin.Headers.Location!;
        authorizeUrl.ToString().Should().StartWith($"{IdpComposition.Issuer}/oidc/authorize?");
        authorizeUrl.Query.Should().Contain("code_challenge=").And.Contain("code_challenge_method=S256");

        // 2) The browser follows it, unauthenticated — the AS delegates the login UI to
        //    the HOST app via /login?returnUrl={the exact authorize URL}.
        var unauthenticated = await world.NavigateAsync(world.IdpClient, world.IdpJar, AsRelative(authorizeUrl));
        unauthenticated.StatusCode.Should().Be(HttpStatusCode.Redirect);
        unauthenticated.Headers.Location!.ToString().Should().StartWith("/login?returnUrl=");
        var returnUrl = LocationQuery(unauthenticated)["returnUrl"];
        returnUrl.Should().StartWith("/oidc/authorize?");

        // ...and the host login page itself is served by the app, not by Sentinel.
        (await world.IdpClient.GetAsync(unauthenticated.Headers.Location!.ToString()))
            .Content.Headers.ContentType!.MediaType.Should().Be("text/html");

        // 3) The login page's form POSTs /auth/login — the Sentinel cookie session appears.
        await world.LoginAtIdpAsync();

        // 4) Re-entering authorize with the session mints a code and bounces to the partner.
        var authorized = await world.NavigateAsync(world.IdpClient, world.IdpJar, returnUrl);
        authorized.StatusCode.Should().Be(HttpStatusCode.Redirect);
        var callbackUrl = authorized.Headers.Location!;
        callbackUrl.ToString().Should().StartWith(IdpComposition.PartnerRedirectUri);
        LocationQuery(authorized).Should().ContainKey("code");

        // 5) The partner's callback exchanges code + PKCE verifier over the back channel,
        //    checks the ID token, calls userinfo, and establishes its own session.
        var callback = await world.NavigateAsync(world.PartnerClient, world.PartnerJar, AsRelative(callbackUrl));
        callback.StatusCode.Should().Be(HttpStatusCode.Redirect);
        callback.Headers.Location!.ToString().Should().Be("/me");

        // 6) Signed in: the partner shows the identity it learned from the IdP.
        var me = await world.NavigateAsync(world.PartnerClient, world.PartnerJar, "/me");
        me.StatusCode.Should().Be(HttpStatusCode.OK);
        using var identity = await ReadJsonAsync(me);
        identity.RootElement.GetProperty("email").GetString().Should().Be(IdpComposition.UserEmail);
        identity.RootElement.GetProperty("name").GetString().Should().Be("Ada Lovelace");
        identity.RootElement.GetProperty("hasRefreshToken").GetBoolean()
            .Should().BeTrue("offline_access was requested");
    }

    // -----------------------------------------------------------------------------------------
    // Refresh grant through the partner session
    // -----------------------------------------------------------------------------------------

    [Fact]
    public async Task Partner_refreshes_its_tokens_without_a_browser_round_trip()
    {
        await using var world = await SsoTestWorld.CreateAsync();
        await CompleteSsoAsync(world);

        // Two consecutive refreshes prove rotation works end-to-end: the second uses the
        // token the first one received.
        for (var i = 0; i < 2; i++)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "/refresh");
            world.PartnerJar.Apply(request);
            var response = await world.PartnerClient.SendAsync(request);
            response.StatusCode.Should().Be(HttpStatusCode.OK, $"refresh #{i + 1} should rotate cleanly");
        }

        (await world.NavigateAsync(world.PartnerClient, world.PartnerJar, "/me"))
            .StatusCode.Should().Be(HttpStatusCode.OK);
    }

    // -----------------------------------------------------------------------------------------
    // Protocol rules the AS enforces, driven directly as a hostile/naive client
    // -----------------------------------------------------------------------------------------

    [Fact]
    public async Task Pkce_is_required_for_the_public_client()
    {
        await using var world = await SsoTestWorld.CreateAsync();
        await world.LoginAtIdpAsync();

        // No code_challenge at all: rejected via redirect with a proper OAuth error.
        var response = await world.NavigateAsync(world.IdpClient, world.IdpJar,
            "/oidc/authorize?client_id=partner-web"
            + $"&redirect_uri={Uri.EscapeDataString(IdpComposition.PartnerRedirectUri)}"
            + "&response_type=code&scope=openid&state=st-1");

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        LocationQuery(response)["error"].Should().Be("invalid_request");
    }

    [Fact]
    public async Task Wrong_pkce_verifier_is_invalid_grant()
    {
        await using var world = await SsoTestWorld.CreateAsync();
        await world.LoginAtIdpAsync();
        var code = await MintCodeAsync(world, challengeVerifier: "correct-verifier-correct-verifier-1234567890");

        var response = await ExchangeAsync(world, code, "wrong-verifier-wrong-verifier-wrong-1234567");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        using var json = await ReadJsonAsync(response);
        json.RootElement.GetProperty("error").GetString().Should().Be("invalid_grant");
    }

    [Fact]
    public async Task Authorization_code_is_single_use()
    {
        await using var world = await SsoTestWorld.CreateAsync();
        await world.LoginAtIdpAsync();
        const string verifier = "one-shot-verifier-one-shot-verifier-123456789";
        var code = await MintCodeAsync(world, verifier);

        (await ExchangeAsync(world, code, verifier)).StatusCode.Should().Be(HttpStatusCode.OK);

        var replay = await ExchangeAsync(world, code, verifier);
        replay.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        using var json = await ReadJsonAsync(replay);
        json.RootElement.GetProperty("error").GetString().Should().Be("invalid_grant");
    }

    // -----------------------------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------------------------

    private static async Task CompleteSsoAsync(SsoTestWorld world)
    {
        var signin = await world.NavigateAsync(world.PartnerClient, world.PartnerJar, "/signin");
        var unauthenticated = await world.NavigateAsync(
            world.IdpClient, world.IdpJar, AsRelative(signin.Headers.Location!));
        await world.LoginAtIdpAsync();
        var authorized = await world.NavigateAsync(
            world.IdpClient, world.IdpJar, LocationQuery(unauthenticated)["returnUrl"]);
        var callback = await world.NavigateAsync(
            world.PartnerClient, world.PartnerJar, AsRelative(authorized.Headers.Location!));
        callback.StatusCode.Should().Be(HttpStatusCode.Redirect, "the SSO dance must complete before the test proper");
    }

    /// <summary>Drives authorize as an already-authenticated browser and returns the minted code.</summary>
    private static async Task<string> MintCodeAsync(SsoTestWorld world, string challengeVerifier)
    {
        var challenge = Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(challengeVerifier)));
        var response = await world.NavigateAsync(world.IdpClient, world.IdpJar,
            "/oidc/authorize?client_id=partner-web"
            + $"&redirect_uri={Uri.EscapeDataString(IdpComposition.PartnerRedirectUri)}"
            + "&response_type=code&scope=openid&state=st-1&nonce=n-1"
            + $"&code_challenge={Uri.EscapeDataString(challenge)}&code_challenge_method=S256");
        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        response.Headers.Location!.ToString().Should().StartWith(IdpComposition.PartnerRedirectUri);
        return LocationQuery(response)["code"];
    }

    private static Task<HttpResponseMessage> ExchangeAsync(SsoTestWorld world, string code, string verifier) =>
        world.IdpClient.PostAsync("/oidc/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = IdpComposition.PartnerClientId,
            ["code"] = code,
            ["redirect_uri"] = IdpComposition.PartnerRedirectUri,
            ["code_verifier"] = verifier,
        }));
}
