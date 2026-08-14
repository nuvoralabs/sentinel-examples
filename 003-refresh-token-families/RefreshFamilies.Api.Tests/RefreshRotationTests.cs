using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;
using Nuvora.Nexus.Sentinel.AspNetCore.Endpoints;
using RefreshFamilies.Api;
using Xunit;

namespace RefreshFamilies.Api.Tests;

/// <summary>
/// The rotation-and-reuse walk as assertions: login → rotate → replay the consumed token → the whole family
/// (rotated token included) is dead and the token.refresh_reuse_detected event fired.
/// </summary>
public class RefreshRotationTests
{
    // -----------------------------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------------------------

    /// <summary>Same composition as Program.cs: services from AddRefreshFamiliesApi, same endpoint groups.</summary>
    private static async Task<IHost> CreateHostAsync()
    {
        var host = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services => services.AddRefreshFamiliesApi())
                .Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapSentinelAuth();
                        endpoints.MapSentinelProfile();
                        endpoints.MapSecurityEvents();
                    });
                }))
            .StartAsync();

        await DemoData.SeedAsync(host.Services);
        return host;
    }

    private static async Task<JsonDocument> ReadJsonAsync(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync());

    private static async Task<(string AccessToken, string RefreshToken)> LoginAsync(HttpClient client)
    {
        var response = await client.PostAsJsonAsync("/auth/login",
            new { email = DemoData.Email, password = DemoData.Password });
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        using var json = await ReadJsonAsync(response);
        return (
            json.RootElement.GetProperty("accessToken").GetString()!,
            json.RootElement.GetProperty("refreshToken").GetString()!);
    }

    private static Task<HttpResponseMessage> RefreshAsync(HttpClient client, string refreshToken) =>
        client.PostAsJsonAsync("/auth/refresh", new { refreshToken });

    private static async Task<string[]> RecordedEventKindsAsync(HttpClient client)
    {
        using var json = await ReadJsonAsync(await client.GetAsync("/security/events"));
        return [.. json.RootElement.EnumerateArray().Select(e => e.GetProperty("kind").GetString()!)];
    }

    // -----------------------------------------------------------------------------------------
    // Rotation
    // -----------------------------------------------------------------------------------------

    [Fact]
    public async Task Refresh_rotates_the_token_and_the_new_pair_works()
    {
        using var host = await CreateHostAsync();
        using var client = host.GetTestClient();
        var (_, refreshToken) = await LoginAsync(client);
        refreshToken.Should().StartWith("srt_", "refresh tokens are opaque, prefixed, greppable values");

        var refresh = await RefreshAsync(client, refreshToken);
        refresh.StatusCode.Should().Be(HttpStatusCode.OK);
        string newAccess, rotated;
        using (var json = await ReadJsonAsync(refresh))
        {
            newAccess = json.RootElement.GetProperty("accessToken").GetString()!;
            rotated = json.RootElement.GetProperty("refreshToken").GetString()!;
        }

        rotated.Should().NotBe(refreshToken, "every refresh rotates");

        // The rotated pair is fully live: the access token authenticates, the refresh chains on.
        var me = new HttpRequestMessage(HttpMethod.Get, "/profile/me");
        me.Headers.Authorization = new AuthenticationHeaderValue("Bearer", newAccess);
        (await client.SendAsync(me)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await RefreshAsync(client, rotated)).StatusCode.Should().Be(HttpStatusCode.OK);
    }

    // -----------------------------------------------------------------------------------------
    // Reuse detection: the heart of this sample
    // -----------------------------------------------------------------------------------------

    [Fact]
    public async Task Replaying_a_consumed_token_kills_the_whole_family_and_emits_the_event()
    {
        using var host = await CreateHostAsync();
        using var client = host.GetTestClient();
        var (_, original) = await LoginAsync(client);

        // Legitimate rotation: the original token is now consumed, `rotated` replaces it.
        string rotated;
        using (var json = await ReadJsonAsync(await RefreshAsync(client, original)))
        {
            rotated = json.RootElement.GetProperty("refreshToken").GetString()!;
        }

        // An attacker (or a buggy client) presents the ORIGINAL again. That is reuse: 401 —
        // deliberately the same 401 as any invalid token, so the presenter learns nothing.
        var reuse = await RefreshAsync(client, original);
        reuse.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await reuse.Content.ReadAsStringAsync()).Should().Contain("invalid_refresh_token");

        // The security event DID fire internally (reuse ⇒ revoke family + emit event).
        (await RecordedEventKindsAsync(client)).Should().Contain("token.refresh_reuse_detected");

        // And the rotated token — held by the legitimate client — is dead too: revoking the
        // whole family is the point; forcing one re-login on the victim is the accepted cost
        // of cutting off the thief.
        (await RefreshAsync(client, rotated)).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Garbage_tokens_are_401_without_any_reuse_event()
    {
        using var host = await CreateHostAsync();
        using var client = host.GetTestClient();
        await LoginAsync(client);

        var garbage = await RefreshAsync(client, "srt_definitely-not-a-real-token");

        // Unknown / expired / family-revoked all answer the identical 401 — but only a
        // genuine replay of a CONSUMED token counts as reuse and raises the alarm.
        garbage.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await garbage.Content.ReadAsStringAsync()).Should().Contain("invalid_refresh_token");
        (await RecordedEventKindsAsync(client)).Should().NotContain("token.refresh_reuse_detected");
    }
}
