using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using MachineKeys.Api;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Xunit;

namespace MachineKeys.Api.Tests;

/// <summary>
/// Owner-capped keys over real HTTP: minting returns the snt_ token exactly once;
/// the key's reach is owner ∩ scopes with denies preserved; demoting the owner shrinks the key
/// on its next use; revocation and expiry fail closed with the same opaque 401.
/// </summary>
public class MachineKeysTests
{
    private sealed class Host : IAsyncDisposable
    {
        private readonly IHost _host;

        private Host(IHost host)
        {
            _host = host;
            Client = host.GetTestClient();
        }

        public HttpClient Client { get; }

        public static async Task<Host> CreateAsync()
        {
            var host = await new HostBuilder()
                .ConfigureWebHost(web => web
                    .UseTestServer()
                    .ConfigureServices(services =>
                    {
                        services.AddLogging();
                        services.AddMachineKeysApi();
                    })
                    .Configure(app =>
                    {
                        app.UseRouting();
                        app.UseAuthentication();
                        app.UseEndpoints(e => e.MapMachineKeysApi());
                    }))
                .StartAsync();
            await SentinelHost.InitializeAsync(host.Services); // same startup step as Program.cs
            return new Host(host);
        }

        public async Task<string> LoginAsync()
        {
            var response = await Client.PostAsJsonAsync("/auth/login", new
            {
                email = MachineKeysComposition.MayaEmail,
                password = MachineKeysComposition.DemoPassword,
            });
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            var body = await response.Content.ReadFromJsonAsync<JsonElement>();
            return body.GetProperty("accessToken").GetString()!;
        }

        public async Task<JsonElement> CreateKeyAsync(string userToken, object request)
        {
            var response = await Client.SendAsync(Authed(HttpMethod.Post, "/keys", userToken, request));
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            return await response.Content.ReadFromJsonAsync<JsonElement>();
        }

        public Task<HttpResponseMessage> WithKeyAsync(string keyToken, string path, HttpMethod? method = null) =>
            Client.SendAsync(Authed(method ?? HttpMethod.Get, path, keyToken));

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await _host.StopAsync();
            _host.Dispose();
        }
    }

    private static HttpRequestMessage Authed(HttpMethod method, string url, string token, object? body = null)
    {
        var request = new HttpRequestMessage(method, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }

        return request;
    }

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response) =>
        await response.Content.ReadFromJsonAsync<JsonElement>();

    [Fact]
    public async Task Minting_returns_the_snt_token_once_and_the_key_authenticates_as_ApiKey()
    {
        await using var host = await Host.CreateAsync();
        var maya = await host.LoginAsync();

        var created = await host.CreateKeyAsync(maya, new { scopes = new[] { "reports:org:*" } });
        var token = created.GetProperty("token").GetString()!;
        token.Should().StartWith("snt_").And.HaveLength(4 + 43, "snt_ + 43 base64url chars = 256 bits");
        created.GetProperty("prefix").GetString().Should().Be(token[..12], "snt_ + 8 chars: recognizable, useless");

        // The listing never shows tokens — only prefixes and metadata.
        var listed = await ReadJsonAsync(await host.Client.SendAsync(Authed(HttpMethod.Get, "/keys", maya)));
        listed.EnumerateArray().Should().ContainSingle()
            .Which.TryGetProperty("token", out _).Should().BeFalse();

        // The attribution split: SubjectId is the CREDENTIAL, OwnerUserId the human behind it.
        var whoami = await ReadJsonAsync(await host.WithKeyAsync(token, "/whoami"));
        whoami.GetProperty("kind").GetString().Should().Be("ApiKey");
        whoami.GetProperty("subjectId").GetGuid().Should().Be(created.GetProperty("id").GetGuid());
        whoami.GetProperty("ownerUserId").GetGuid().Should().Be(MachineKeysComposition.MayaId);
    }

    [Fact]
    public async Task Effective_permissions_are_owner_intersected_with_scopes_denies_preserved()
    {
        await using var host = await Host.CreateAsync();
        var maya = await host.LoginAsync();
        var created = await host.CreateKeyAsync(maya, new { scopes = new[] { "reports:org:*" } });
        var key = created.GetProperty("token").GetString()!;

        // Owner allows it AND the scope covers it → 200.
        (await host.WithKeyAsync(key, "/reports")).StatusCode.Should().Be(HttpStatusCode.OK);

        // The owner allows billing — but no scope covers it → capped away.
        (await host.WithKeyAsync(key, "/billing")).StatusCode.Should().Be(HttpStatusCode.Forbidden);

        // The scope covers purge — but the owner's DENY is preserved unconditionally.
        (await host.WithKeyAsync(key, "/reports/purge", HttpMethod.Post)).StatusCode
            .Should().Be(HttpStatusCode.Forbidden, "a key can never escape its owner's denies");

        // What /profile/permissions discloses IS the capped set.
        var permissions = await ReadJsonAsync(await host.WithKeyAsync(key, "/profile/permissions"));
        var patterns = permissions.GetProperty("patterns").EnumerateArray()
            .Select(p => p.GetProperty("pattern").GetString())
            .ToArray();
        patterns.Should().Contain("reports:org:*").And.NotContain("billing:org:*");
    }

    [Fact]
    public async Task Scopes_never_add_authority_beyond_the_owner()
    {
        await using var host = await Host.CreateAsync();
        var maya = await host.LoginAsync();

        // The scope is much broader than the owner — the key still gets only her slice.
        var created = await host.CreateKeyAsync(maya, new { scopes = new[] { "*:*:*" } });
        var key = created.GetProperty("token").GetString()!;

        (await host.WithKeyAsync(key, "/reports")).StatusCode.Should().Be(HttpStatusCode.OK);
        (await host.WithKeyAsync(key, "/admin")).StatusCode
            .Should().Be(HttpStatusCode.Forbidden, "the owner never held admin:global:manage");
    }

    [Fact]
    public async Task Demoting_the_owner_shrinks_every_existing_key_on_its_next_use()
    {
        await using var host = await Host.CreateAsync();
        var maya = await host.LoginAsync();
        var created = await host.CreateKeyAsync(maya, new { scopes = new[] { "reports:org:*" } });
        var key = created.GetProperty("token").GetString()!;

        (await host.WithKeyAsync(key, "/reports/export")).StatusCode
            .Should().Be(HttpStatusCode.OK, "before the demotion the wildcard covers export");

        // Demote Maya to read-only. Nothing on the key row changes.
        (await host.Client.PostAsync("/demo/demote-owner", null)).StatusCode.Should().Be(HttpStatusCode.OK);

        (await host.WithKeyAsync(key, "/reports/export")).StatusCode
            .Should().Be(HttpStatusCode.Forbidden, "the snapshot is recomputed at every use");
        (await host.WithKeyAsync(key, "/reports")).StatusCode
            .Should().Be(HttpStatusCode.OK, "what the owner kept, the key keeps");
    }

    [Fact]
    public async Task Revoked_and_expired_keys_fail_with_the_same_opaque_401()
    {
        await using var host = await Host.CreateAsync();
        var maya = await host.LoginAsync();

        var revocable = await host.CreateKeyAsync(maya, new { scopes = new[] { "reports:org:*" } });
        var revoke = await host.Client.SendAsync(Authed(
            HttpMethod.Post, $"/keys/{revocable.GetProperty("id").GetGuid()}/revoke", maya));
        revoke.StatusCode.Should().Be(HttpStatusCode.NoContent);
        (await host.WithKeyAsync(revocable.GetProperty("token").GetString()!, "/reports")).StatusCode
            .Should().Be(HttpStatusCode.Unauthorized);

        var expired = await host.CreateKeyAsync(
            maya, new { scopes = new[] { "reports:org:*" }, expiresInMinutes = -1 });
        (await host.WithKeyAsync(expired.GetProperty("token").GetString()!, "/reports")).StatusCode
            .Should().Be(HttpStatusCode.Unauthorized);

        (await host.WithKeyAsync("snt_definitely-not-a-real-token", "/reports")).StatusCode
            .Should().Be(HttpStatusCode.Unauthorized, "unknown, revoked and expired are indistinguishable");
    }

    [Fact]
    public async Task Invalid_scopes_are_rejected_at_creation()
    {
        await using var host = await Host.CreateAsync();
        var maya = await host.LoginAsync();

        var response = await host.Client.SendAsync(Authed(
            HttpMethod.Post, "/keys", maya, new { scopes = new[] { "not a pattern" } }));
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest, "scopes are validated when the key is minted");

        var empty = await host.Client.SendAsync(Authed(
            HttpMethod.Post, "/keys", maya, new { scopes = Array.Empty<string>() }));
        empty.StatusCode.Should().Be(HttpStatusCode.BadRequest, "a scope-less key could never allow anything");
    }
}
