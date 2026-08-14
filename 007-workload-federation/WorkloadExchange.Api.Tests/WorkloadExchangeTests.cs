using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using WorkloadExchange.Api;
using Xunit;

namespace WorkloadExchange.Api.Tests;

/// <summary>
/// The secretless-CI loop over real HTTP: a fake CI OIDC token goes into the exchange
/// endpoint, an RFC 8693-shaped response with a working Sentinel access token comes out, and the
/// protected API accepts it. Wrong audience / issuer / subject / claim are all rejected.
/// </summary>
public class WorkloadExchangeTests
{
    private const string ExchangePath = "/oidc/workload/token";
    private const string TokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange";

    private sealed class Host : IAsyncDisposable
    {
        private readonly IHost _host;

        private Host(IHost host)
        {
            _host = host;
            Client = host.GetTestClient();
            Idp = host.Services.GetRequiredService<FakeCiIdp>();
        }

        public HttpClient Client { get; }

        public FakeCiIdp Idp { get; }

        public static async Task<Host> CreateAsync()
        {
            var host = await new HostBuilder()
                .ConfigureWebHost(web => web
                    .UseTestServer()
                    .ConfigureServices(services =>
                    {
                        services.AddLogging();
                        services.AddRouting();
                        services.AddWorkloadExchangeApi();
                    })
                    .Configure(app =>
                    {
                        app.UseRouting();
                        app.UseAuthentication();
                        app.UseEndpoints(e => e.MapWorkloadExchangeApi());
                    }))
                .StartAsync();
            await SentinelHost.InitializeAsync(host.Services); // same startup step as Program.cs
            return new Host(host);
        }

        public Task<HttpResponseMessage> ExchangeAsync(string subjectToken) =>
            Client.PostAsync(ExchangePath, new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = TokenExchangeGrant,
                ["subject_token"] = subjectToken,
                ["subject_token_type"] = "urn:ietf:params:oauth:token-type:jwt",
            }));

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await _host.StopAsync();
            _host.Dispose();
        }
    }

    private static async Task<JsonDocument> ReadJsonAsync(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync());

    private static async Task AssertInvalidGrantAsync(HttpResponseMessage response)
    {
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        using var json = await ReadJsonAsync(response);
        json.RootElement.GetProperty("error").GetString().Should().Be("invalid_grant");
    }

    [Fact]
    public async Task Ci_token_exchanges_for_a_sentinel_token_that_reaches_the_protected_api()
    {
        await using var host = await Host.CreateAsync();

        // 1) The "CI job" presents its platform-minted OIDC token at the exchange endpoint.
        var exchange = await host.ExchangeAsync(host.Idp.IssueToken());
        exchange.StatusCode.Should().Be(HttpStatusCode.OK);
        exchange.Headers.CacheControl!.NoStore.Should().BeTrue("token responses are no-store (RFC 6749 §5.1)");

        string accessToken;
        using (var json = await ReadJsonAsync(exchange))
        {
            accessToken = json.RootElement.GetProperty("access_token").GetString()!;
            json.RootElement.GetProperty("issued_token_type").GetString()
                .Should().Be("urn:ietf:params:oauth:token-type:access_token");
            json.RootElement.GetProperty("token_type").GetString().Should().Be("Bearer");
            json.RootElement.TryGetProperty("refresh_token", out _).Should().BeFalse(
                "a refresh token would be a long-lived secret in CI — workloads re-exchange instead");
        }

        // 2) The exchanged token passes the REAL Sentinel authentication handler, acting as the
        //    trust's service account (a machine identity).
        var request = new HttpRequestMessage(HttpMethod.Post, "/deployments");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var response = await host.Client.SendAsync(request);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        using var deployment = await ReadJsonAsync(response);
        deployment.RootElement.GetProperty("subjectId").GetGuid()
            .Should().Be(WorkloadComposition.ServiceAccountId, "the exchanged token acts AS the service account");
    }

    [Fact]
    public async Task Wrong_external_audience_is_rejected()
    {
        await using var host = await Host.CreateAsync();

        // The token was minted FOR someone else — the trust's audience check fails.
        var response = await host.ExchangeAsync(host.Idp.IssueToken(aud: "someone-else"));

        await AssertInvalidGrantAsync(response);
    }

    [Fact]
    public async Task Unknown_issuer_is_rejected()
    {
        await using var host = await Host.CreateAsync();

        // Same key, different iss: no trust is configured for that issuer, so the exchange is
        // refused before any signature politics — trusts are looked up by exact iss.
        var response = await host.ExchangeAsync(host.Idp.IssueToken(issuer: "https://evil-idp.sample"));

        await AssertInvalidGrantAsync(response);
    }

    [Fact]
    public async Task Subject_outside_the_trust_pattern_is_rejected()
    {
        await using var host = await Host.CreateAsync();

        // repo:evil/* does not match the trust's repo:nuvoralabs/* subject pattern.
        var response = await host.ExchangeAsync(host.Idp.IssueToken(
            sub: "repo:evil/nexus:ref:refs/heads/master", repository: "evil/nexus"));

        await AssertInvalidGrantAsync(response);
    }

    [Fact]
    public async Task Claim_rule_mismatch_is_rejected()
    {
        await using var host = await Host.CreateAsync();

        // Right repo, wrong branch: the ref=refs/heads/master claim rule fails.
        var response = await host.ExchangeAsync(host.Idp.IssueToken(
            sub: "repo:nuvoralabs/nexus:ref:refs/heads/feature", gitRef: "refs/heads/feature"));

        await AssertInvalidGrantAsync(response);
    }

    [Fact]
    public async Task Missing_subject_token_is_invalid_request_and_plain_requests_stay_401()
    {
        await using var host = await Host.CreateAsync();

        var missing = await host.Client.PostAsync(ExchangePath, new FormUrlEncodedContent(
            new Dictionary<string, string> { ["grant_type"] = TokenExchangeGrant }));
        missing.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        using (var json = await ReadJsonAsync(missing))
        {
            json.RootElement.GetProperty("error").GetString().Should().Be("invalid_request");
        }

        // And the protected API without any token is an ordinary 401.
        (await host.Client.PostAsync("/deployments", content: null))
            .StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }
}
