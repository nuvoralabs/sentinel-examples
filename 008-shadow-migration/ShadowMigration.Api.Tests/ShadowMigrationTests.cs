using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using ShadowMigration.Api;
using Xunit;

namespace ShadowMigration.Api.Tests;

/// <summary>
/// The migration walkthrough, end to end over real HTTP: import → legacy-password
/// login → shadow mode catches an incomplete grant mapping → cutover blocked →
/// mapping fixed + window reset → gate opens → Sentinel decides alone.
/// </summary>
public sealed class ShadowMigrationTests : IDisposable
{
    private readonly WebApplicationFactory<Program> _factory = new();
    private readonly HttpClient _client;

    public ShadowMigrationTests()
    {
        _client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });
    }

    [Fact]
    public async Task Import_shadow_divergence_gate_and_cutover()
    {
        // ---- Step 1: import the legacy ASP.NET Identity database. ----------------------------
        var import = await _client.PostAsync("/migration/import", content: null);
        import.StatusCode.Should().Be(HttpStatusCode.OK);
        using (var report = await ReadJson(import))
        {
            report.RootElement.GetProperty("users").GetProperty("created").GetInt32().Should().Be(2);
            report.RootElement.GetProperty("credentials").GetProperty("created").GetInt32().Should().Be(2);
        }

        // ---- Step 2: Alice logs in with her LEGACY password (hash coexistence). --------------
        var alice = await LoginAsync(LegacySystem.AliceEmail, LegacySystem.AlicePassword);

        // ---- Step 3: shadow mode. Reading agrees (both allow: the imported role was
        // mapped to tickets:global:read); closing DIVERGES — legacy allows, Sentinel has no
        // grant yet. The legacy decision stays authoritative, so the request still succeeds.
        (await GetAsync(alice, "/tickets")).StatusCode.Should().Be(HttpStatusCode.OK);
        (await PostAsync(alice, "/tickets/TCK-1/close")).StatusCode.Should().Be(HttpStatusCode.OK);

        using (var report = await ReadJson(await _client.GetAsync("/migration/report")))
        {
            report.RootElement.GetProperty("mode").GetString().Should().Be("Shadow");
            report.RootElement.GetProperty("agreements").GetInt64().Should().BeGreaterThan(0);
            report.RootElement.GetProperty("divergences").GetInt64().Should().Be(1);
            report.RootElement.GetProperty("readyForCutover").GetBoolean().Should().BeFalse();
        }

        // ---- Step 4: cutover is BLOCKED while divergences > 0. -------------------------------
        (await _client.PostAsync("/migration/cutover", null)).StatusCode.Should().Be(HttpStatusCode.Conflict);

        // ---- Step 5: fix the mapping, reset the shadow window, replay traffic. ---------------
        (await _client.PostAsync("/migration/grants/close-tickets", null)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await _client.PostAsync("/migration/shadow/reset", null)).StatusCode.Should().Be(HttpStatusCode.OK);

        (await GetAsync(alice, "/tickets")).StatusCode.Should().Be(HttpStatusCode.OK);
        (await PostAsync(alice, "/tickets/TCK-1/close")).StatusCode.Should().Be(HttpStatusCode.OK);

        using (var report = await ReadJson(await _client.GetAsync("/migration/report")))
        {
            report.RootElement.GetProperty("divergences").GetInt64().Should().Be(0);
            report.RootElement.GetProperty("readyForCutover").GetBoolean().Should().BeTrue();
        }

        // ---- Step 6: the gate opens; Sentinel's evaluator is now the only decision path. -----
        var cutover = await _client.PostAsync("/migration/cutover", null);
        cutover.StatusCode.Should().Be(HttpStatusCode.OK);

        (await GetAsync(alice, "/tickets")).StatusCode.Should().Be(HttpStatusCode.OK);
        (await PostAsync(alice, "/tickets/TCK-2/close")).StatusCode.Should().Be(HttpStatusCode.OK);

        // Bob never had the support role — denied by Sentinel alone after cutover
        // (default deny), exactly as the legacy table would have said.
        var bob = await LoginAsync(LegacySystem.BobEmail, LegacySystem.BobPassword);
        (await GetAsync(bob, "/tickets")).StatusCode.Should().Be(HttpStatusCode.Forbidden);

        // And anonymous callers are 401 before authorization even runs.
        (await _client.GetAsync("/tickets")).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Import_is_idempotent()
    {
        (await _client.PostAsync("/migration/import", null)).StatusCode.Should().Be(HttpStatusCode.OK);
        var second = await _client.PostAsync("/migration/import", null);
        second.StatusCode.Should().Be(HttpStatusCode.OK);
        using var report = await ReadJson(second);
        // Re-running updates by natural key instead of duplicating.
        report.RootElement.GetProperty("users").GetProperty("created").GetInt32().Should().Be(0);
    }

    private async Task<string> LoginAsync(string email, string password)
    {
        var response = await _client.PostAsJsonAsync("/auth/login", new { email, password });
        response.StatusCode.Should().Be(HttpStatusCode.OK, "imported users keep working credentials");
        using var json = await ReadJson(response);
        return json.RootElement.GetProperty("accessToken").GetString()!;
    }

    private Task<HttpResponseMessage> GetAsync(string bearer, string path) =>
        Send(bearer, new HttpRequestMessage(HttpMethod.Get, path));

    private Task<HttpResponseMessage> PostAsync(string bearer, string path) =>
        Send(bearer, new HttpRequestMessage(HttpMethod.Post, path));

    private Task<HttpResponseMessage> Send(string bearer, HttpRequestMessage request)
    {
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return _client.SendAsync(request);
    }

    private static async Task<JsonDocument> ReadJson(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync());

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }
}
