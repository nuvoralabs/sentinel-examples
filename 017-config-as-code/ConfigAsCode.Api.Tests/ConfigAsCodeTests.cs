using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using ConfigAsCode.Api;
using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Nuvora.Nexus.Sentinel.DeclarativeConfig;
using Xunit;

namespace ConfigAsCode.Api.Tests;

/// <summary>
/// The config-as-code loop: boot applies the declared YAML; re-apply is a strict
/// no-op; dry-run previews without writing; drift is diffed field-by-field; prune is reported
/// and REFUSED; a typo'd section fails parsing instead of configuring nothing.
/// </summary>
public class ConfigAsCodeTests
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

        public IServiceProvider Services => _host.Services;

        public static async Task<Host> CreateAsync()
        {
            // The confidential client's secret comes from the environment — never the file.
            Environment.SetEnvironmentVariable("CLINIC_SECRET_PARTNER_PORTAL", "dev-only-portal-secret");

            var host = await new HostBuilder()
                .ConfigureWebHost(web => web
                    .UseTestServer()
                    .ConfigureServices(services =>
                    {
                        services.AddLogging();
                        services.AddConfigAsCodeApi();
                    })
                    .Configure(app =>
                    {
                        app.UseRouting();
                        app.UseEndpoints(e => e.MapConfigAsCodeApi());
                    }))
                .StartAsync();
            await ConfigAsCodeComposition.ApplyDeclaredConfigAsync(host.Services); // same boot step as Program.cs
            return new Host(host);
        }

        public async Task<ConfigDiffReport> ApplyAsync(SentinelDeclarativeConfig config, bool dryRun = false)
        {
            using var scope = Services.CreateScope();
            var applier = scope.ServiceProvider.GetRequiredService<DeclarativeConfigApplier>();
            return await applier.ApplyAsync(config, dryRun);
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await _host.StopAsync();
            _host.Dispose();
        }
    }

    private static SentinelDeclarativeConfig Declared() =>
        SentinelConfigParser.ParseYaml(ConfigAsCodeComposition.LoadDeclaredYaml());

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response) =>
        await response.Content.ReadFromJsonAsync<JsonElement>();

    [Fact]
    public async Task Boot_applies_the_declared_realm_org_roles_and_clients()
    {
        await using var host = await Host.CreateAsync();

        var state = await ReadJsonAsync(await host.Client.GetAsync("/config/state"));
        var realm = state.EnumerateArray().Single();
        realm.GetProperty("realm").GetString().Should().Be("clinic");
        realm.GetProperty("organizations").EnumerateArray()
            .Select(o => o.GetString()).Should().Contain("lakeside");
        realm.GetProperty("roles").EnumerateArray()
            .Select(r => r.GetProperty("key").GetString()).Should().Contain("support");

        var clients = realm.GetProperty("clients").EnumerateArray().ToArray();
        clients.Should().HaveCount(2);
        clients.Single(c => c.GetProperty("clientId").GetString() == "clinic-spa")
            .GetProperty("hasSecret").GetBoolean().Should().BeFalse("public clients have no secret");
        clients.Single(c => c.GetProperty("clientId").GetString() == "partner-portal")
            .GetProperty("hasSecret").GetBoolean().Should().BeTrue(
                "the secretRef resolved from the environment and was hashed at apply time");
    }

    [Fact]
    public async Task Reapplying_the_unchanged_file_is_a_strict_noop()
    {
        await using var host = await Host.CreateAsync();

        // Empty body → the endpoint re-applies the bundled file.
        var response = await host.Client.PostAsJsonAsync("/config/apply", new { });
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var report = await ReadJsonAsync(response);
        report.GetProperty("isNoOp").GetBoolean().Should().BeTrue(
            "the same file must re-apply as a strict no-op — that is what makes boot-time apply safe");
        report.GetProperty("creates").GetInt32().Should().Be(0);
    }

    [Fact]
    public async Task Dry_run_reports_the_diff_without_writing()
    {
        await using var host = await Host.CreateAsync();

        var drifted = Declared();
        drifted.Realms[0].OidcClients[0].AllowedScopes.Add("offline_access");

        var preview = await host.ApplyAsync(drifted, dryRun: true);
        preview.DryRun.Should().BeTrue();
        preview.Updates.Should().Be(1);
        preview.Entries.Should().Contain(e =>
            e.Section == "oidcClient" && e.Kind == ConfigChangeKind.Update && e.Detail!.Contains("allowedScopes"));

        // Nothing was written: the same drift still shows as an update on a real apply.
        (await host.ApplyAsync(drifted)).Updates.Should().Be(1, "the dry run must not have applied it");
    }

    [Fact]
    public async Task Drift_is_diffed_by_natural_key_and_reapplies_to_a_noop()
    {
        await using var host = await Host.CreateAsync();

        var drifted = Declared();
        drifted.Realms[0].Organizations[0].DisplayName = "Lakeside Clinic (North)";
        drifted.Realms[0].Roles[0].Grants.Add(new GrantConfig { Pattern = "sentinel:org:audit_read" });

        var report = await host.ApplyAsync(drifted);
        report.Entries.Should().Contain(e =>
            e.Section == "organization" && e.Kind == ConfigChangeKind.Update && e.Detail!.Contains("displayName"));
        report.Entries.Should().Contain(e =>
            e.Section == "role" && e.Kind == ConfigChangeKind.Update && e.Detail!.Contains("1 grant"));

        (await host.ApplyAsync(drifted)).IsNoOp.Should().BeTrue("after the drift lands, the file is the state again");
    }

    [Fact]
    public async Task Prune_is_reported_and_refused_never_deleted()
    {
        await using var host = await Host.CreateAsync();

        var pruning = Declared();
        pruning.Realms[0].OidcClients.Clear();     // the clients vanish from the file…
        pruning.Realms[0].Prune.OidcClients = true; // …and the section opts into prune reporting

        var report = await host.ApplyAsync(pruning);
        var wouldPrune = report.Entries.Where(e => e.Kind == ConfigChangeKind.WouldPrune).ToArray();
        wouldPrune.Should().HaveCount(2, "both undeclared clients are reported");
        wouldPrune.Should().OnlyContain(e => e.Detail!.Contains("refuses to auto-delete"));

        // v1 never deletes: the clients are still being served.
        var state = await ReadJsonAsync(await host.Client.GetAsync("/config/state"));
        state.EnumerateArray().Single().GetProperty("clients").GetArrayLength().Should().Be(2);
    }

    [Fact]
    public async Task A_typo_fails_parsing_instead_of_configuring_nothing()
    {
        await using var host = await Host.CreateAsync();

        var response = await host.Client.PostAsJsonAsync("/config/apply", new
        {
            yaml = """
                version: 1
                reallms:
                  - key: typo
                """,
        });

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ReadJsonAsync(response)).GetProperty("error").GetString().Should().Be("parse_error");
    }
}
