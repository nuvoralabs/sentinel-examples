using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using IdentityImport.Api;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Nuvora.Nexus.Sentinel.Authentication;
using Nuvora.Nexus.Sentinel.Stores.EfCore;
using Xunit;

namespace IdentityImport.Api.Tests;

/// <summary>
/// The migration pipeline over real HTTP: dry run writes nothing; the real run lands
/// users/roles/groups/clients from all four sources; foreign hashes verify at login and rehash
/// to argon2id; Duende's sha256 secrets rotate with the plaintext surfaced once; re-import is
/// idempotent.
/// </summary>
public class IdentityImportTests
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
            var host = await new HostBuilder()
                .ConfigureWebHost(web => web
                    .UseTestServer()
                    .ConfigureServices(services =>
                    {
                        services.AddLogging();
                        services.AddIdentityImportApi();
                    })
                    .Configure(app =>
                    {
                        app.UseRouting();
                        app.UseAuthentication();
                        app.UseEndpoints(e => e.MapIdentityImportApi());
                    }))
                .StartAsync();
            await ImportComposition.InitializeAsync(host.Services); // same startup step as Program.cs
            return new Host(host);
        }

        public async Task<JsonElement> RunAsync(string path)
        {
            var response = await Client.PostAsync(path, content: null);
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            return await response.Content.ReadFromJsonAsync<JsonElement>();
        }

        public Task<HttpResponseMessage> LoginAsync(string email, string password) =>
            Client.PostAsJsonAsync("/auth/login", new { email, password });

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await _host.StopAsync();
            _host.Dispose();
        }
    }

    private static int Created(JsonElement report, string source, string entity) =>
        report.GetProperty(source).GetProperty(entity).GetProperty("created").GetInt32();

    [Fact]
    public async Task Dry_run_reports_everything_and_writes_nothing()
    {
        await using var host = await Host.CreateAsync();

        var report = await host.RunAsync("/migration/dry-run");
        report.GetProperty("dryRun").GetBoolean().Should().BeTrue();
        Created(report, "aspnetIdentity", "users").Should().Be(1);
        Created(report, "keycloak", "users").Should().Be(1);
        Created(report, "auth0", "users").Should().Be(2);
        Created(report, "duende", "clients").Should().Be(2);

        // Zero writes: the database is still empty.
        using var scope = host.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();
        (await db.Users.AnyAsync()).Should().BeFalse("a dry run is a report, not an import");
        (await db.OidcClients.AnyAsync()).Should().BeFalse();
    }

    [Fact]
    public async Task Import_lands_users_roles_groups_and_clients_from_all_four_sources()
    {
        await using var host = await Host.CreateAsync();

        var report = await host.RunAsync("/migration/import");
        report.GetProperty("dryRun").GetBoolean().Should().BeFalse();

        using var scope = host.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();

        (await db.Users.CountAsync()).Should().Be(4, "alice + kara + carol + dan");

        // Imported roles are prefixed so they can't collide with a declared catalog.
        (await db.Roles.Select(r => r.Key).ToListAsync())
            .Should().Contain(["imported:support-agent", "imported:admin"]);
        (await db.Groups.Select(g => g.Key).ToListAsync()).Should().Contain("engineering");

        // Clients from Keycloak AND Duende land in the same OIDC table.
        (await db.OidcClients.Select(c => c.ClientId).ToListAsync())
            .Should().Contain(["legacy-spa", "legacy-mvc", "legacy-public-spa"]);

        // Auth0's blocked flag became a Sentinel suspension.
        var dan = await db.Users.SingleAsync(u => u.Email == LegacyExports.DanEmail);
        dan.Status.ToString().Should().Be("Suspended");
    }

    [Fact]
    public async Task Identity_v3_hash_verifies_at_login_and_rehashes_to_argon2id()
    {
        await using var host = await Host.CreateAsync();
        await host.RunAsync("/migration/import");

        // Before the first login the credential still carries the foreign algorithm tag.
        var before = await (await host.Client.GetAsync(
            $"/migration/credentials/{LegacyExports.AliceEmail}")).Content.ReadFromJsonAsync<JsonElement>();
        before.GetProperty("algorithms").EnumerateArray().Select(a => a.GetString())
            .Should().ContainSingle().Which.Should().Be("aspnet-identity-v3");

        // Alice logs in with the password she has always used.
        var login = await host.LoginAsync(LegacyExports.AliceEmail, LegacyExports.AlicePassword);
        login.StatusCode.Should().Be(HttpStatusCode.OK, "imported users keep their working credentials");

        // The successful login transparently upgraded the stored hash.
        var after = await (await host.Client.GetAsync(
            $"/migration/credentials/{LegacyExports.AliceEmail}")).Content.ReadFromJsonAsync<JsonElement>();
        after.GetProperty("algorithms").EnumerateArray().Select(a => a.GetString())
            .Should().ContainSingle().Which.Should().Be("argon2id");

        // The wrong password still loses, before and after the upgrade.
        (await host.LoginAsync(LegacyExports.AliceEmail, "wrong-password"))
            .StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Keycloak_pbkdf2_and_auth0_bcrypt_credentials_both_log_in()
    {
        await using var host = await Host.CreateAsync();
        await host.RunAsync("/migration/import");

        (await host.LoginAsync(LegacyExports.KaraEmail, LegacyExports.KaraPassword))
            .StatusCode.Should().Be(HttpStatusCode.OK, "Keycloak pbkdf2-sha256 re-encodes to PHC and verifies");
        (await host.LoginAsync(LegacyExports.CarolEmail, LegacyExports.CarolPassword))
            .StatusCode.Should().Be(HttpStatusCode.OK, "Auth0 bcrypt travels verbatim and verifies");

        // Dan was blocked in Auth0 → imported Suspended → cannot log in (and has no password anyway).
        (await host.LoginAsync(LegacyExports.DanEmail, "anything"))
            .StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Duende_sha256_secrets_trigger_rotation_on_migration()
    {
        await using var host = await Host.CreateAsync();
        var report = await host.RunAsync("/migration/import");

        // The fresh secret is surfaced ONCE in the report — and only for the confidential client.
        var generated = report.GetProperty("duende").GetProperty("generatedClientSecrets");
        generated.TryGetProperty("legacy-mvc", out var secret).Should().BeTrue();
        generated.TryGetProperty("legacy-public-spa", out _).Should().BeFalse("public clients have no secret");

        using var scope = host.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();
        var hasher = scope.ServiceProvider.GetRequiredService<PasswordHasher>();
        var mvc = await db.OidcClients.SingleAsync(c => c.ClientId == "legacy-mvc");

        // The generated secret verifies against the stored hash; the OLD secret is dead.
        hasher.VerifyAndUpgrade(secret.GetString()!, mvc.SecretAlgorithm!, mvc.SecretHash!, out _)
            .Should().BeTrue();
        hasher.VerifyAndUpgrade("old-mvc-secret", mvc.SecretAlgorithm!, mvc.SecretHash!, out _)
            .Should().BeFalse("sha256(secret) cannot be migrated — rotation is mandatory");
    }

    [Fact]
    public async Task Reimport_is_idempotent_updating_instead_of_duplicating()
    {
        await using var host = await Host.CreateAsync();
        await host.RunAsync("/migration/import");
        var second = await host.RunAsync("/migration/import");

        Created(second, "aspnetIdentity", "users").Should().Be(0);
        second.GetProperty("aspnetIdentity").GetProperty("users").GetProperty("updated").GetInt32()
            .Should().Be(1, "matched by email, updated in place");

        using var scope = host.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();
        (await db.Users.CountAsync(u => u.Email == LegacyExports.AliceEmail))
            .Should().Be(1, "re-import never duplicates");
    }
}
