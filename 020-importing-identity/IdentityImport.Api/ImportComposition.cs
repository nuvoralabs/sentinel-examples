using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Nuvora.Nexus.Sentinel.AspNetCore;
using Nuvora.Nexus.Sentinel.AspNetCore.DependencyInjection;
using Nuvora.Nexus.Sentinel.AspNetCore.Endpoints;
using Nuvora.Nexus.Sentinel.Audit;
using Nuvora.Nexus.Sentinel.Authentication;
using Nuvora.Nexus.Sentinel.Definitions;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Nuvora.Nexus.Sentinel.Importers;
using Nuvora.Nexus.Sentinel.Login;
using Nuvora.Nexus.Sentinel.Stores.EfCore;
using Nuvora.Nexus.Sentinel.Stores.EfCore.DependencyInjection;
using Nuvora.Nexus.Sentinel.Tokens;

namespace IdentityImport.Api;

/// <summary>
/// Four importers over one EF import target: ASP.NET Core Identity (V3 hashes
/// verify + rehash on login), a Keycloak realm export, an Auth0 ndjson export, and Duende
/// client config (secret rotation-on-migration) — every run dry-runnable first. Shared
/// verbatim by Program.cs and the tests.
/// </summary>
public static class ImportComposition
{
    public const string Issuer = "https://identityimport.sample";
    public const string Audience = "import-api";

    public static readonly Guid RealmId = Guid.Parse("00000000-0000-0000-0000-000000000020");

    public static IServiceCollection AddIdentityImportApi(this IServiceCollection services)
    {
        services.AddRouting();

        // One in-memory SQLite database for the host's lifetime — the held-open connection IS
        // the database. Swap for UseNpgsql/UseSqlServer in production.
        var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();
        services.AddSingleton(connection);

        // In-memory choices for a teaching sample (ephemeral keys, no EF row churn for
        // audit/definitions); the identity/import data itself lands in the REAL EF stores.
        services.AddSingleton<ISigningKeyStore, InMemorySigningKeyStore>();
        services.AddSingleton<IAuditStore, InMemoryAuditStore>();
        services.AddSingleton<IDefinitionCatalogStore, InMemoryDefinitionCatalogStore>();

        // The persistence adapter + the import target over the same context.
        services.AddSentinelEfCoreStores(o => o.UseSqlite(connection));
        services.AddSentinelEfImportTarget();

        // Hash coexistence: argon2id is current, the ACCEPTED set adds the foreign algorithms
        // (aspnet-identity-v3, bcrypt) — imported credentials verify at login and are
        // transparently rehashed to argon2id. Cheap parameters: teaching code.
        services.AddSingleton(new PasswordHasher(
            new Argon2idPasswordHashAlgorithm(memoryKib: 8, iterations: 1, parallelism: 1),
            [new Pbkdf2PasswordHashAlgorithm(), .. ImporterHashAlgorithms.All()]));

        services.Configure<SentinelTokenOptions>(o => o.Issuer = Issuer);
        services.AddSentinel(o =>
        {
            o.DefaultRealmId = RealmId;
            o.AllowDevelopmentDefaults = true; // sample-only ephemeral signing keys
        });
        services.AddSentinelAuthentication(o =>
        {
            o.Issuer = Issuer;
            o.Audience = Audience;
            o.DefaultRealmId = RealmId;
            o.Transport = SentinelTokenTransport.Bearer;
        });

        return services;
    }

    /// <summary>Startup: create the schema, then the standard fail-fast init. Program.cs and tests both call this.</summary>
    public static async Task InitializeAsync(IServiceProvider services)
    {
        using (var scope = services.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<SentinelDbContext>().Database.EnsureCreatedAsync();
        }

        await SentinelHost.InitializeAsync(services);
    }

    public static IEndpointRouteBuilder MapIdentityImportApi(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapSentinelAuth(); // imported users log in with their LEGACY passwords

        // Dry run first, always: full report, zero writes — the triage list for a migration.
        endpoints.MapPost("/migration/dry-run", (IImportTarget target, PasswordHasher hasher, CancellationToken ct) =>
            RunAllAsync(target, hasher, dryRun: true, ct));

        // The real thing. Idempotent by natural key: re-running updates, never duplicates.
        endpoints.MapPost("/migration/import", (IImportTarget target, PasswordHasher hasher, CancellationToken ct) =>
            RunAllAsync(target, hasher, dryRun: false, ct));

        // SAMPLE-ONLY: which hash algorithm a user's credential carries right now — watch it
        // flip from the foreign tag to argon2id after the first successful login.
        endpoints.MapGet("/migration/credentials/{email}", async (string email, SentinelDbContext db) =>
        {
            var normalized = email.Trim().ToLowerInvariant();
            var user = await db.Users.SingleOrDefaultAsync(u => u.Email == normalized);
            if (user is null)
            {
                return Results.NotFound();
            }

            var algorithms = await db.UserCredentials
                .Where(c => c.UserId == user.Id)
                .Select(c => c.Algorithm)
                .ToListAsync();
            return Results.Ok(new { email = normalized, algorithms });
        });

        return endpoints;
    }

    private static async Task<IResult> RunAllAsync(
        IImportTarget target, PasswordHasher hasher, bool dryRun, CancellationToken ct)
    {
        var options = new ImportOptions { TargetRealmId = RealmId, DryRun = dryRun };

        // Each importer is a plain class over the shared target — construct, run, report.
        // Keycloak and Duende take the host's hasher: plaintext Keycloak client secrets are
        // re-hashed on the way in, Duende's unrecoverable sha256 secrets are ROTATED.
        var aspnet = await new AspNetIdentityImporter(target)
            .ImportAsync(LegacyExports.AspNetIdentity(), options, ct);
        var keycloak = await new KeycloakRealmImporter(target, hasher)
            .ImportAsync(LegacyExports.KeycloakRealmExport(), options, ct);
        var auth0 = await new Auth0Importer(target)
            .ImportAsync(LegacyExports.Auth0Export(), options, ct);
        var duende = await new DuendeConfigImporter(target, hasher)
            .ImportAsync(LegacyExports.DuendeClientsExport(), options, ct);

        return Results.Ok(new
        {
            dryRun,
            aspnetIdentity = ReportView.From(aspnet),
            keycloak = ReportView.From(keycloak),
            auth0 = ReportView.From(auth0),
            duende = ReportView.From(duende),
        });
    }
}

/// <summary>Wire shape for an <see cref="ImportReport"/> — one summary per source.</summary>
public sealed record ReportView(
    CountsView Users, CountsView Credentials, CountsView Roles, CountsView Groups, CountsView Clients,
    int RoleAssignments, IReadOnlyList<string> Issues, IReadOnlyDictionary<string, string> GeneratedClientSecrets)
{
    public static ReportView From(ImportReport report) => new(
        CountsView.From(report.Users),
        CountsView.From(report.Credentials),
        CountsView.From(report.Roles),
        CountsView.From(report.Groups),
        CountsView.From(report.Clients),
        report.RoleAssignments.Created,
        report.Issues.Select(i => $"{i.Severity}: {i.Entity}/{i.Key}: {i.Message}").ToArray(),
        report.GeneratedClientSecrets);
}

public sealed record CountsView(int Created, int Updated, int Skipped)
{
    public static CountsView From(ImportCounts counts) => new(counts.Created, counts.Updated, counts.Skipped);
}
