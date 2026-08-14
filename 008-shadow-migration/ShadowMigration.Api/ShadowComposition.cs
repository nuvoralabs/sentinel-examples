using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Nuvora.Nexus.Sentinel;
using Nuvora.Nexus.Sentinel.AspNetCore;
using Nuvora.Nexus.Sentinel.AspNetCore.DependencyInjection;
using Nuvora.Nexus.Sentinel.AspNetCore.Endpoints;
using Nuvora.Nexus.Sentinel.Audit;
using Nuvora.Nexus.Sentinel.Authentication;
using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.Definitions;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Nuvora.Nexus.Sentinel.Identity;
using Nuvora.Nexus.Sentinel.Importers;
using Nuvora.Nexus.Sentinel.Login;
using Nuvora.Nexus.Sentinel.Permissions;
using Nuvora.Nexus.Sentinel.Ports;
using Nuvora.Nexus.Sentinel.Stores.EfCore;
using Nuvora.Nexus.Sentinel.Stores.EfCore.DependencyInjection;
using Nuvora.Nexus.Sentinel.Stores.EfCore.Stores;
using Nuvora.Nexus.Sentinel.Tokens;

namespace ShadowMigration.Api;

/// <summary>
/// The migration story end-to-end: import an ASP.NET-Identity-shaped legacy database into
/// Sentinel's REAL EF Core stores (SQLite in-memory), run the legacy authorizer and Sentinel's
/// evaluator side by side under <see cref="ShadowAuthzRecorder"/>, and gate cutover on
/// zero divergences. Shared verbatim by Program.cs and the tests.
/// </summary>
public static class ShadowComposition
{
    public const string Issuer = "https://shadow.sample";
    public const string Audience = "tickets-api";
    public const string ImportedSupportRole = "imported:support-agent";

    public static readonly Guid RealmId = Guid.Parse("00000000-0000-0000-0000-000000000008");

    public static IServiceCollection AddShadowMigrationApi(this IServiceCollection services)
    {
        // One in-memory SQLite database for the host's lifetime — the held-open connection IS
        // the database. Swap for UseNpgsql/UseSqlServer in production.
        var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();
        services.AddSingleton(connection);

        // ------------------------------------------------------------------------------------
        // Lifetime bridging is the LIBRARY's job now: AddSentinel's singletons (snapshot
        // cache, audit, definition sync, key ring) consume their scoped ports through internal
        // scope-per-call adapters, so the EF adapter's DbContext-bound ISubjectDataSource just
        // works. The in-memory registrations below are deliberate CHOICES (ephemeral keys, no
        // EF row churn for audit/definitions in a teaching sample), not lifetime workarounds.
        // ------------------------------------------------------------------------------------
        services.AddSingleton<ISigningKeyStore, InMemorySigningKeyStore>(); // ephemeral keys, sample-only
        services.AddSingleton<IAuditStore, InMemoryAuditStore>();
        services.AddSingleton<IDefinitionCatalogStore, InMemoryDefinitionCatalogStore>();

        // The REAL persistence adapter + the import target over the same context.
        services.AddSentinelEfCoreStores(o => o.UseSqlite(connection));
        services.AddSentinelEfImportTarget();

        // Hash coexistence: current algorithm argon2id, ACCEPTED set includes the foreign
        // ones (aspnet-identity-v3, bcrypt, pbkdf2) — imported credentials verify at login and
        // are transparently rehashed to argon2id at login. Cheap parameters: teaching code.
        services.AddSingleton(new PasswordHasher(
            new Argon2idPasswordHashAlgorithm(memoryKib: 8, iterations: 1, parallelism: 1),
            [new Pbkdf2PasswordHashAlgorithm(), .. ImporterHashAlgorithms.All()]));

        services.Configure<SentinelTokenOptions>(o => o.Issuer = Issuer);
        services.AddSentinel(o =>
        {
            o.DefaultRealmId = RealmId;
            o.AllowDevelopmentDefaults = true; // sample-only ephemeral signing keys (production persists a real key)
        });
        services.AddSentinelAuthentication(o =>
        {
            o.Issuer = Issuer;
            o.Audience = Audience;
            o.DefaultRealmId = RealmId;
            o.Transport = SentinelTokenTransport.Bearer;
        });

        services.AddSingleton<MigrationState>();

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

    public static IEndpointRouteBuilder MapShadowMigrationApi(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapSentinelAuth(); // imported users log in with their LEGACY passwords

        // ------------------------------------------------------------------------------------
        // Step 1 — the import: AspNetIdentityImporter over the legacy rows, into the EF
        // import target. Idempotent by natural key: re-running updates, never duplicates. Then
        // the NEW permission model is attached to the imported role — deliberately incomplete
        // (read but not close), which is exactly the kind of mapping mistake shadow mode exists
        // to catch.
        // ------------------------------------------------------------------------------------
        endpoints.MapPost("/migration/import", async (
            IImportTarget target, SentinelDbContext db, CancellationToken ct) =>
        {
            var importer = new AspNetIdentityImporter(target);
            var report = await importer.ImportAsync(
                LegacySystem.CreateSource(), new ImportOptions { TargetRealmId = RealmId }, ct);

            await EnsureRoleGrantAsync(db, ImportedSupportRole, LegacySystem.Permissions.ReadTickets, ct);
            // NOTE: tickets:global:close is intentionally NOT mapped yet — see /migration/report.

            return Results.Ok(new
            {
                dryRun = report.DryRun,
                users = new { report.Users.Created, report.Users.Updated, report.Users.Skipped },
                credentials = new { report.Credentials.Created, report.Credentials.Updated, report.Credentials.Skipped },
                roles = new { report.Roles.Created, report.Roles.Updated, report.Roles.Skipped },
                roleAssignments = new { report.RoleAssignments.Created },
                issues = report.Issues.Select(i => new { severity = i.Severity.ToString(), i.Entity, i.Key, i.Message }),
            });
        });

        // Step 3 — the operator reviewed the divergence events and completes the mapping.
        endpoints.MapPost("/migration/grants/close-tickets", async (SentinelDbContext db, CancellationToken ct) =>
        {
            await EnsureRoleGrantAsync(db, ImportedSupportRole, LegacySystem.Permissions.CloseTickets, ct);
            return Results.Ok(new { granted = LegacySystem.Permissions.CloseTickets });
        });

        // The shadow-mode scoreboard: agreements, divergences, and whether the cutover gate is open.
        endpoints.MapGet("/migration/report", (MigrationState state) =>
        {
            var report = state.Recorder.Report();
            return Results.Ok(new
            {
                mode = state.Mode.ToString(),
                report.Agreements,
                report.Divergences,
                report.Total,
                report.ReadyForCutover,
            });
        });

        // A fresh shadow window: judge the gate on traffic AFTER the mapping fix.
        endpoints.MapPost("/migration/shadow/reset", (MigrationState state) =>
        {
            state.ResetWindow();
            return Results.Ok(new { reset = true });
        });

        // The gate itself: cutover is BLOCKED while divergences > 0 (or nothing was
        // sampled), allowed at zero — then Sentinel becomes the only decision path.
        endpoints.MapPost("/migration/cutover", (MigrationState state) =>
        {
            var report = state.Recorder.Report();
            return state.TryCutOver()
                ? Results.Ok(new { mode = MigrationMode.CutOver.ToString() })
                : Results.Conflict(new
                {
                    error = "cutover_blocked",
                    report.Agreements,
                    report.Divergences,
                    report.Total,
                    reason = report.Total == 0
                        ? "no shadow traffic sampled yet"
                        : "divergences must be zero",
                });
        });

        // ------------------------------------------------------------------------------------
        // The app's actual endpoints. During shadow mode the LEGACY decision is returned
        // (recorder.Compare passes it through unchanged) while Sentinel evaluates the
        // same check alongside; after cutover Sentinel's evaluator decides alone.
        // ------------------------------------------------------------------------------------
        endpoints.MapGet("/tickets", async (HttpContext http, CancellationToken ct) =>
            await AuthorizeAsync(http, LegacySystem.Permissions.ReadTickets, ct)
                ? Results.Ok(new { tickets = new[] { "TCK-1", "TCK-2" } })
                : Results.Problem(statusCode: StatusCodes.Status403Forbidden, title: "tickets:global:read denied."))
            .AddSampleAuth();

        endpoints.MapPost("/tickets/{id}/close", async (string id, HttpContext http, CancellationToken ct) =>
            await AuthorizeAsync(http, LegacySystem.Permissions.CloseTickets, ct)
                ? Results.Ok(new { closed = id })
                : Results.Problem(statusCode: StatusCodes.Status403Forbidden, title: "tickets:global:close denied."))
            .AddSampleAuth();

        return endpoints;
    }

    /// <summary>401 before authorization: both ticket endpoints need an authenticated principal.</summary>
    private static TBuilder AddSampleAuth<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        builder.AddEndpointFilter(async (context, next) =>
            context.HttpContext.GetSentinelPrincipal() is null
                ? Results.Unauthorized()
                : await next(context));
        return builder;
    }

    /// <summary>
    /// One decision path for both modes. The snapshot is loaded FRESH per request (not from the
    /// authentication handler's cached copy) so a grant-mapping fix is visible immediately; a
    /// production host keeps the cache and publishes a cache-bus invalidation instead.
    /// </summary>
    private static async Task<bool> AuthorizeAsync(HttpContext http, string permission, CancellationToken ct)
    {
        var principal = http.GetSentinelPrincipal()!;
        var services = http.RequestServices;
        var state = services.GetRequiredService<MigrationState>();

        var data = await services.GetRequiredService<ISubjectDataSource>()
            .LoadAsync(principal.SubjectId, principal.OrganizationId, ct);
        var snapshot = data is null ? null : SubjectSnapshotBuilder.Build(data);
        var check = new AccessCheck(PermissionId.Parse(permission));

        if (state.Mode == MigrationMode.CutOver)
        {
            return snapshot is not null && AuthorizationEvaluator.Evaluate(snapshot, in check).IsAllowed;
        }

        // Shadow mode: the legacy if-ladder still decides; Sentinel evaluates the same
        // check alongside and every disagreement is counted + emitted as authz.shadow_divergence.
        var user = await services.GetRequiredService<IUserStore>().GetAsync(principal.SubjectId, ct);
        var legacyDecision = user is not null && LegacySystem.Allows(user.Email, permission);
        return snapshot is null
            ? legacyDecision // no snapshot to compare against; legacy remains authoritative
            : state.Recorder.Compare(legacyDecision, snapshot, in check);
    }

    /// <summary>Attaches an allow grant to a role by key, idempotently (import spirit: re-runs update, never duplicate).</summary>
    private static async Task EnsureRoleGrantAsync(
        SentinelDbContext db, string roleKey, string permission, CancellationToken ct)
    {
        var role = await db.Roles.SingleAsync(r => r.RealmId == RealmId && r.Key == roleKey, ct);
        if (!await db.Grants.AnyAsync(g => g.RoleId == role.Id && g.Pattern == permission, ct))
        {
            db.Grants.Add(new GrantRecord
            {
                RealmId = RealmId,
                RoleId = role.Id,
                Pattern = permission,
                Effect = GrantEffect.Allow,
                CreatedAt = DateTimeOffset.UtcNow,
            });
            await db.SaveChangesAsync(ct);
        }
    }
}

