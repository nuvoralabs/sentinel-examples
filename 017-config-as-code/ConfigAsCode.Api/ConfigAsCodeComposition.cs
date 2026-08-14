using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Nuvora.Nexus.Sentinel.Admin;
using Nuvora.Nexus.Sentinel.Authentication;
using Nuvora.Nexus.Sentinel.DeclarativeConfig;
using Nuvora.Nexus.Sentinel.DeclarativeConfig.DependencyInjection;
using Nuvora.Nexus.Sentinel.Login;
using Nuvora.Nexus.Sentinel.Ports;

namespace ConfigAsCode.Api;

/// <summary>
/// Config-as-code, isolated: a host whose realm/org/roles/clients come from a YAML
/// file, applied idempotently at boot through the public store ports. This sample deliberately
/// carries no login stack — the config plane is the subject. Shared verbatim by Program.cs and
/// the tests.
/// </summary>
public static class ConfigAsCodeComposition
{
    public const string ConfigFileName = "clinic.sentinel.yaml";

    /// <summary>The bundled declarative file, exactly as deployed next to the binary.</summary>
    public static string LoadDeclaredYaml() =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, ConfigFileName));

    public static IServiceCollection AddConfigAsCodeApi(this IServiceCollection services)
    {
        services.AddRouting();

        // The applier writes through the same public store ports the admin API uses. This
        // sample opts into the in-memory ones; AddSentinelEfCoreStores registers persistent
        // equivalents for every port (that is the only change a real host makes).
        services.AddSingleton<IAdminStore>(new InMemoryAdminStore());
        services.AddSingleton<IOidcStore>(new InMemoryOidcStore());

        // The applier's own dependencies (a full Sentinel host gets these from AddSentinel).
        services.AddSingleton(new PasswordHasher(
            new Argon2idPasswordHashAlgorithm(memoryKib: 8, iterations: 1, parallelism: 1))); // cheap: teaching code
        services.AddSingleton<ISentinelClock>(SystemClock.Instance);

        // Registers DeclarativeConfigApplier + the env-var ISecretResolver default.
        services.AddSentinelDeclarativeConfig();

        return services;
    }

    /// <summary>
    /// Boot-time apply, fail-closed: booting with silently unapplied config is how drift
    /// starts, so per-entry errors abort startup. Program.cs and the tests both run this.
    /// </summary>
    public static async Task ApplyDeclaredConfigAsync(IServiceProvider services)
    {
        var declared = SentinelConfigParser.ParseYaml(LoadDeclaredYaml());

        using var scope = services.CreateScope();
        var applier = scope.ServiceProvider.GetRequiredService<DeclarativeConfigApplier>();
        var report = await applier.ApplyAsync(declared, dryRun: false);
        if (report.HasErrors)
        {
            throw new InvalidOperationException("Declarative config apply reported errors:\n  "
                + string.Join("\n  ", report.Entries.Where(e => e.Kind == ConfigChangeKind.Error)));
        }
    }

    public static IEndpointRouteBuilder MapConfigAsCodeApi(this IEndpointRouteBuilder endpoints)
    {
        // Re-apply the bundled file (or any YAML the caller posts) and return the diff report.
        // dryRun=true previews without writing.
        endpoints.MapPost("/config/apply", async (
            DeclarativeConfigApplier applier, ApplyRequest? request) =>
        {
            SentinelDeclarativeConfig declared;
            try
            {
                declared = SentinelConfigParser.ParseYaml(request?.Yaml ?? LoadDeclaredYaml());
            }
            catch (DeclarativeConfigParseException ex)
            {
                return Results.BadRequest(new { error = "parse_error", message = ex.Message });
            }

            try
            {
                var report = await applier.ApplyAsync(declared, request?.DryRun ?? false);
                return Results.Ok(ReportView.From(report));
            }
            catch (DeclarativeConfigValidationException ex)
            {
                return Results.BadRequest(new
                {
                    error = "validation_error",
                    issues = ex.Issues.Select(i => i.ToString()),
                });
            }
        });

        // What the stores actually hold — the proof for idempotency and prune refusal.
        endpoints.MapGet("/config/state", async (IAdminStore admin, IOidcStore oidc) =>
        {
            var view = new List<object>();
            foreach (var realm in await admin.ListRealmsAsync())
            {
                var roles = new List<object>();
                foreach (var role in await admin.ListRolesAsync(realm.Id, organizationId: null))
                {
                    var grants = await admin.GetRoleGrantsAsync(role.Id);
                    roles.Add(new { role.Key, grants = grants.Select(g => g.Pattern) });
                }

                view.Add(new
                {
                    realm = realm.Key,
                    organizations = (await admin.ListOrganizationsAsync(realm.Id)).Select(o => o.Key),
                    roles,
                    clients = (await oidc.ListClientsAsync(realm.Id)).Select(c => new
                    {
                        c.ClientId,
                        type = c.ClientType.ToString().ToLowerInvariant(),
                        hasSecret = c.SecretHash is not null,
                        scopes = c.AllowedScopes,
                    }),
                });
            }

            return Results.Ok(view);
        });

        return endpoints;
    }
}

public sealed record ApplyRequest(string? Yaml, bool DryRun);

/// <summary>Wire shape for a <see cref="ConfigDiffReport"/>.</summary>
public sealed record ReportView(
    bool DryRun, int Creates, int Updates, int Unchanged, bool IsNoOp, bool HasErrors,
    IReadOnlyList<ReportEntryView> Entries)
{
    public static ReportView From(ConfigDiffReport report) => new(
        report.DryRun, report.Creates, report.Updates, report.Unchanged, report.IsNoOp, report.HasErrors,
        report.Entries.Select(e => new ReportEntryView(
            e.Section, e.Key, e.Kind.ToString(), e.Detail)).ToArray());
}

public sealed record ReportEntryView(string Section, string Key, string Kind, string? Detail);
