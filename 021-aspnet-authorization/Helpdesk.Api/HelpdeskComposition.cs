using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Nuvora.Nexus.Sentinel.AspNetCore.DependencyInjection;
using Nuvora.Nexus.Sentinel.Authentication;
using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.Authorization.AspNetCore;
using Nuvora.Nexus.Sentinel.Authorization.AspNetCore.DependencyInjection;
using Nuvora.Nexus.Sentinel.Definitions;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Nuvora.Nexus.Sentinel.Identity;
using Nuvora.Nexus.Sentinel.Login;
using Nuvora.Nexus.Sentinel.Ports;
using Nuvora.Nexus.Sentinel.Tokens;

namespace Helpdesk.Api;

/// <summary>
/// The whole wiring for a helpdesk that authorizes with Sentinel through ASP.NET's own
/// authorization: the usual Sentinel services, plus one call that puts the engine behind
/// <c>[Authorize]</c> and <c>[SentinelPermission]</c>.
/// </summary>
public static class HelpdeskComposition
{
    public static readonly Guid Realm = Guid.Parse("00000000-0000-0000-0000-0000000000a1");
    public static readonly Guid NorthOrg = Guid.Parse("11111111-1111-1111-1111-1111111111a1");
    public static readonly Guid SouthOrg = Guid.Parse("22222222-2222-2222-2222-2222222222a1");
    public static readonly Guid HardwareTeam = Guid.Parse("33333333-3333-3333-3333-3333333333a1");
    public static readonly Guid BillingTeam = Guid.Parse("44444444-4444-4444-4444-4444444444a1");

    public const string Issuer = "https://helpdesk.example";

    public static IServiceCollection AddHelpdesk(this IServiceCollection services)
    {
        services.AddControllers();
        services.AddRouting();

        var store = new InMemoryIdentityStore();
        services.AddSingleton(store);
        services.AddSingleton<IUserStore>(store);
        services.AddSingleton<IMfaStore>(store);
        services.AddSingleton<ISessionStore>(store);
        services.AddSingleton<IRefreshTokenStore, InMemoryRefreshTokenStore>();
        services.AddSingleton<IMachineIdentityStore, InMemoryMachineIdentityStore>();

        services.AddSingleton<TicketStore>();
        services.AddScoped<TicketResolver>();
        services.AddSingleton<HelpdeskDirectory>();
        services.AddSingleton<ISubjectDataSource>(sp => sp.GetRequiredService<HelpdeskDirectory>());

        services.Configure<SentinelTokenOptions>(o => o.Issuer = Issuer);

        services.AddSentinel(o =>
        {
            o.DefaultRealmId = Realm;
            // Ephemeral signing keys are for samples. A real deployment supplies its own, and
            // Sentinel refuses to start outside development without them.
            o.AllowDevelopmentDefaults = true;
        });

        services.AddSentinelAuthentication(o =>
        {
            o.Issuer = Issuer;
            o.DefaultRealmId = Realm;
        });

        // The one call this sample is about. Everything after it is ordinary ASP.NET code.
        services.AddSentinelAuthorization(o =>
        {
            // A caller still on roles keeps working while their code is migrated; the role is only
            // granted to whoever holds the permission it maps onto.
            o.RoleCompatibility.MapRole("Supervisor", HelpdeskDefinitions.ReportsRead);
            o.IncludePermissionInResponse = true;
        });

        services.AddSingleton(sp => new SubjectSnapshotCache(
            sp.GetRequiredService<ISubjectDataSource>(),
            sp.GetRequiredService<ISentinelClock>(),
            sp.GetRequiredService<ISentinelCacheBus>()));

        return services;
    }

    /// <summary>
    /// Publishes the permissions and then refuses to serve traffic if any endpoint is guarded by
    /// something that cannot be enforced as written.
    /// </summary>
    public static async Task ValidateHelpdeskAsync(this IEndpointRouteBuilder endpoints)
    {
        // Signing keys first: a host with none must die before it accepts traffic.
        await SentinelHost.InitializeAsync(endpoints.ServiceProvider);

        var sync = endpoints.ServiceProvider.GetRequiredService<DefinitionSyncService>();
        await sync.SyncAsync(HelpdeskDefinitions.All, HelpdeskDefinitions.OwnerService);

        await endpoints.ValidateSentinelAuthorizationAsync();
    }
}
