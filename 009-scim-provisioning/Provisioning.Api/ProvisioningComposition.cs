using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Nuvora.Nexus.Sentinel.Login;
using Nuvora.Nexus.Sentinel.Scim;
using Nuvora.Nexus.Sentinel.Scim.DependencyInjection;

namespace Provisioning.Api;

/// <summary>
/// The whole SCIM host composition, shared verbatim by Program.cs and the test host.
/// SCIM is deliberately standalone: no AddSentinel(), no signing keys, no login stack —
/// just a store, AddSentinelScim(), and MapSentinelScim(). Auth is the sct_ bearer token,
/// enforced by the endpoint group itself.
/// </summary>
public static class ProvisioningComposition
{
    public static IServiceCollection AddProvisioningApi(this IServiceCollection services)
    {
        services.AddRouting();

        // Register the store BEFORE AddSentinelScim(): every Sentinel registration is TryAdd,
        // so the host's instance wins and stays reachable for seeding and assertions.
        // A real deployment registers AddSentinelEfCoreStores instead and gets EfScimStore.
        var store = new InMemoryScimStore();
        ProvisioningWorld.Seed(store);
        services.AddSingleton(store);
        services.AddSingleton<IScimStore>(store);

        // Defaults: BaseUrl "/scim/v2", MaxPageSize 100.
        services.AddSentinelScim();

        return services;
    }

    public static IEndpointRouteBuilder MapProvisioningApi(this IEndpointRouteBuilder endpoints)
    {
        // /scim/v2/{ServiceProviderConfig,ResourceTypes,Schemas,Users,Groups} — every route
        // (discovery included) behind the sct_ bearer filter.
        endpoints.MapSentinelScim();
        return endpoints;
    }
}
