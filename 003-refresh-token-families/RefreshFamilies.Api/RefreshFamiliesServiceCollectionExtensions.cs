using Microsoft.Extensions.DependencyInjection;
using Nuvora.Nexus.Sentinel.AspNetCore;
using Nuvora.Nexus.Sentinel.AspNetCore.DependencyInjection;
using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Nuvora.Nexus.Sentinel.Login;
using Nuvora.Nexus.Sentinel.Ports;
using Nuvora.Nexus.Sentinel.Tokens;

namespace RefreshFamilies.Api;

public static class RefreshFamiliesServiceCollectionExtensions
{
    /// <summary>
    /// Sentinel over the Bearer transport (the API/machine/mobile posture), with
    /// a recording event sink so the family-reuse security event is visible. Shared by
    /// Program.cs and the test host so both run the exact same wiring.
    /// </summary>
    public static IServiceCollection AddRefreshFamiliesApi(this IServiceCollection services)
    {
        services.AddRouting();

        // BEFORE AddSentinel: its port defaults use TryAdd, so an earlier registration wins
        // over the no-op sink.
        var sink = new RecordingEventSink();
        services.AddSingleton(sink);
        services.AddSingleton<ISentinelEventSink>(sink);

        // Identity stores are opt-in: the in-memory ones, seeded by DemoData. The
        // refresh-token store itself needs no registration — AddSentinel defaults to the
        // single-node InMemoryRefreshTokenStore; fleets swap in the ValKey adapter.
        var store = new InMemoryIdentityStore();
        services.AddSingleton(store);
        services.AddSingleton<IUserStore>(store);
        services.AddSingleton<IMfaStore>(store);
        services.AddSingleton<ISessionStore>(store);
        services.AddSingleton<ISubjectDataSource, DemoSubjectSource>();

        services.Configure<SentinelTokenOptions>(o => o.Issuer = DemoData.Issuer);

        services.AddSentinel(o =>
        {
            o.DefaultRealmId = DemoData.Realm;
            // Ephemeral development signing keys: sample-only opt-in.
            o.AllowDevelopmentDefaults = true;
        });

        services.AddSentinelAuthentication(o =>
        {
            o.Issuer = DemoData.Issuer;
            o.Audience = DemoData.Audience;
            o.DefaultRealmId = DemoData.Realm;
            // Bearer transport: tokens in the JSON body, no cookies — refresh rotation
            // is the client's job, which is exactly what this sample walks through.
            o.Transport = SentinelTokenTransport.Bearer;
        });

        return services;
    }
}

/// <summary>Minimal snapshot source: no grants — this sample is about tokens, not authorization.</summary>
public sealed class DemoSubjectSource : ISubjectDataSource
{
    public ValueTask<SubjectData?> LoadAsync(
        Guid userId, Guid? organizationId, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult<SubjectData?>(new SubjectData(
            userId, DemoData.Realm, organizationId, TeamMemberships: [], Grants: [], Attributes: null));
}
