using Microsoft.Extensions.DependencyInjection;
using Nuvora.Nexus.Sentinel.AspNetCore;
using Nuvora.Nexus.Sentinel.AspNetCore.DependencyInjection;
using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Nuvora.Nexus.Sentinel.Login;
using Nuvora.Nexus.Sentinel.Ports;
using Nuvora.Nexus.Sentinel.Tokens;

namespace Passkeys.Api;

public static class PasskeysServiceCollectionExtensions
{
    /// <summary>
    /// The passkeys-first composition: the base Sentinel stack plus
    /// AddSentinelPasskeys with this host's WebAuthn relying-party identity. Shared by
    /// Program.cs and the test host so both run the exact same wiring.
    /// </summary>
    public static IServiceCollection AddPasskeysApi(this IServiceCollection services)
    {
        services.AddRouting();

        // BEFORE AddSentinel: TryAdd lets this recording sink win over the no-op default.
        var sink = new RecordingEventSink();
        services.AddSingleton(sink);
        services.AddSingleton<ISentinelEventSink>(sink);

        // Identity AND passkey stores are opt-in, never silently defaulted: passkeys are
        // identity data. In-memory here; a real host registers the EF Core adapter.
        var store = new InMemoryIdentityStore();
        var passkeys = new InMemoryPasskeyStore();
        services.AddSingleton(store);
        services.AddSingleton<IUserStore>(store);
        services.AddSingleton<IMfaStore>(store);
        services.AddSingleton<ISessionStore>(store);
        services.AddSingleton(passkeys);
        services.AddSingleton<IPasskeyStore>(passkeys);
        services.AddSingleton<ISubjectDataSource, DemoSubjectSource>();

        services.Configure<SentinelTokenOptions>(o => o.Issuer = PasskeyDemo.Issuer);

        services.AddSentinel(o =>
        {
            o.DefaultRealmId = PasskeyDemo.Realm;
            // Ephemeral development signing keys: sample-only opt-in.
            o.AllowDevelopmentDefaults = true;
        });

        services.AddSentinelAuthentication(o =>
        {
            o.Issuer = PasskeyDemo.Issuer;
            o.Audience = PasskeyDemo.Audience;
            o.DefaultRealmId = PasskeyDemo.Realm;
            // Bearer keeps the ceremony JSON round-trips easy to follow; the cookie transport
            // (sample 001) composes with passkeys identically.
            o.Transport = SentinelTokenTransport.Bearer;
        });

        // The WebAuthn relying party: RpId must be the effective domain the browser sees,
        // and every allowed web origin is listed — assertions from any other origin fail closed.
        services.AddSentinelPasskeys(o =>
        {
            o.RpId = PasskeyDemo.RpId;
            o.RpName = "Passkeys Sample";
            o.Origins.Add(PasskeyDemo.Origin);
        });

        return services;
    }
}

/// <summary>Minimal snapshot source: no grants — this sample is about the passkey factor, not authorization.</summary>
public sealed class DemoSubjectSource : ISubjectDataSource
{
    public ValueTask<SubjectData?> LoadAsync(
        Guid userId, Guid? organizationId, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult<SubjectData?>(new SubjectData(
            userId, PasskeyDemo.Realm, organizationId, TeamMemberships: [], Grants: [], Attributes: null));
}
