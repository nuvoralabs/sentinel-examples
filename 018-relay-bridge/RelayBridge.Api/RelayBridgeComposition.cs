using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Nuvora.Nexus.Relay;
using Nuvora.Nexus.Relay.Auth.Exceptions;
using Nuvora.Nexus.Relay.Bus;
using Nuvora.Nexus.Sentinel.AspNetCore.DependencyInjection;
using Nuvora.Nexus.Sentinel.AspNetCore.Endpoints;
using Nuvora.Nexus.Sentinel.Authentication;
using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Nuvora.Nexus.Sentinel.Identity;
using Nuvora.Nexus.Sentinel.Login;
using Nuvora.Nexus.Sentinel.Relay.DependencyInjection;

namespace RelayBridge.Api;

/// <summary>
/// A Relay application whose authentication, authorization AND tenancy come from
/// Sentinel: the Sentinel handler authenticates the request, the bridge middleware projects
/// principal + permission snapshot onto Relay's AuthContext, and the org claim becomes Relay's
/// tenant. Shared verbatim by Program.cs and the tests.
/// </summary>
public static class RelayBridgeComposition
{
    public const string Issuer = "https://relaybridge.sample";
    public const string Audience = "tickets-api";
    public const string DemoPassword = "relay-bridge-demo-password";

    public static readonly Guid RealmId = Guid.Parse("00000000-0000-0000-0000-000000000018");
    public static readonly Guid SupportOrgId = Guid.Parse("00000018-0000-0000-0000-0000000000aa");

    // Fixed ids so the README's curl walkthrough and the tests agree on who is who.
    public static readonly Guid RitaId = Guid.Parse("00000018-0000-0000-0000-00000000000a");
    public static readonly Guid IvanId = Guid.Parse("00000018-0000-0000-0000-00000000000b");
    public static readonly Guid NadiaId = Guid.Parse("00000018-0000-0000-0000-00000000000c");

    public const string RitaEmail = "rita@support.sample";   // tickets:*:*            → read + close
    public const string IvanEmail = "ivan@support.sample";   // tickets:org:read       → read only
    public const string NadiaEmail = "nadia@support.sample"; // wildcard + close DENY  → deny overrides

    public static IServiceCollection AddRelayBridgeApi(this IServiceCollection services)
    {
        services.AddRouting();

        // ------------------------- Sentinel stack -------------------------
        var store = new InMemoryIdentityStore();
        var hasher = new PasswordHasher(
            new Argon2idPasswordHashAlgorithm(memoryKib: 8, iterations: 1, parallelism: 1)); // cheap: teaching code
        Seed(store, hasher);

        services.AddSingleton(store);
        services.AddSingleton<IUserStore>(store);
        services.AddSingleton<IMfaStore>(store);
        services.AddSingleton<ISessionStore>(store);
        services.AddSingleton<ISubjectDataSource, TicketGrantsSource>();
        services.AddSingleton(hasher);

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
        });

        // -------------------------- Relay stack ---------------------------
        // Relay over this assembly (commands + handlers), then the bridge: Sentinel becomes
        // the authorization authority and the tenant source.
        services.AddRelay(typeof(ReadTicketsCommand).Assembly);
        services.AddSentinelRelayAuthorization();
        services.AddSentinelRelayTenancy();

        return services;
    }

    private static void Seed(InMemoryIdentityStore store, PasswordHasher hasher)
    {
        AddUser(store, hasher, RitaId, RitaEmail, "Rita Resolver");
        AddUser(store, hasher, IvanId, IvanEmail, "Ivan Intern");
        AddUser(store, hasher, NadiaId, NadiaEmail, "Nadia No-Close");
    }

    private static void AddUser(
        InMemoryIdentityStore store, PasswordHasher hasher, Guid id, string email, string displayName)
    {
        var user = new User
        {
            Id = id,
            RealmId = RealmId,
            Email = email,
            EmailVerified = true,
            DisplayName = displayName,
        };
        store.AddUser(user, new UserCredential
        {
            UserId = user.Id,
            Algorithm = hasher.Current.Name,
            Hash = hasher.Hash(DemoPassword),
        });
        store.AddOrgMembership(user.Id, SupportOrgId); // the org claim → Relay's TenantContext
    }

    public static IEndpointRouteBuilder MapRelayBridgeApi(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapSentinelAuth(); // POST /auth/login

        // Real dispatch through Relay's bus. Relay's HTTP surface normally maps
        // UnauthorizedException/ForbiddenException via UseRelayExceptionHandling; this host
        // maps the same two exceptions inline to stay minimal.
        endpoints.MapPost("/tickets/read", (Delegate)((HttpContext ctx) => ExecuteAsync(
            () => ctx.RequestServices.GetRequiredService<ICommandBus>()
                .Execute<ReadTicketsCommand, TicketObservation>(new ReadTicketsCommand(), ctx.RequestAborted))));
        endpoints.MapPost("/tickets/close", (Delegate)((HttpContext ctx) => ExecuteAsync(
            () => ctx.RequestServices.GetRequiredService<ICommandBus>()
                .Execute<CloseTicketCommand, TicketObservation>(new CloseTicketCommand(), ctx.RequestAborted))));

        return endpoints;
    }

    private static async Task<IResult> ExecuteAsync(Func<Task<TicketObservation>> execute)
    {
        try
        {
            return Results.Json(await execute());
        }
        catch (UnauthorizedException)
        {
            return Results.StatusCode(StatusCodes.Status401Unauthorized);
        }
        catch (ForbiddenException)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }
    }
}

/// <summary>
/// Grants for the three agents. The strings feed Sentinel's REAL evaluator through the
/// bridge — which is why Rita's wildcard reaches <c>tickets:org:read</c> without the literal
/// string existing anywhere, and why Nadia's deny wins over her own wildcard.
/// </summary>
public sealed class TicketGrantsSource : ISubjectDataSource
{
    private static readonly Dictionary<Guid, GrantData[]> Grants = new()
    {
        [RelayBridgeComposition.RitaId] =
        [
            Grant("tickets:*:*", GrantEffect.Allow),
        ],
        [RelayBridgeComposition.IvanId] =
        [
            Grant("tickets:org:read", GrantEffect.Allow),
        ],
        [RelayBridgeComposition.NadiaId] =
        [
            Grant("tickets:*:*", GrantEffect.Allow),
            Grant("tickets:org:close", GrantEffect.Deny), // deny-overrides
        ],
    };

    private static GrantData Grant(string pattern, GrantEffect effect) =>
        new(pattern, effect, null, null, null, "role:support-demo");

    public ValueTask<SubjectData?> LoadAsync(
        Guid userId, Guid? organizationId, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult<SubjectData?>(new SubjectData(
            userId,
            RelayBridgeComposition.RealmId,
            organizationId,
            TeamMemberships: [],
            Grants: Grants.TryGetValue(userId, out var grants) ? grants : [],
            Attributes: null));
}
