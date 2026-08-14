using Nuvora.Nexus.Relay.Auth;
using Nuvora.Nexus.Relay.Auth.Attributes;
using Nuvora.Nexus.Relay.Core.Application.Commands;
using Nuvora.Nexus.Relay.Tenancy;
using Nuvora.Nexus.Sentinel.Relay.Authorization;

namespace RelayBridge.Api;

/// <summary>
/// What a handler observes: the Sentinel subject became Relay's
/// <c>AuthContext.UserId</c> (same Guid, no mapping table) and the token's org claim became
/// the ambient <c>TenantContext</c>.
/// </summary>
public sealed record TicketObservation(Guid? UserId, string? Username, Guid? TenantId, string? OrgClaim)
{
    public static TicketObservation Capture(AuthContext auth, TenantContext tenant) => new(
        auth.UserId,
        auth.Username,
        tenant.TenantId,
        auth.Claims.TryGetValue("org", out var org) ? org : null);
}

/// <summary>
/// [RequirePermission] is RELAY's attribute — the permission STRING is Sentinel's
/// <c>service:scope:action</c> grammar, and with the bridge installed the check is decided by
/// Sentinel's evaluator (wildcards, deny-overrides), not by string equality.
/// </summary>
[RequireAuthentication]
[RequirePermission("tickets:org:read")]
[SkipTransaction] // No persistence in this host — keeps Relay's transactional pipeline out of it.
public sealed record ReadTicketsCommand : ICommand<TicketObservation>;

/// <summary>
/// The same check through the per-dispatch policy path: <c>[RequirePolicy("sentinel")]</c>
/// evaluates against the live subject snapshot at dispatch time.
/// </summary>
[RequireAuthentication]
[RequirePolicy(SentinelAuthorizationPolicy.PolicyName)]
[RequirePermission("tickets:org:close")]
[SkipTransaction]
public sealed record CloseTicketCommand : ICommand<TicketObservation>;

public sealed class ReadTicketsCommandHandler(IAuthContextAccessor auth, ITenantContextAccessor tenant)
    : ICommandHandler<ReadTicketsCommand, TicketObservation>
{
    public Task<TicketObservation> Handle(ReadTicketsCommand message, CancellationToken cancellationToken) =>
        Task.FromResult(TicketObservation.Capture(auth.Current, tenant.Current));
}

public sealed class CloseTicketCommandHandler(IAuthContextAccessor auth, ITenantContextAccessor tenant)
    : ICommandHandler<CloseTicketCommand, TicketObservation>
{
    public Task<TicketObservation> Handle(CloseTicketCommand message, CancellationToken cancellationToken) =>
        Task.FromResult(TicketObservation.Capture(auth.Current, tenant.Current));
}
