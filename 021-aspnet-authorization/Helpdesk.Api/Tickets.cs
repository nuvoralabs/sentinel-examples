using Microsoft.AspNetCore.Http;
using Nuvora.Nexus.Sentinel.Authorization.AspNetCore;

namespace Helpdesk.Api;

/// <summary>A support ticket: it belongs to an organization, and one team handles it.</summary>
public sealed record Ticket(Guid Id, Guid OrganizationId, Guid TeamId, string Subject);

/// <summary>The tickets this sample serves, seeded in memory.</summary>
public sealed class TicketStore
{
    private readonly Dictionary<Guid, Ticket> _tickets = [];

    public void Add(Ticket ticket) => _tickets[ticket.Id] = ticket;

    public Ticket? Find(Guid id) => _tickets.TryGetValue(id, out var ticket) ? ticket : null;

    public IEnumerable<Ticket> All => _tickets.Values;

    public IEnumerable<Ticket> InOrganization(Guid? organizationId) =>
        _tickets.Values.Where(ticket => ticket.OrganizationId == organizationId);

    public IEnumerable<Ticket> ForTeams(Guid? organizationId, IReadOnlyList<Guid> teams) =>
        InOrganization(organizationId).Where(ticket => teams.Contains(ticket.TeamId));
}

/// <summary>
/// Loads the ticket named in the route and reports the organization and team it belongs to.
/// </summary>
/// <remarks>
/// This is the case the route-value shorthand cannot cover: the ticket's team is not in the URL, it
/// is a property of the record, so it has to be looked up before the question can be asked. Every
/// check on a note therefore concerns the team that actually owns that ticket.
/// </remarks>
public sealed class TicketResolver : ISentinelResourceResolver
{
    private readonly TicketStore _tickets;

    public TicketResolver(TicketStore tickets)
    {
        _tickets = tickets;
    }

    public ValueTask<SentinelResourceResolution> ResolveAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        var raw = httpContext.Request.RouteValues["ticketId"]?.ToString();

        if (!Guid.TryParse(raw, out var id) || _tickets.Find(id) is not { } ticket)
        {
            // Not "no resource, carry on unbound" — the request is refused.
            return ValueTask.FromResult(SentinelResourceResolution.NotFound);
        }

        return ValueTask.FromResult(SentinelResourceResolution.Found(
            new SentinelResourceContext(
                OrganizationId: ticket.OrganizationId,
                TeamIds: [ticket.TeamId])));
    }
}
