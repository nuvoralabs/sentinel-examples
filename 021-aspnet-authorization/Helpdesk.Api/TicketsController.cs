using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.Authorization.AspNetCore;

namespace Helpdesk.Api;

/// <summary>
/// An ordinary ASP.NET controller. Every action is guarded the way the framework's own
/// authorization works — the difference is who answers the question.
/// </summary>
[ApiController]
[Route("api")]
public sealed class TicketsController : ControllerBase
{
    private readonly TicketStore _tickets;

    public TicketsController(TicketStore tickets)
    {
        _tickets = tickets;
    }

    /// <summary>
    /// The realm-wide report. Guarded by a plain policy naming a permission — the shape a codebase
    /// migrating from stock authorization already has, working unchanged.
    /// </summary>
    [HttpGet("reports")]
    [Authorize(Policy = HelpdeskDefinitions.ReportsRead)]
    public IActionResult Report() => Ok(new { tickets = _tickets.All.Count() });

    /// <summary>
    /// One organization's tickets. The organization comes from the route, so the question asked is
    /// about the organization in the URL — not whichever one the caller happens to belong to.
    /// </summary>
    [HttpGet("orgs/{orgId:guid}/tickets")]
    [SentinelPermission(HelpdeskDefinitions.TicketsRead, Organization = "{orgId}")]
    public IActionResult ListForOrganization(Guid orgId) =>
        Ok(_tickets.InOrganization(orgId).Select(ticket => new { ticket.Id, ticket.Subject }));

    /// <summary>Closing a ticket, checked against the organization that ticket belongs to.</summary>
    [HttpPost("tickets/{ticketId:guid}/close")]
    [SentinelPermission(HelpdeskDefinitions.TicketsClose, ResolverType = typeof(TicketResolver))]
    public IActionResult Close(Guid ticketId) => Ok(new { ticketId, status = "closed" });

    /// <summary>
    /// A ticket's notes, restricted to the team handling it. The team is a property of the ticket
    /// rather than part of the URL, so a resolver loads it before the question is asked.
    /// </summary>
    [HttpGet("tickets/{ticketId:guid}/notes")]
    [SentinelPermission(HelpdeskDefinitions.NotesRead, ResolverType = typeof(TicketResolver))]
    public IActionResult Notes(Guid ticketId) =>
        Ok(new { ticketId, notes = new[] { "Customer called back", "Waiting on parts" } });

    /// <summary>
    /// The caller's own view of the queue. Asking what they may see first means the database is
    /// queried once, correctly — rather than fetching everything and filtering afterwards, which is
    /// where rows leak.
    /// </summary>
    [HttpGet("queue")]
    [Authorize(Policy = HelpdeskDefinitions.ReportsRead)]
    public IActionResult Queue()
    {
        var scope = HttpContext.GetSentinelListScope(HelpdeskDefinitions.NotesRead);

        var visible = scope?.Level switch
        {
            null or VisibilityLevel.None => [],
            VisibilityLevel.Granted => _tickets.InOrganization(scope.OrganizationId),
            _ => _tickets.ForTeams(scope.OrganizationId, scope.TeamIds),
        };

        return Ok(new
        {
            visibility = scope?.Level.ToString() ?? nameof(VisibilityLevel.None),
            tickets = visible.Select(ticket => new { ticket.Id, ticket.Subject }),
        });
    }
}
