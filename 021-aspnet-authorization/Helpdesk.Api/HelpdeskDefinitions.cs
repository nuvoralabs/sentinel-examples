using Nuvora.Nexus.Sentinel.Definitions;

namespace Helpdesk.Api;

/// <summary>
/// The helpdesk's permissions, declared in code. Definition sync publishes them at startup, and an
/// endpoint guarded by anything that was never published stops the application from starting.
/// </summary>
public static class HelpdeskDefinitions
{
    public const string OwnerService = "helpdesk";

    /// <summary>Read any ticket in an organization — the front-desk baseline.</summary>
    public const string TicketsRead = "helpdesk:org:tickets_read";

    /// <summary>Close a ticket, still only within the caller's organization.</summary>
    public const string TicketsClose = "helpdesk:org:tickets_close";

    /// <summary>Read the notes attached to a ticket, restricted to the team handling it.</summary>
    public const string NotesRead = "helpdesk:team:notes_read";

    /// <summary>Read the realm-wide report — nothing about one particular ticket.</summary>
    public const string ReportsRead = "helpdesk:global:reports_read";

    public static readonly SentinelDefinitions All = new(
    [
        new PermissionDefinition(TicketsRead, "Read an organization's tickets", ownerService: OwnerService),
        new PermissionDefinition(TicketsClose, "Close an organization's tickets", ownerService: OwnerService),
        new PermissionDefinition(NotesRead, "Read a ticket's notes", ownerService: OwnerService),
        new PermissionDefinition(ReportsRead, "Read the helpdesk report", ownerService: OwnerService),
    ],
        apps: []);
}
