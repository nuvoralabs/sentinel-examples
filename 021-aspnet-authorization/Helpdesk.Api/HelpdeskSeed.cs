using Microsoft.Extensions.DependencyInjection;
using Nuvora.Nexus.Sentinel.Authentication;
using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.Identity;
using Nuvora.Nexus.Sentinel.Login;

namespace Helpdesk.Api;

/// <summary>Three members of staff, chosen so every guard in the controller has someone it refuses.</summary>
public static class HelpdeskSeed
{
    public const string Password = "correct-horse-battery-staple";

    public const string Agent = "avery@helpdesk.example";
    public const string Supervisor = "sam@helpdesk.example";
    public const string Outsider = "olive@helpdesk.example";

    public static void Seed(IServiceProvider services)
    {
        var identity = services.GetRequiredService<InMemoryIdentityStore>();
        var directory = services.GetRequiredService<HelpdeskDirectory>();
        var hasher = services.GetRequiredService<PasswordHasher>();
        var tickets = services.GetRequiredService<TicketStore>();

        tickets.Add(new Ticket(
            Guid.Parse("aaaaaaaa-0000-0000-0000-00000000000a"),
            HelpdeskComposition.NorthOrg, HelpdeskComposition.HardwareTeam, "Laptop will not charge"));
        tickets.Add(new Ticket(
            Guid.Parse("bbbbbbbb-0000-0000-0000-00000000000b"),
            HelpdeskComposition.NorthOrg, HelpdeskComposition.BillingTeam, "Duplicate invoice"));
        tickets.Add(new Ticket(
            Guid.Parse("cccccccc-0000-0000-0000-00000000000c"),
            HelpdeskComposition.SouthOrg, HelpdeskComposition.HardwareTeam, "Monitor flickering"));

        // Avery works the hardware queue for North: reads and closes North's tickets, and sees
        // notes only for the tickets their own team handles.
        var avery = Add(identity, hasher, Agent, HelpdeskComposition.NorthOrg);
        directory.Grant(avery, [HelpdeskComposition.HardwareTeam],
            new GrantData(HelpdeskDefinitions.TicketsRead, GrantEffect.Allow, HelpdeskComposition.NorthOrg, null, null, "role:agent"),
            new GrantData(HelpdeskDefinitions.TicketsClose, GrantEffect.Allow, HelpdeskComposition.NorthOrg, null, null, "role:agent"),
            new GrantData(HelpdeskDefinitions.NotesRead, GrantEffect.Allow, null, [HelpdeskComposition.HardwareTeam], null, "role:agent"));

        // Sam supervises: reads the report, and reads every ticket in North.
        var sam = Add(identity, hasher, Supervisor, HelpdeskComposition.NorthOrg);
        directory.Grant(sam, [],
            new GrantData(HelpdeskDefinitions.ReportsRead, GrantEffect.Allow, null, null, null, "role:supervisor"),
            new GrantData(HelpdeskDefinitions.TicketsRead, GrantEffect.Allow, HelpdeskComposition.NorthOrg, null, null, "role:supervisor"));

        // Olive has an account and nothing else — every guard should refuse them.
        Add(identity, hasher, Outsider, HelpdeskComposition.SouthOrg);
    }

    private static Guid Add(InMemoryIdentityStore identity, PasswordHasher hasher, string email, Guid organizationId)
    {
        var user = new User
        {
            RealmId = HelpdeskComposition.Realm,
            Email = email,
            EmailVerified = true,
            DisplayName = email,
        };

        identity.AddUser(user, new UserCredential
        {
            UserId = user.Id,
            Algorithm = hasher.Current.Name,
            Hash = hasher.Hash(Password),
        });
        identity.AddOrgMembership(user.Id, organizationId);

        return user.Id;
    }
}
