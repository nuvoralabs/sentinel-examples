// Sample 015 — break-glass & impersonation: an admin acts as a user on a signed,
// time-boxed, audited token (the `act` claim + the /profile/me banner); a break-glass account
// logs in with alarms ringing and its grants structurally capped; the drill health check keeps
// the emergency path honest. All the wiring lives in GovernanceComposition.cs, shared verbatim
// with the tests.

using Governance.Api;
using Nuvora.Nexus.Sentinel.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddGovernanceApi();

var app = builder.Build();

app.UseAuthentication();
app.MapGovernanceApi();

// Fail-fast startup init: the signing-key ring must exist before traffic.
await SentinelHost.InitializeAsync(app.Services);

await app.RunAsync();
