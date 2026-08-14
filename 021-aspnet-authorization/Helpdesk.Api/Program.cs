// Sample 021 — ASP.NET authorization, decided by Sentinel. An ordinary controller-based API:
// [Authorize(Policy = "...")] and [SentinelPermission] are enforced by Sentinel's evaluator, so
// permissions, wildcards, deny-overrides and per-record scoping all apply to endpoints written
// exactly the way ASP.NET documents.

using Helpdesk.Api;
using Nuvora.Nexus.Sentinel.AspNetCore.Endpoints;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHelpdesk();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// Sentinel's own login endpoints, so the walkthrough can obtain a token.
app.MapSentinelAuth();
app.MapControllers();

HelpdeskSeed.Seed(app.Services);

// Publishes the permissions, then refuses to serve traffic if any endpoint is guarded by something
// that cannot be enforced as written — an unbound organization check, a team check with no team, a
// binding naming a route value that does not exist.
await app.ValidateHelpdeskAsync();

await app.RunAsync();

/// <summary>Anchor so the test project can reference this application's composition.</summary>
public partial class Program;
