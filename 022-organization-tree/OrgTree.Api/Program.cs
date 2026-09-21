// Sample 022 — the organization tree: divisions under a tenant, cascading grants, node
// switching, tighten-only policies and application assignment.
// Thin composition: everything interesting lives in OrgTreeComposition, which the tests reuse.

using Nuvora.Nexus.Sentinel.DependencyInjection;
using OrgTree.Api;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOrgTreeApi();

var app = builder.Build();

app.UseAuthentication(); // the Sentinel scheme establishes the principal + snapshot

app.MapOrgTreeApi();

// Fail-fast startup init: the signing-key ring must exist before traffic.
await SentinelHost.InitializeAsync(app.Services);

await app.RunAsync();
