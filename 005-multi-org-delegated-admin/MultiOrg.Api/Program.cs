// Sample 005 — multi-org membership, org switch and delegated admin.
// Thin composition: everything interesting lives in MultiOrgComposition, which the tests reuse.

using MultiOrg.Api;
using Nuvora.Nexus.Sentinel.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddMultiOrgApi();

var app = builder.Build();

app.UseAuthentication(); // the Sentinel scheme establishes the principal + snapshot

app.MapMultiOrgApi();

// Fail-fast startup init: the signing-key ring must exist before traffic.
await SentinelHost.InitializeAsync(app.Services);

await app.RunAsync();
