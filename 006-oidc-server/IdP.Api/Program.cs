// Sample 006 — Sentinel as an OAuth2/OIDC authorization server, IdP side.
// Thin composition: everything interesting lives in IdpComposition, which the tests reuse.

using IdP.Api;
using Nuvora.Nexus.Sentinel.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddIdpApi();

var app = builder.Build();

app.UseAuthentication(); // the Sentinel scheme — feeds the authorize endpoint's principal

app.MapIdpApi();

// Fail-fast startup init: the signing-key ring must exist before traffic.
await SentinelHost.InitializeAsync(app.Services);

await app.RunAsync();
