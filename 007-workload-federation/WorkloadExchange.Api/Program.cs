// Sample 007 — workload identity federation / secretless CI.
// Thin composition: everything interesting lives in WorkloadComposition, which the tests reuse.

using Nuvora.Nexus.Sentinel.DependencyInjection;
using WorkloadExchange.Api;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddWorkloadExchangeApi();

var app = builder.Build();

app.UseAuthentication(); // the Sentinel scheme — exchanged tokens are ordinary access tokens

app.MapWorkloadExchangeApi();

// Fail-fast startup init: the signing-key ring must exist before traffic.
await SentinelHost.InitializeAsync(app.Services);

await app.RunAsync();
