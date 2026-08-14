// Sample 019 — owner-capped API keys: snt_ tokens whose effective permissions are
// owner ∩ scopes, recomputed at every use — denies preserved, demotion shrinks keys, the key
// dies with its owner. All the wiring lives in MachineKeysComposition.cs, shared verbatim
// with the tests.

using MachineKeys.Api;
using Nuvora.Nexus.Sentinel.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddMachineKeysApi();

var app = builder.Build();

app.UseAuthentication(); // one scheme, three credential shapes: Bearer JWT → snt_ key → cookie
app.MapMachineKeysApi();

// Fail-fast startup init: the signing-key ring must exist before traffic.
await SentinelHost.InitializeAsync(app.Services);

await app.RunAsync();
