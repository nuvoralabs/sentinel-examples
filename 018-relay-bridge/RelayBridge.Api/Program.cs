// Sample 018 — the Sentinel ↔ Relay bridge: one middleware call makes Sentinel the
// authentication, authorization AND tenancy authority for a Relay application. All the wiring
// lives in RelayBridgeComposition.cs, shared verbatim with the tests.

using Nuvora.Nexus.Relay.Tenancy;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Nuvora.Nexus.Sentinel.Relay.Middleware;
using RelayBridge.Api;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRelayBridgeApi();

var app = builder.Build();

// Documented order: authentication (the Sentinel handler stashes principal + snapshot) →
// the bridge projection (REPLACES Relay's UseRelayAuthContext — never run both) → tenant
// resolution (reads the projected principal) → endpoints.
app.UseAuthentication();
app.UseSentinelRelayAuthContext();
app.UseRelayTenantContext();

app.MapRelayBridgeApi();

// Fail-fast startup init: the signing-key ring must exist before traffic.
await SentinelHost.InitializeAsync(app.Services);

await app.RunAsync();
