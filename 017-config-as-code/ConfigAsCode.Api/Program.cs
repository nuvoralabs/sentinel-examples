// Sample 017 — config-as-code: the realm, org, roles and OIDC clients this host
// serves are DECLARED in clinic.sentinel.yaml and applied idempotently at boot — matched by
// natural key, created when missing, updated when drifted, never deleted. All the wiring
// lives in ConfigAsCodeComposition.cs, shared verbatim with the tests.

using ConfigAsCode.Api;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddConfigAsCodeApi();

var app = builder.Build();

app.MapConfigAsCodeApi();

// Boot-time apply, fail-closed: config errors abort startup instead of drifting silently.
await ConfigAsCodeComposition.ApplyDeclaredConfigAsync(app.Services);

await app.RunAsync();
