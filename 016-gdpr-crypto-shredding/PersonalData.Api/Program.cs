// Sample 016 — GDPR: export the Art. 20 bundle, erase with crypto-shredding
// (shred the subject's key → anonymize the row → redact the ledgers), and verify the
// tamper-evident audit chain STILL passes afterwards. All the wiring lives in
// PersonalDataComposition.cs, shared verbatim with the tests.

using Nuvora.Nexus.Sentinel.DependencyInjection;
using PersonalData.Api;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddPersonalDataApi();

var app = builder.Build();

app.UseAuthentication();
app.MapPersonalDataApi();

// Fail-fast startup init: the signing-key ring must exist before traffic.
await SentinelHost.InitializeAsync(app.Services);

await app.RunAsync();
