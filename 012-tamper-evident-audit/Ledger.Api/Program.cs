// Sample 012 — Tamper-Evident Audit. Every delegated-admin mutation appends to a per-realm
// hash chain (AdminAuditChain); GET /sentinel-admin/audit re-verifies the whole chain on
// every read and reports chainIntact / firstBrokenSequence. The tests tamper with stored
// entries and watch the verdict flip; redaction (payloads nulled, digests kept) does not.

using Ledger.Api;
using Nuvora.Nexus.Sentinel.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddLedgerApi();

var app = builder.Build();

app.UseAuthentication();
app.MapLedgerApi();

await SentinelHost.InitializeAsync(app.Services);

await app.RunAsync();

/// <summary>Anchor so the test project can reference the app assembly's composition.</summary>
public partial class Program;
