// Sample 013 — Abuse Protection Layers. The four rate-limit layers Sentinel checks before
// touching the database on every login — per-IP, per-IP+account, account lockout,
// credential-stuffing heuristics — plus the adaptive captcha band and the per-layer
// fail-open/fail-closed outage policy.

using AbuseGate.Api;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAbuseGateApi();

var app = builder.Build();

app.UseDemoClientIp(); // demo-only: X-Demo-Ip header simulates distinct client addresses

app.UseAuthentication();
app.MapAbuseGateApi();

await GateWorld.SeedAsync(app.Services);

await app.RunAsync();

/// <summary>Anchor so the test project can reference the app assembly's composition.</summary>
public partial class Program;
