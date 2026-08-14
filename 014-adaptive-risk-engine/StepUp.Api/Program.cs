// Sample 014 — Adaptive Risk Engine. Every password login is scored by deterministic,
// explainable signals (new device 30, impossible travel 40, IP reputation 50, velocity 25,
// plus this app's own watchlist signal at 40). Score ≥ 40 demands MFA step-up — falling
// back to email OTP for users without TOTP — and ≥ 80 blocks, indistinguishable from a
// wrong password. A first-seen device alerts the user by mail even when the login sails.

using StepUp.Api;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddStepUpApi();

var app = builder.Build();

app.UseDemoClientIp(); // demo-only: X-Demo-Ip header simulates distinct client addresses

app.UseAuthentication();
app.MapStepUpApi();

await StepUpWorld.SeedAsync(app.Services);

await app.RunAsync();

/// <summary>Anchor so the test project can reference the app assembly's composition.</summary>
public partial class Program;
