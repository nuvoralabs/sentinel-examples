// Sample 004 — Passkeys. The WebAuthn round trip: AddSentinelPasskeys + MapSentinelPasskeys
// mount registration ceremonies (authenticated), usernameless passwordless login, passkey-as-
// second-factor MFA, and credential management under /auth/passkey. In a browser the options
// JSON goes straight into navigator.credentials.create()/get(); the test project drives the same
// endpoints with a software authenticator instead.

using Nuvora.Nexus.Sentinel.AspNetCore.Endpoints;
using Passkeys.Api;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddPasskeysApi();

var app = builder.Build();

// The Sentinel scheme is the default, so plain UseAuthentication runs the handler.
app.UseAuthentication();

// Mountable endpoint groups, opt-in per group.
app.MapSentinelAuth();
app.MapSentinelProfile();
app.MapSentinelPasskeys();

// Key check + demo seed data before serving traffic.
await PasskeyDemo.SeedAsync(app.Services);

await app.RunAsync();

/// <summary>Anchor so the test project can reference the app assembly's composition.</summary>
public partial class Program;
