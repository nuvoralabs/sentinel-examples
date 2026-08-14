// Sample 003 — Refresh Token Families. Opaque rotating refresh tokens with FAMILY-BASED REUSE
// DETECTION: every login starts a family; each POST /auth/refresh rotates to a
// new token and consumes the old one; presenting a consumed token means it leaked — the whole
// family is revoked (rotated token included) and a token.refresh_reuse_detected security event
// fires through the event sink, observable here at GET /security/events.

using Nuvora.Nexus.Sentinel.AspNetCore.Endpoints;
using RefreshFamilies.Api;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRefreshFamiliesApi();

var app = builder.Build();

// The Sentinel scheme is the default, so plain UseAuthentication runs the handler.
app.UseAuthentication();

// Mountable endpoint groups, opt-in per group.
app.MapSentinelAuth();
app.MapSentinelProfile();

// Demo-only visibility into the event sink.
app.MapSecurityEvents();

// Key check + demo seed data before serving traffic.
await DemoData.SeedAsync(app.Services);

await app.RunAsync();

/// <summary>Anchor so the test project can reference the app assembly's composition.</summary>
public partial class Program;
