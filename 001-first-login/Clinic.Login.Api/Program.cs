// Sample 001 — First Login. An ordinary ASP.NET minimal API that EMBEDS Sentinel:
// password + TOTP login over the httpOnly-cookie transport with CSRF double-submit,
// plus one protected app endpoint. Everything here is AddSentinel* / MapSentinel* calls —
// the same composition the reference server makes.

using Clinic.Login.Api;
using Nuvora.Nexus.Sentinel.AspNetCore.Endpoints;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddClinicLoginApi();

var app = builder.Build();

// The Sentinel scheme is the default, so plain UseAuthentication runs the handler.
app.UseAuthentication();

// Mountable endpoint groups, opt-in per group: the login flows and the profile surface.
app.MapSentinelAuth();
app.MapSentinelProfile();

// The app's own endpoint, protected by the Sentinel principal.
app.MapClinicDashboard();

// Key check + demo seed data before serving traffic.
await ClinicDemo.SeedAsync(app.Services);

await app.RunAsync();

/// <summary>Anchor so the test project can reference the app assembly's composition.</summary>
public partial class Program;
