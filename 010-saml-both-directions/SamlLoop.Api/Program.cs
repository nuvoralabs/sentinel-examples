// Sample 010 — SAML in both directions. ONE host that is simultaneously a SAML IdP and a
// SAML SP, looped onto itself: /auth/saml/self/start sends the browser to this host's own
// /saml/idp/sso, which issues a signed assertion back to this host's own /auth/saml/acs —
// verified against the pinned certificate, never against whatever the document embeds.

using SamlLoop.Api;

// SAML endpoint URLs are compared ordinally against the live request, so the launch origin
// must match the seeded connection URLs exactly.
const string Origin = "http://localhost:5010";

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSamlLoopApi();

var app = builder.Build();
app.Urls.Add(Origin);

app.UseAuthentication();
app.MapSamlLoopApi();

await SamlLoopComposition.SeedConnectionsAsync(app.Services, Origin);

await app.RunAsync();

/// <summary>Anchor so the test project can reference the app assembly's composition.</summary>
public partial class Program;
