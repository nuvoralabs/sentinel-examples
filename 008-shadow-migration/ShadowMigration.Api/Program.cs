// Sample 008 — Shadow Migration: import a legacy ASP.NET-Identity database into
// Sentinel, let imported users log in with their LEGACY passwords (hash
// coexistence), run legacy and Sentinel authorization side by side (shadow mode), and
// gate cutover on zero divergences. All the interesting wiring lives in ShadowComposition.cs,
// shared verbatim with the tests.

using ShadowMigration.Api;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddShadowMigrationApi();

var app = builder.Build();
app.UseAuthentication();
app.MapShadowMigrationApi();

await ShadowComposition.InitializeAsync(app.Services);

app.Run();

/// <summary>TestHost anchor for the sample's test project.</summary>
public partial class Program;
