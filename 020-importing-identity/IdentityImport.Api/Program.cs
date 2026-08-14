// Sample 020 — importing identity: four legacy exports (ASP.NET Core Identity,
// Keycloak, Auth0, Duende) land in Sentinel's real EF stores through one import target — dry
// run first, real run idempotent, foreign hashes verifying at login and rehashing to
// argon2id, unrecoverable client secrets rotated with the plaintext surfaced exactly once.
// All the wiring lives in ImportComposition.cs, shared verbatim with the tests.

using IdentityImport.Api;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddIdentityImportApi();

var app = builder.Build();

app.UseAuthentication();
app.MapIdentityImportApi();

await ImportComposition.InitializeAsync(app.Services);

await app.RunAsync();
