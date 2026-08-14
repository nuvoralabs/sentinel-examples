// Sample 009 — SCIM Provisioning. A minimal host that serves Sentinel's SCIM 2.0 surface:
// Users + Groups CRUD under /scim/v2, authenticated by per-organization sct_ bearer tokens.
// Two orgs, two tokens — each corporate IdP can only ever provision into its own org.

using Provisioning.Api;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddProvisioningApi();

var app = builder.Build();

app.MapProvisioningApi();

// Mint one provisioning token per organization and print it once — the secret is never
// recoverable later (only its SHA-256 digest is stored). A real host mints these from an
// admin surface and hands them to the IdP operator through a secret channel, never a log.
var (acme, globex) = await ProvisioningWorld.MintTokensAsync(app.Services);
Console.WriteLine("SCIM provisioning tokens (shown once, demo only):");
Console.WriteLine($"  Acme Clinic  : {acme.Secret}");
Console.WriteLine($"  Globex Health: {globex.Secret}");

await app.RunAsync();

/// <summary>Anchor so the test project can reference the app assembly's composition.</summary>
public partial class Program;
