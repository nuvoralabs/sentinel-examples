// Sample 002 — Permission Grammar. The authorization engine with NOTHING else around it:
// no login, no tokens, no stores — just Sentinel.Core's grammar (service:scope:action, per-
// segment wildcards, deny-overrides, ABAC conditions) and the single-path
// evaluator behind two endpoints, POST /check and POST /visibility.

using Grammar.Api;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRouting();

var app = builder.Build();

app.MapGrammarEndpoints();

await app.RunAsync();

/// <summary>Anchor so the test project can reference the app assembly's composition.</summary>
public partial class Program;
