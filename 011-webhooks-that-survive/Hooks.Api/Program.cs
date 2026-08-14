// Sample 011 — Webhooks that survive. An app that embeds Sentinel and both SENDS and
// RECEIVES its webhooks: subscribe over /sentinel-admin/webhooks, receive HMAC-signed
// deliveries at /billing/events, verify with WebhookSignature.Verify, and watch the
// dispatcher retry a failing receiver until it heals.

using Hooks.Api;

var builder = WebApplication.CreateBuilder(args);

// Demo-friendly retry ladder (seconds, not the production 1m/5m/30m/2h/12h) so the README
// outage walkthrough resolves while you watch.
builder.Services.AddHooksApi(o =>
{
    o.PollInterval = TimeSpan.FromSeconds(1);
    o.RetryBackoff = [TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(15)];
});

var app = builder.Build();

app.UseAuthentication();
app.MapHooksApi();

await HooksWorld.SeedAsync(app.Services);

await app.RunAsync();

/// <summary>Anchor so the test project can reference the app assembly's composition.</summary>
public partial class Program;
