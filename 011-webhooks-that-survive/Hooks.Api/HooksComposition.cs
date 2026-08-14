using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Nuvora.Nexus.Sentinel.AspNetCore;
using Nuvora.Nexus.Sentinel.AspNetCore.DependencyInjection;
using Nuvora.Nexus.Sentinel.AspNetCore.Endpoints;
using Nuvora.Nexus.Sentinel.AspNetCore.Webhooks;
using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Nuvora.Nexus.Sentinel.Login;
using Nuvora.Nexus.Sentinel.Tokens;
using Nuvora.Nexus.Sentinel.Webhooks;

namespace Hooks.Api;

/// <summary>
/// The whole composition, shared verbatim by Program.cs and the test host: the login
/// stack (events need a source), the webhook outbox + admin service, the hosted dispatcher,
/// and the app's own signed-delivery receiver.
/// </summary>
public static class HooksComposition
{
    public static IServiceCollection AddHooksApi(
        this IServiceCollection services, Action<WebhookDispatcherOptions>? webhooks = null)
    {
        services.AddRouting();

        var identity = new InMemoryIdentityStore();
        var directory = new HooksDirectory();
        services.AddSingleton(identity);
        services.AddSingleton<IUserStore>(identity);
        services.AddSingleton<IMfaStore>(identity);
        services.AddSingleton<ISessionStore>(identity);
        services.AddSingleton(directory);
        services.AddSingleton<ISubjectDataSource>(directory);

        services.Configure<SentinelTokenOptions>(o => o.Issuer = HooksWorld.Issuer);
        services.AddSentinel(o =>
        {
            o.DefaultRealmId = HooksWorld.RealmId;
            o.AllowDevelopmentDefaults = true; // ephemeral dev signing keys, explicit opt-in
        });
        services.AddSentinelAuthentication(o =>
        {
            o.Issuer = HooksWorld.Issuer;
            o.Audience = HooksWorld.Audience;
            o.DefaultRealmId = HooksWorld.RealmId;
            o.Transport = SentinelTokenTransport.Bearer;
        });

        // The outbox: rewrites ISentinelEventSink into a composite that also enqueues
        // matching events as durable deliveries. Timings are injectable so the README run
        // retries in seconds while production keeps the 1m/5m/30m/2h/12h ladder.
        services.AddSentinelWebhooks(webhooks ?? delegate { });

        // The pump: a hosted service that claims due deliveries, POSTs, signs, retries.
        services.AddSentinelWebhookDispatcher();

        // The app's own receiving side.
        services.AddSingleton<BillingReceiver>();

        return services;
    }

    public static IEndpointRouteBuilder MapHooksApi(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapSentinelAuth();          // /auth/* — the event source (login.failed, …)
        endpoints.MapSentinelWebhookAdmin();  // /sentinel-admin/webhooks/* — subscriptions

        // The receiver: anonymous by design — authentication IS the HMAC signature.
        endpoints.MapPost("/billing/events", async (HttpContext http, BillingReceiver receiver) =>
        {
            using var reader = new StreamReader(http.Request.Body);
            var body = await reader.ReadToEndAsync(http.RequestAborted);
            var status = receiver.Record(
                http.Request.Headers[WebhookSignature.SignatureHeader].ToString(),
                http.Request.Headers[WebhookSignature.EventHeader].ToString(),
                http.Request.Headers[WebhookSignature.DeliveryHeader].ToString(),
                body);
            return Results.StatusCode(status);
        });

        // Read side for the README walkthrough.
        endpoints.MapGet("/billing/received", (BillingReceiver receiver) =>
            Results.Ok(receiver.Accepted.Select(d => new { d.DeliveryId, d.EventKind })));

        // Demo plumbing: hand the receiver its whsec_ secret (an external receiver gets it
        // through configuration; this sample's lives in the same process).
        endpoints.MapPost("/billing/secret", (BillingReceiver receiver, ReceiverSecret body) =>
        {
            receiver.Secret = body.Secret;
            return Results.NoContent();
        });

        return endpoints;
    }
}

/// <summary>Body of the demo secret hand-off endpoint.</summary>
public sealed record ReceiverSecret(string Secret);
