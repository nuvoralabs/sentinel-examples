using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Hooks.Api;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Nuvora.Nexus.Sentinel.Webhooks;
using Xunit;

namespace Hooks.Api.Tests;

/// <summary>
/// In-memory host for the sample: the SAME composition as Program.cs, with two
/// test-only twists — millisecond dispatcher timings, and a loopback transport registered
/// BEFORE AddHooksApi so the dispatcher's TryAdd keeps it and deliveries POST straight back
/// into the TestServer.
/// </summary>
internal sealed class HooksTestHost : IAsyncDisposable
{
    private sealed class ClientHolder
    {
        public HttpClient? Client;
    }

    private readonly IHost _host;

    private HooksTestHost(IHost host, HttpClient client, BillingReceiver receiver)
    {
        _host = host;
        Client = client;
        Receiver = receiver;
    }

    public HttpClient Client { get; }

    public BillingReceiver Receiver { get; }

    public static async Task<HooksTestHost> CreateAsync()
    {
        var holder = new ClientHolder();

        var host = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    // Loopback transport FIRST — the dispatcher registration is TryAdd, so
                    // this one wins and "outbound" webhooks land back in this TestServer.
                    services.AddSingleton<Func<WebhookRequest, CancellationToken, Task<int>>>(
                        async (request, ct) =>
                        {
                            using var message = new HttpRequestMessage(HttpMethod.Post, request.Url)
                            {
                                Content = new StringContent(request.Body, Encoding.UTF8, "application/json"),
                            };
                            foreach (var (name, value) in request.Headers)
                            {
                                message.Headers.TryAddWithoutValidation(name, value);
                            }

                            using var response = await holder.Client!.SendAsync(message, ct);
                            return (int)response.StatusCode;
                        });

                    services.AddHooksApi(o =>
                    {
                        o.PollInterval = TimeSpan.FromMilliseconds(50);
                        o.RetryBackoff = [TimeSpan.FromMilliseconds(200)];
                    });
                })
                .Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseEndpoints(endpoints => endpoints.MapHooksApi());
                }))
            .StartAsync();

        holder.Client = host.GetTestClient();
        await HooksWorld.SeedAsync(host.Services);

        return new HooksTestHost(
            host, holder.Client, host.Services.GetRequiredService<BillingReceiver>());
    }

    /// <summary>Password login; returns the bearer access token.</summary>
    public async Task<string> LoginAsync(string email)
    {
        var response = await Client.PostAsJsonAsync("/auth/login", new { email, password = HooksWorld.Password });
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("accessToken").GetString()!;
    }

    /// <summary>Sends an authenticated admin request.</summary>
    public async Task<HttpResponseMessage> AdminAsync(
        string bearer, HttpMethod method, string path, object? body = null)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }

        return await Client.SendAsync(request);
    }

    /// <summary>
    /// Subscribes /billing/events to the given event-kind patterns and hands the
    /// once-only secret to the receiver. Returns the endpoint id.
    /// </summary>
    public async Task<Guid> SubscribeAsync(string bearer, params string[] eventKinds)
    {
        var response = await AdminAsync(bearer, HttpMethod.Post, "/sentinel-admin/webhooks/", new
        {
            organizationId = (Guid?)null,
            url = "http://localhost/billing/events",
            eventKinds,
        });
        response.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Receiver.Secret = json.RootElement.GetProperty("secret").GetString();
        return json.RootElement.GetProperty("endpoint").GetProperty("id").GetGuid();
    }

    /// <summary>Deadline-poll for an async condition (the dispatcher pumps in the background).</summary>
    public static async Task WaitUntilAsync(Func<Task<bool>> condition, string what)
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(15);
        while (DateTimeOffset.UtcNow < deadline)
        {
            if (await condition())
            {
                return;
            }

            await Task.Delay(25);
        }

        Assert.Fail($"Timed out waiting for: {what}");
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _host.StopAsync();
        _host.Dispose();
    }
}
