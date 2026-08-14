using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using Hooks.Api;
using Nuvora.Nexus.Sentinel.Webhooks;
using Xunit;

namespace Hooks.Api.Tests;

/// <summary>
/// The article-011 walk, as executable assertions: subscribe → signed delivery →
/// HMAC verification → retry/backoff through an outage → dead-letter when the outage
/// outlives the ladder → secret rotation.
/// </summary>
public class WebhookDeliveryTests
{
    // ---------------------------------------------------------------------------------------
    // Subscribe + receive + verify
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task A_failed_login_arrives_as_a_signed_verified_delivery()
    {
        await using var host = await HooksTestHost.CreateAsync();
        var ops = await host.LoginAsync(HooksWorld.OpsEmail);

        var endpointId = await host.SubscribeAsync(ops, "login.*");

        // The event source: a wrong-password login emits login.failed into the outbox.
        await host.Client.PostAsJsonAsync("/auth/login",
            new { email = HooksWorld.UserEmail, password = "not-the-password" });

        await HooksTestHost.WaitUntilAsync(
            async () => host.Receiver.Accepted.Any(d => d.EventKind == "login.failed"),
            "the signed login.failed delivery");

        // The receiver only accepts deliveries whose HMAC verified — reaching Accepted IS
        // the verification assertion. The payload carries the envelope contract.
        var delivery = host.Receiver.Accepted.Single(d => d.EventKind == "login.failed");
        using (var payload = JsonDocument.Parse(delivery.Body))
        {
            payload.RootElement.GetProperty("kind").GetString().Should().Be("login.failed");
            payload.RootElement.GetProperty("realmId").GetGuid().Should().Be(HooksWorld.RealmId);
        }

        // The secret was shown exactly once, at subscription: the endpoint view has none.
        var view = await host.AdminAsync(ops, HttpMethod.Get, $"/sentinel-admin/webhooks/{endpointId}");
        (await view.Content.ReadAsStringAsync()).Should().NotContain("whsec_");
    }

    // ---------------------------------------------------------------------------------------
    // The verification recipe itself (no host needed)
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Verify_accepts_the_exact_bytes_and_rejects_tampering_and_stale_timestamps()
    {
        var secret = WebhookSecrets.NewSecret();
        var now = DateTimeOffset.UtcNow;
        var t = now.ToUnixTimeSeconds();
        const string body = """{"id":"evt-1","kind":"login.failed"}""";

        var header = $"t={t},v1={WebhookSignature.ComputeV1(secret, t, body)}";

        WebhookSignature.Verify(secret, header, body, now).Should().BeTrue();

        // One changed byte in the body: the MAC no longer matches.
        WebhookSignature.Verify(secret, header, body.Replace("evt-1", "evt-2"), now)
            .Should().BeFalse("the HMAC covers the exact received bytes");

        // Replay outside the tolerance window (default 5 minutes): rejected on age alone.
        WebhookSignature.Verify(secret, header, body, now.AddMinutes(11))
            .Should().BeFalse("the timestamp inside the signature bounds replay");
    }

    // ---------------------------------------------------------------------------------------
    // Retry / backoff / dead-letter
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task An_outage_is_retried_with_the_same_delivery_id_until_the_receiver_heals()
    {
        await using var host = await HooksTestHost.CreateAsync();
        var ops = await host.LoginAsync(HooksWorld.OpsEmail);
        var endpointId = await host.SubscribeAsync(ops, "login.*");

        // The receiver 500s once, then heals; webhook.test bypasses subscription matching.
        host.Receiver.FailNext(1);
        await host.AdminAsync(ops, HttpMethod.Post, $"/sentinel-admin/webhooks/{endpointId}/test");

        await HooksTestHost.WaitUntilAsync(
            async () => host.Receiver.Accepted.Any(d => d.EventKind == "webhook.test"),
            "the retried webhook.test delivery");

        // Two HTTP attempts, one accepted delivery: the retry re-sent the SAME delivery id
        // and the receiver's dedupe absorbed it.
        host.Receiver.TotalRequests.Should().Be(2);
        host.Receiver.Accepted.Should().HaveCount(1);

        var deliveries = await host.AdminAsync(
            ops, HttpMethod.Get, $"/sentinel-admin/webhooks/{endpointId}/deliveries");
        using var json = JsonDocument.Parse(await deliveries.Content.ReadAsStringAsync());
        var item = json.RootElement.GetProperty("items")[0];
        item.GetProperty("attemptCount").GetInt32().Should().Be(2);
        item.GetProperty("deliveredAt").ValueKind.Should().NotBe(JsonValueKind.Null);
    }

    [Fact]
    public async Task An_outage_that_outlives_the_backoff_ladder_dead_letters_the_delivery()
    {
        await using var host = await HooksTestHost.CreateAsync();
        var ops = await host.LoginAsync(HooksWorld.OpsEmail);
        var endpointId = await host.SubscribeAsync(ops, "login.*");

        // The test ladder has ONE rung, so attempt 1 fails, one retry fails, then abandonment.
        host.Receiver.FailNext(10);
        await host.AdminAsync(ops, HttpMethod.Post, $"/sentinel-admin/webhooks/{endpointId}/test");

        await HooksTestHost.WaitUntilAsync(async () =>
        {
            var response = await host.AdminAsync(
                ops, HttpMethod.Get, $"/sentinel-admin/webhooks/{endpointId}/deliveries");
            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            return json.RootElement.GetProperty("items").EnumerateArray()
                .Any(d => d.GetProperty("abandoned").GetBoolean());
        }, "the delivery to be abandoned");

        var deliveries = await host.AdminAsync(
            ops, HttpMethod.Get, $"/sentinel-admin/webhooks/{endpointId}/deliveries");
        using var abandoned = JsonDocument.Parse(await deliveries.Content.ReadAsStringAsync());
        var item = abandoned.RootElement.GetProperty("items")[0];
        item.GetProperty("attemptCount").GetInt32().Should().Be(2);
        item.GetProperty("deliveredAt").ValueKind.Should().Be(JsonValueKind.Null);
        item.GetProperty("lastError").GetString().Should().Be("HTTP 500");
    }

    // ---------------------------------------------------------------------------------------
    // Secret rotation
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task After_rotation_only_the_new_secret_verifies_and_the_retry_heals_the_gap()
    {
        await using var host = await HooksTestHost.CreateAsync();
        var ops = await host.LoginAsync(HooksWorld.OpsEmail);
        var endpointId = await host.SubscribeAsync(ops, "login.*");
        var oldSecret = host.Receiver.Secret!;

        var rotate = await host.AdminAsync(
            ops, HttpMethod.Post, $"/sentinel-admin/webhooks/{endpointId}/rotate-secret");
        string newSecret;
        using (var json = JsonDocument.Parse(await rotate.Content.ReadAsStringAsync()))
        {
            newSecret = json.RootElement.GetProperty("secret").GetString()!;
        }

        newSecret.Should().StartWith("whsec_").And.NotBe(oldSecret);

        // The receiver still holds the OLD secret: the next delivery fails verification
        // (400), the dispatcher retries, and the updated receiver accepts the retry.
        await host.AdminAsync(ops, HttpMethod.Post, $"/sentinel-admin/webhooks/{endpointId}/test");
        await HooksTestHost.WaitUntilAsync(
            async () => host.Receiver.TotalRequests >= 1, "the first (still-old-secret) attempt");

        host.Receiver.Secret = newSecret;

        await HooksTestHost.WaitUntilAsync(
            async () => host.Receiver.Accepted.Any(d => d.EventKind == "webhook.test"),
            "the retried delivery to verify under the rotated secret");
    }
}
