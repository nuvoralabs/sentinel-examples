using Nuvora.Nexus.Sentinel.Webhooks;

namespace Hooks.Api;

/// <summary>One delivery the receiver accepted, after signature verification.</summary>
public sealed record AcceptedDelivery(string DeliveryId, string EventKind, string Body);

/// <summary>
/// The consuming side of the contract — what YOUR app writes. It follows the receiver
/// recipe to the letter: read the exact bytes, verify the HMAC with
/// <see cref="WebhookSignature.Verify"/>, deduplicate on the delivery id, and answer 2xx
/// only when the delivery is safely accepted. <see cref="FailNext"/> simulates an outage so
/// the dispatcher's retry/backoff loop is observable.
/// </summary>
public sealed class BillingReceiver
{
    private readonly Lock _gate = new();
    private readonly List<AcceptedDelivery> _accepted = [];
    private readonly HashSet<string> _seen = [];
    private int _failNext;

    /// <summary>The endpoint's whsec_ secret — captured ONCE, at subscription time.</summary>
    public string? Secret { get; set; }

    public IReadOnlyList<AcceptedDelivery> Accepted
    {
        get
        {
            lock (_gate)
            {
                return _accepted.ToList();
            }
        }
    }

    public int TotalRequests { get; private set; }

    /// <summary>Answer 500 to the next <paramref name="count"/> deliveries (simulated outage).</summary>
    public void FailNext(int count)
    {
        lock (_gate)
        {
            _failNext = count;
        }
    }

    /// <summary>The receiver recipe. Returns the HTTP status to answer.</summary>
    public int Record(string signatureHeader, string eventKind, string deliveryId, string body)
    {
        lock (_gate)
        {
            TotalRequests++;

            if (_failNext > 0)
            {
                _failNext--;
                return StatusCodes.Status500InternalServerError; // outage: dispatcher will retry
            }

            // 1-5 of the recipe: exact bytes, parse t/v1, tolerance window, HMAC-SHA256 over
            // "{t}.{body}", constant-time compare — all inside Verify.
            if (Secret is null
                || !WebhookSignature.Verify(Secret, signatureHeader, body, DateTimeOffset.UtcNow))
            {
                return StatusCodes.Status400BadRequest;
            }

            // Deduplicate on X-Sentinel-Delivery: retries re-send the same delivery id.
            if (_seen.Add(deliveryId))
            {
                _accepted.Add(new AcceptedDelivery(deliveryId, eventKind, body));
            }

            return StatusCodes.Status204NoContent;
        }
    }
}
