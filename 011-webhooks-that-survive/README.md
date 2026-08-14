# Sample 011 — Webhooks That Survive

Companion to **[Article 011 — Webhooks that survive](https://sentinel.nuvoralabs.com/articles/webhooks-that-survive/)**.

One app that embeds Sentinel and plays **both sides of the webhook contract**: it
subscribes over `/sentinel-admin/webhooks`, emits real security events (`login.failed`),
and receives the HMAC-signed deliveries at its own `/billing/events` endpoint — verifying
each one with `WebhookSignature.Verify`, deduplicating on the delivery id, and (on demand)
failing so the dispatcher's retry/backoff ladder becomes visible.

| | |
|---|---|
| Ops admin | `ops@hooks.sample` / `sample-password-1!` (`sentinel:global:manage`) |
| Ordinary user | `dana@hooks.sample` / `sample-password-1!` (her failed logins are the events) |
| Demo retry ladder | 5s, 15s (production default: 1m, 5m, 30m, 2h, 12h — then dead-letter) |

## Run it

```bash
dotnet run --project samples/011-webhooks-that-survive/Hooks.Api

# 1) Login as ops and subscribe /billing/events to login.* (the secret is shown ONCE)
TOKEN=$(curl -s localhost:5000/auth/login -H 'content-type: application/json' \
  -d '{"email":"ops@hooks.sample","password":"sample-password-1!"}' | jq -r .accessToken)
SUB=$(curl -s localhost:5000/sentinel-admin/webhooks/ -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"url":"http://localhost:5000/billing/events","eventKinds":["login.*"]}')
ID=$(echo $SUB | jq -r .endpoint.id)

# 2) Hand the whsec_ secret to the receiver (an external receiver gets it via config)
curl -s -X POST localhost:5000/billing/secret -H 'content-type: application/json' \
  -d "{\"secret\":$(echo $SUB | jq .secret)}"

# 3) Produce an event: a wrong-password login emits login.failed
curl -s localhost:5000/auth/login -H 'content-type: application/json' \
  -d '{"email":"dana@hooks.sample","password":"wrong"}' > /dev/null

# 4) Within ~1s the signed delivery lands, verifies, and shows up here
curl -s localhost:5000/billing/received | jq

# 5) Delivery log — attempts, backoff timing, dead-letter state
curl -s localhost:5000/sentinel-admin/webhooks/$ID/deliveries -H "Authorization: Bearer $TOKEN" | jq
```

The failing-then-healing outage, the same-delivery-id retries and the dead-letter path are
pinned deterministically by the tests.

## Test it

```bash
dotnet test samples/011-webhooks-that-survive/Hooks.Api.Tests
```

> Requires the **.NET 10 SDK**. No Docker/database needed.
