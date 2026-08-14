# Sample 013 — Abuse Protection Layers

Companion to **[Article 013 — Four layers before the database](https://sentinel.nuvoralabs.com/articles/abuse-protection-layers/)**.

Every `POST /auth/login` passes an **abuse gate** before Sentinel even looks up the user:
per-IP rate limit → per-IP-and-account → account lockout → credential-stuffing heuristics.
This sample tunes `SentinelAbuseOptions` down to curl-able thresholds, plugs in an offline
captcha verifier so the `captcha_required` band is walkable, and pins each layer, the
solved-captcha path, and both outage fail modes in tests.

| | |
|---|---|
| Users | `alice@gate.sample`, `bob@gate.sample` / `sample-password-1!` |
| Captcha answer | `let-me-in` (demo verifier; site key `demo-site-key`) |
| Demo thresholds | per-IP 10/5m · per-IP+account 8/15m · lockout 5 fails/15m · stuffing 20 distinct/10m |

> The app trusts an `X-Demo-Ip` header so one machine can play many clients. Demo only —
> a real deployment derives the address from the connection or configured forwarded headers.

## Run it

```bash
dotnet run --project samples/013-abuse-protection-layers/AbuseGate.Api

# Hammer the login until the captcha band opens (per-IP threshold 10 × factor 0.5 ⇒ attempt 6)
for i in $(seq 1 6); do
  curl -s -o /dev/null -w "%{http_code} " localhost:5000/auth/login \
    -H 'content-type: application/json' -H 'X-Demo-Ip: 203.0.113.9' \
    -d '{"email":"alice@gate.sample","password":"wrong"}'
done; echo
# 401 401 401 401 401 429

# The 429 names its price — and carries the public site key:
curl -s localhost:5000/auth/login -H 'content-type: application/json' -H 'X-Demo-Ip: 203.0.113.9' \
  -d '{"email":"alice@gate.sample","password":"sample-password-1!"}' | jq '{error, siteKey}'
# { "error": "captcha_required", "siteKey": "demo-site-key" }

# A solved captcha rides the same request, and the human proceeds:
curl -s localhost:5000/auth/login -H 'content-type: application/json' -H 'X-Demo-Ip: 203.0.113.9' \
  -d '{"email":"alice@gate.sample","password":"sample-password-1!","captchaToken":"let-me-in"}' \
  | jq .status
# "ok"

# A different IP was never bothered:
curl -s localhost:5000/auth/login -H 'content-type: application/json' -H 'X-Demo-Ip: 198.51.100.7' \
  -d '{"email":"bob@gate.sample","password":"sample-password-1!"}' | jq .status
# "ok"
```

## Test it

```bash
dotnet test samples/013-abuse-protection-layers/AbuseGate.Api.Tests
```

> Requires the **.NET 10 SDK**. No Docker/database needed.
