# Sample 014 — Adaptive Risk Engine

Companion to **[Article 014 — Risk, scored in the open](https://sentinel.nuvoralabs.com/articles/adaptive-risk-engine/)**.

Every password login is scored by **deterministic, explainable signals** — new device (30),
impossible travel (40), IP reputation (50), velocity (25), plus this app's own ten-line
`WatchlistSignal` (40). Default thresholds: score **≥ 40** demands MFA step-up — falling
back to **email OTP** for users without TOTP — and **≥ 80** blocks, indistinguishable from
a wrong password. A first-seen device triggers a security-alert mail even when the login
sails through. Mails print to the console (demo mailer).

| | |
|---|---|
| Normal user | `nora@stepup.sample` / `sample-password-1!` (no TOTP) |
| Watchlisted user | `victor@stepup.sample` / `sample-password-1!` |
| Listed (bad) IP | `185.220.101.7` |

> The app trusts an `X-Demo-Ip` header so one machine can play many clients. Demo only.

## Run it

```bash
dotnet run --project samples/014-adaptive-risk-engine/StepUp.Api

# Familiar login: score 0, straight through
curl -s localhost:5000/auth/login -H 'content-type: application/json' \
  -d '{"email":"nora@stepup.sample","password":"sample-password-1!"}' | jq .status   # "ok"

# New device: 30 points — no step-up, but watch the console: a security_alert mail fires
curl -s localhost:5000/auth/login -H 'content-type: application/json' \
  -d '{"email":"nora@stepup.sample","password":"sample-password-1!","deviceFingerprint":"fp-laptop"}' \
  | jq .status                                                                       # "ok"

# Listed IP: 50 points ⇒ step-up; no TOTP enrolled ⇒ email-OTP fallback
curl -s localhost:5000/auth/login -H 'content-type: application/json' -H 'X-Demo-Ip: 185.220.101.7' \
  -d '{"email":"nora@stepup.sample","password":"sample-password-1!"}' | jq
# { "status": "mfa_required", "factor": "email_otp", "mfaPendingToken": "…" }
# → the 6-digit code is in the console ([mail] kind=email_otp … code=NNNNNN)
curl -s localhost:5000/auth/mfa/verify -H 'content-type: application/json' \
  -d '{"mfaPendingToken":"…","code":"NNNNNN","kind":"email_otp"}' | jq .status       # "ok"

# Listed IP + new device: 50 + 30 = 80 ⇒ Block — the same 401 as a wrong password
curl -si localhost:5000/auth/login -H 'content-type: application/json' -H 'X-Demo-Ip: 185.220.101.7' \
  -d '{"email":"nora@stepup.sample","password":"sample-password-1!","deviceFingerprint":"fp-fresh"}' \
  | head -1                                                                          # 401
```

## Test it

```bash
dotnet test samples/014-adaptive-risk-engine/StepUp.Api.Tests
```

> Requires the **.NET 10 SDK**. No Docker/database needed.
