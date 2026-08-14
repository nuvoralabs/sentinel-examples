# Sample 001 — First Login

Companion to **[Article 001 — First Login](https://sentinel.nuvoralabs.com/articles/first-login/)**.

A digital-clinic minimal API that **embeds Sentinel**: password + TOTP login
over the **httpOnly-cookie transport** with CSRF double-submit, and one
protected app endpoint. No database — the sample opts into Sentinel's in-memory stores
and seeds one clinician at startup:

| | |
|---|---|
| Email | `dr.riley@clinic.example` |
| Password | `correct-horse-battery-staple` |
| TOTP secret | `JBSWY3DPEHPK3PXP` (base32 — add it to any authenticator app) |

The flow: `POST /auth/login` answers `mfa_required` + a single-purpose pending token;
`POST /auth/mfa/verify` with the current TOTP code completes it and sets three cookies —
httpOnly `sentinel_at` / `sentinel_rt` and the script-readable `sentinel_csrf` whose value must
be echoed in `X-Sentinel-Csrf` on every state-changing request.

## Run it

```bash
dotnet run --project samples/001-first-login/Clinic.Login.Api

# 1) First factor: correct password ⇒ mfa_required + a pending token, no session yet
PENDING=$(curl -s localhost:5000/auth/login -H 'content-type: application/json' \
  -d '{"email":"dr.riley@clinic.example","password":"correct-horse-battery-staple"}' \
  | jq -r .mfaPendingToken)

# 2) Second factor: current TOTP code ⇒ cookie session (oathtool, or read your authenticator app)
curl -si -c cookies.txt localhost:5000/auth/mfa/verify -H 'content-type: application/json' \
  -d "{\"mfaPendingToken\":\"$PENDING\",\"code\":\"$(oathtool -b --totp JBSWY3DPEHPK3PXP)\",\"kind\":\"totp\"}"

# 3) The cookie session opens the protected endpoint (and /profile/me, /profile/sessions, ...)
curl -i -b cookies.txt localhost:5000/clinic/dashboard                                # 200
curl -i localhost:5000/clinic/dashboard                                               # 401

# 4) State-changing requests need the CSRF double-submit header
curl -i -X POST -b cookies.txt localhost:5000/auth/logout                             # 401
CSRF=$(awk '$6=="sentinel_csrf" {print $7}' cookies.txt)
curl -i -X POST -b cookies.txt -H "X-Sentinel-Csrf: $CSRF" localhost:5000/auth/logout # 204
```

> The auth cookies are set `Secure`; curl ≥ 8.6 sends them to `localhost` over plain http. On
> older curl, replay the `Set-Cookie` values by hand with `-H 'Cookie: …'`.

## Test it

```bash
dotnet test samples/001-first-login/Clinic.Login.Api.Tests
```

> Requires the **.NET 10 SDK**. No Docker/database needed.
