# Sample 006 — OIDC Server (SSO for a Partner App)

Sentinel as a standards-compliant **OAuth2/OIDC authorization server**, plus a
second app that signs in against it — the smallest complete SSO pair:

| Project | Role |
|---|---|
| `IdP.Api` | Sentinel AS: `AddSentinelOidcServer()` + `MapSentinelOidc()` + `MapSentinelAuth()` for the login session, and the **host-owned** `/login` page per the interaction contract (Sentinel ships no hosted login pages) |
| `Partner.Web` | The relying party — a plain OIDC client with **zero Sentinel references**: redirects to the authorize endpoint, exchanges code + PKCE over the back channel, calls userinfo, keeps its own session, refreshes tokens |

The dance (all endpoints from `/.well-known/openid-configuration`):

```
Partner /signin ──302──▶ IdP /oidc/authorize (code + PKCE)
                              │ unauthenticated? 302 /login?returnUrl=…
                              │ host login page → POST /auth/login → cookie session
                              ▼ re-enter authorize
Partner /callback ◀──302── redirect_uri?code=…&state=…
   │ back channel: POST /oidc/token (code + code_verifier)  → access/id/refresh tokens
   │ GET /oidc/userinfo (Bearer)                            → identity
   ▼ /me shows who signed in; POST /refresh rotates
```

Seeded: user `ada@clinic.sample` / `sample-password-1!`; public client `partner-web`
(PKCE **required**, first-party so consent is skipped per the per-client consent policy).

## Run it

```bash
# Terminal 1 — the IdP
dotnet run --project samples/006-oidc-server/IdP.Api --urls http://localhost:5006

# Terminal 2 — the partner app (defaults point at :5006)
dotnet run --project samples/006-oidc-server/Partner.Web --urls http://localhost:5007
```

Then open <http://localhost:5007/signin> in a browser: you land on the IdP's login page
(pre-filled), sign in, bounce back, and <http://localhost:5007/me> shows the identity.
`curl -X POST http://localhost:5007/refresh --cookie "partner_session=…"` exercises the
refresh grant.

## Test it

```bash
dotnet test samples/006-oidc-server/Sso.Tests
```

The tests run BOTH apps on TestServers and play the browser between them: discovery, the full
authorize → login → code → token → userinfo dance, PKCE-required and wrong-verifier rejections,
single-use codes, and the refresh grant.

> Requires the **.NET 10 SDK**. No Docker/database needed — in-memory stores, ephemeral dev
> signing keys (explicit opt-in).
