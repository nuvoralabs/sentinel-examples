# Sample 004 — Passkeys

Companion to **[Article 004 — Passkeys](https://sentinel.nuvoralabs.com/articles/passkeys/)**.

The WebAuthn round trip, passkeys-first: `AddSentinelPasskeys` +
`MapSentinelPasskeys` mount the whole ceremony surface under `/auth/passkey` —

| Endpoint | Purpose |
|---|---|
| `POST /auth/passkey/register/options` | start registration (authenticated: a passkey is added to an existing account) |
| `POST /auth/passkey/register` | verify the attestation, store the credential |
| `GET/POST /auth/passkey/login/options` | start a **usernameless** login ceremony (no `allowCredentials` — nothing leaks) |
| `POST /auth/passkey/login` | verify the assertion, mint a full session — no password anywhere |
| `POST /auth/passkey/mfa/verify` | passkey as the second factor for a password login |
| `GET /auth/passkey/`, `DELETE /auth/passkey/{id}` | credential management |

The seeded user (`sam@passkeys.example` / `passwords-are-so-2010`) starts with a password only;
the walk is password login → register passkey → passwordless from then on. Registration uses
attestation `none`; a user-verifying passkey counts as a phishing-resistant first factor, and
sign-count regressions (cloned authenticators) are rejected with a
`passkey.signcount_regression` security event.

## Run it

Ceremonies need a WebAuthn client — in a browser the `options` JSON goes straight into
`navigator.credentials.create()` / `.get()`. The option endpoints are curl-able:

```bash
dotnet run --project samples/004-passkeys/Passkeys.Api

# Password login (the seeded first factor)
AT=$(curl -s localhost:5000/auth/login -H 'content-type: application/json' \
  -d '{"email":"sam@passkeys.example","password":"passwords-are-so-2010"}' | jq -r .accessToken)

# Registration options: raw WebAuthn creation options for navigator.credentials.create()
curl -s -X POST localhost:5000/auth/passkey/register/options -H "Authorization: Bearer $AT" \
  -H 'content-type: application/json' -d '{}' | jq

# Usernameless login options: unauthenticated, empty allowCredentials by design
curl -s localhost:5000/auth/passkey/login/options | jq

# List the account's registered passkeys
curl -s localhost:5000/auth/passkey/ -H "Authorization: Bearer $AT" | jq
```

The tests complete the ceremonies end to end with a **software authenticator**
(`FakeAuthenticator`, copied from the library's own HTTP test suite): real ECDSA P-256
signatures through the genuine Fido2NetLib verification path — rpIdHash, origin, challenge,
signature, and sign-count checks included.

## Test it

```bash
dotnet test samples/004-passkeys/Passkeys.Api.Tests
```

> Requires the **.NET 10 SDK**. No Docker/database needed.
