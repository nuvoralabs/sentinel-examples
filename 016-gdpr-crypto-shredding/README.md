# Sample 016 — GDPR Crypto-Shredding

Companion to **[Article 016 — GDPR & crypto-shredding](https://sentinel.nuvoralabs.com/articles/gdpr-crypto-shredding/)**.

The privacy surface end to end, in-memory:

- **Export** — `POST /sentinel-admin/privacy/export/{userId}` returns the Art. 20 bundle
  (identity, org memberships, sessions, security events, linked identities). Fenced to
  `sentinel:global:manage`; a non-admin gets 403, never a partial bundle.
- **Erase** — `POST /sentinel-admin/privacy/erase/{userId}` with `{"confirm":"erase"}`:
  crypto-shred (destroy the subject's AES-256 key) → revoke sessions → delete
  authenticators/links → anonymize the user row (`erased+<id>@invalid`) → redact both
  ledgers. The **admin audit chain still verifies** afterwards — redaction nulls payloads,
  never digests or hashes.
- **The shredder as an app primitive** — `POST /notes` stores text encrypted under the
  caller's subject key via `ISentinelCryptoShredder`; after erasure the ciphertext is
  permanently `[unrecoverable]` without touching the notes table.
- **Retention** — `POST /demo/retention/sweep` runs the same `RetentionService.RunOnceAsync`
  the daily background sweep (`AddSentinelRetentionService`) calls: old security events are
  deleted, old audit *payloads* are redacted, audit rows never die.

Seeded users (password for both: `personal-data-demo-password`):

| Email | Role |
|---|---|
| `dpo@clinic.sample` | data-protection officer (`sentinel:global:manage`) |
| `jane@clinic.sample` | ordinary data subject |

## Run it

```bash
dotnet run --project samples/016-gdpr-crypto-shredding/PersonalData.Api

DPO=$(curl -s localhost:5000/auth/login -H 'content-type: application/json' \
  -d '{"email":"dpo@clinic.sample","password":"personal-data-demo-password"}' | jq -r .accessToken)
JANE=$(curl -s localhost:5000/auth/login -H 'content-type: application/json' \
  -d '{"email":"jane@clinic.sample","password":"personal-data-demo-password"}' | jq -r .accessToken)

# 1) Jane stores PII — encrypted under HER key
curl -s localhost:5000/notes -H "Authorization: Bearer $JANE" -H 'content-type: application/json' \
  -d '{"text":"allergy: penicillin"}' | jq

# 2) Export the Art. 20 bundle
curl -s -X POST localhost:5000/sentinel-admin/privacy/export/00000016-0000-0000-0000-00000000000b \
  -H "Authorization: Bearer $DPO" | jq '{email:.user.email, sessions:(.sessions|length), events:(.securityEvents|length)}'

# 3) Erase — the confirmation body is mandatory (irreversible)
curl -s -X POST localhost:5000/sentinel-admin/privacy/erase/00000016-0000-0000-0000-00000000000b \
  -H "Authorization: Bearer $DPO" -H 'content-type: application/json' -d '{"confirm":"erase"}' | jq

# 4) The note is gone forever (the key was shredded, the ciphertext remains)
curl -s localhost:5000/demo/notes/00000016-0000-0000-0000-00000000000b | jq

# 5) Jane can no longer log in — and the audit chain STILL verifies
curl -si localhost:5000/auth/login -H 'content-type: application/json' \
  -d '{"email":"jane@clinic.sample","password":"personal-data-demo-password"}' | head -1   # 401
curl -s localhost:5000/demo/audit/verify | jq                                             # null = intact
```

## Test it

```bash
dotnet test samples/016-gdpr-crypto-shredding/PersonalData.Api.Tests
```

> Requires the **.NET 10 SDK**. No Docker/database needed — in-memory stores and key store,
> ephemeral dev signing keys (explicit opt-in). Production swaps in `AddSentinelEfCoreStores`,
> which persists the subject keys, the EF `IPersonalDataSource` and the retention store.
