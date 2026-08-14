# Sample 012 — Tamper-Evident Audit

Companion to **[Article 012 — The audit log that notices](https://sentinel.nuvoralabs.com/articles/tamper-evident-audit/)**.

Every delegated-admin mutation appends to a **per-realm hash chain** (`AdminAuditChain`):
each entry commits to actor, action, target, time, payload digests and the previous entry's
hash. `GET /sentinel-admin/audit` re-verifies the whole chain on every read and reports
`chainIntact` / `firstBrokenSequence`. The tests play the hostile DBA — rewriting entries,
forging payloads, deleting rows — and watch the verdict flip; retention redaction
(payloads nulled, digests kept) verifiably does not break the chain.

| | |
|---|---|
| Realm admin | `rita@ledger.sample` / `sample-password-1!` (`sentinel:global:manage`) |
| Auditor | `vera@ledger.sample` / `sample-password-1!` (`sentinel:global:audit_read` only) |
| Target user | `sam@ledger.sample` (gets suspended/reactivated to generate entries) |

## Run it

```bash
dotnet run --project samples/012-tamper-evident-audit/Ledger.Api

# 1) Login as the realm admin and make two mutations
TOKEN=$(curl -s localhost:5000/auth/login -H 'content-type: application/json' \
  -d '{"email":"rita@ledger.sample","password":"sample-password-1!"}' | jq -r .accessToken)
ORG=11111111-1111-1111-1111-111111111111
SAM=$(curl -s "localhost:5000/sentinel-admin/orgs/$ORG/users" -H "Authorization: Bearer $TOKEN" \
  | jq -r '.[] | select(.email=="sam@ledger.sample") | .id')
curl -s -X POST localhost:5000/sentinel-admin/orgs/$ORG/users/$SAM/suspend    -H "Authorization: Bearer $TOKEN" > /dev/null
curl -s -X POST localhost:5000/sentinel-admin/orgs/$ORG/users/$SAM/reactivate -H "Authorization: Bearer $TOKEN" > /dev/null

# 2) Read the ledger: two linked entries, chain verified on read
curl -s 'localhost:5000/sentinel-admin/audit?fromSequence=1&limit=50' \
  -H "Authorization: Bearer $TOKEN" | jq '{chainIntact, firstBrokenSequence,
    entries: [.entries[] | {sequence, action, previousHash, entryHash}]}'

# 3) The auditor persona can read the ledger but not mutate (403 admin_scope)
AUD=$(curl -s localhost:5000/auth/login -H 'content-type: application/json' \
  -d '{"email":"vera@ledger.sample","password":"sample-password-1!"}' | jq -r .accessToken)
curl -s 'localhost:5000/sentinel-admin/audit' -H "Authorization: Bearer $AUD" | jq .chainIntact  # true
curl -si -X POST localhost:5000/sentinel-admin/orgs/$ORG/users/$SAM/suspend \
  -H "Authorization: Bearer $AUD" | head -1                                                      # 403
```

Tampering needs write access to the store, so the flip-to-`false` demonstrations live in
the tests, where the in-memory store's live entries are mutated directly.

## Test it

```bash
dotnet test samples/012-tamper-evident-audit/Ledger.Api.Tests
```

> Requires the **.NET 10 SDK**. No Docker/database needed.
