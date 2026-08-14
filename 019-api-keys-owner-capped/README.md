# Sample 019 — Owner-Capped API Keys

Companion to **[Article 019 — API keys, owner-capped](https://sentinel.nuvoralabs.com/articles/api-keys-owner-capped/)**.

Personal automation credentials done right: Maya mints an `snt_` API key scoped to
`reports:org:*`, and the key's effective permissions are **her current grants ∩ the key's
scopes, recomputed at every use**:

- **The token is returned once** — `snt_` + 43 base64url chars (256 bits); only its SHA-256
  hash is stored, the 12-char prefix is kept for display.
- **Denies are preserved unconditionally** — Maya's explicit deny on `reports:org:purge`
  blocks the key even though the scope covers it.
- **Scopes never add authority** — a `*:*:*` scope still yields only Maya's slice.
- **Demotion shrinks keys instantly** — demote Maya and every key she owns loses the same
  reach on its next request; nothing on the key rows changes.
- **Same handler chain** — the `snt_` prefix routes the credential inside the one Sentinel
  authentication scheme (`Bearer snt_…` or a bare header value); revoked, expired and
  unknown keys all fail with the same opaque 401.
- The key's principal is the **credential** (`kind: ApiKey`, `subjectId` = key id) with
  `ownerUserId` riding along — audit lines name both.

The key *management* endpoints (`POST/GET /keys`, `POST /keys/{id}/revoke`) are
host-authored: the library ships `MachineAuthService` and the handler-chain support; the
HTTP shape is yours.

## Run it

```bash
dotnet run --project samples/019-api-keys-owner-capped/MachineKeys.Api

MAYA=$(curl -s localhost:5000/auth/login -H 'content-type: application/json' \
  -d '{"email":"maya@robotics.sample","password":"machine-keys-demo-password"}' | jq -r .accessToken)

# 1) Mint a key scoped to reports — the token appears in this response and nowhere else
KEY=$(curl -s localhost:5000/keys -H "Authorization: Bearer $MAYA" -H 'content-type: application/json' \
  -d '{"scopes":["reports:org:*"]}' | jq -r .token)

# 2) The key reads reports, but billing is capped away and purge is denied
curl -s  localhost:5000/reports -H "Authorization: Bearer $KEY" | jq
curl -si localhost:5000/billing -H "Authorization: Bearer $KEY" | head -1                 # 403
curl -si -X POST localhost:5000/reports/purge -H "Authorization: Bearer $KEY" | head -1   # 403 (owner deny)

# 3) Demote Maya — the SAME key shrinks on its next use
curl -s -X POST localhost:5000/demo/demote-owner | jq
curl -si localhost:5000/reports/export -H "Authorization: Bearer $KEY" | head -1          # 403 now
curl -s  localhost:5000/reports        -H "Authorization: Bearer $KEY" | jq               # still 200
```

## Test it

```bash
dotnet test samples/019-api-keys-owner-capped/MachineKeys.Api.Tests
```

> Requires the **.NET 10 SDK**. No Docker/database needed — in-memory identity and machine
> stores, ephemeral dev signing keys (explicit opt-in).
