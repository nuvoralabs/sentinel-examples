# Sample 017 — Config as Code

Companion to **[Article 017 — Config as code](https://sentinel.nuvoralabs.com/articles/config-as-code/)**.

The host's realm, organization, roles (with grants) and OIDC clients are **declared** in
[`clinic.sentinel.yaml`](ConfigAsCode.Api/clinic.sentinel.yaml) and applied at boot by
`DeclarativeConfigApplier` — idempotently, through the same public store ports the admin
API uses:

- **Matched by natural key** (realm/org/role keys, `clientId`), created when missing,
  updated field-by-field when drifted. Re-applying the unchanged file is a **strict no-op**.
- **Never deleted.** Absence from the file is not deletion; a section's `prune:` flag makes
  the report say `WouldPrune … refuses to auto-delete` and nothing else happens.
- **Secrets stay out of the file** — `secretRef` names an environment variable; an
  unresolvable ref skips that entry with a warning instead of blanking a stored secret.
- **Fail-closed boot**: per-entry apply errors abort startup — silently unapplied config is
  how drift starts.
- A typo'd section (`reallms:`) fails parsing outright in both YAML and JSON.

The Sentinel **reference server** runs this exact flow at boot (`SENTINEL_CONFIG`), then
first-run bootstrap prints a single-use **admin invitation link** to stdout — the article
walks through it.

## Run it

```bash
export CLINIC_SECRET_PARTNER_PORTAL=dev-only-portal-secret
dotnet run --project samples/017-config-as-code/ConfigAsCode.Api

# 1) What the boot apply created
curl -s localhost:5000/config/state | jq

# 2) Re-apply the bundled file — a strict no-op
curl -s localhost:5000/config/apply -H 'content-type: application/json' -d '{}' | jq '{isNoOp, creates, updates}'

# 3) Preview a drift without writing (dry run)
curl -s localhost:5000/config/apply -H 'content-type: application/json' -d '{
  "dryRun": true,
  "yaml": "version: 1\nrealms:\n  - key: clinic\n    displayName: Clinic (renamed)\n"
}' | jq .entries

# 4) A typo fails the apply instead of configuring nothing
curl -si localhost:5000/config/apply -H 'content-type: application/json' \
  -d '{"yaml":"version: 1\nreallms: []\n"}' | head -1   # 400
```

## Test it

```bash
dotnet test samples/017-config-as-code/ConfigAsCode.Api.Tests
```

> Requires the **.NET 10 SDK**. No Docker/database needed — the applier writes to in-memory
> stores; swapping in `AddSentinelEfCoreStores` is the only change for persistence.
