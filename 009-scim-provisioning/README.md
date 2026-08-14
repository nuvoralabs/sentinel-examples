# Sample 009 — SCIM Provisioning

Companion to **[Article 009 — SCIM provisioning](https://sentinel.nuvoralabs.com/articles/scim-provisioning/)**.

A minimal host that serves Sentinel's **SCIM 2.0 provisioning surface**: Users + Groups
CRUD under `/scim/v2`, authenticated by per-organization `sct_` bearer tokens. Two orgs,
two tokens — each corporate IdP can only ever provision into its own org. No database,
no login stack, no signing keys: SCIM is standalone (`AddSentinelScim()` + `MapSentinelScim()`).

| | |
|---|---|
| Realm | `00000000-…-0001` |
| Org A | Acme Clinic (`11111111-…`) — token `acme-idp provisioning` |
| Org B | Globex Health (`22222222-…`) — token `globex-idp provisioning` |
| Pre-existing user | `ada@acme.sample` (Acme, never SCIM-provisioned — the 409 demo) |

The app mints both tokens at startup and prints them **once** (only the SHA-256 digest is
stored — a real host hands them to the IdP operator over a secret channel, never a log).

## Run it

```bash
dotnet run --project samples/009-scim-provisioning/Provisioning.Api
# copy the printed tokens:
ACME=sct_…
GLOBEX=sct_…

# Provision a user into Acme (Okta/Azure-AD shaped request)
curl -s localhost:5000/scim/v2/Users -H "Authorization: Bearer $ACME" \
  -H 'content-type: application/scim+json' \
  -d '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
       "userName":"grace@acme.sample","displayName":"Grace Hopper","externalId":"okta|00u1"}' | jq
ID=… # the returned "id"

# Filter (the supported eq subset), then soft-delete and observe active:false
curl -s "localhost:5000/scim/v2/Users?filter=userName%20eq%20%22grace@acme.sample%22" \
  -H "Authorization: Bearer $ACME" | jq .totalResults                       # 1
curl -si -X DELETE localhost:5000/scim/v2/Users/$ID -H "Authorization: Bearer $ACME"  # 204
curl -s localhost:5000/scim/v2/Users/$ID -H "Authorization: Bearer $ACME" | jq .active # false

# Org isolation: the same id under Globex's token is 404, not 403
curl -si localhost:5000/scim/v2/Users/$ID -H "Authorization: Bearer $GLOBEX"          # 404

# Realm-wide userName uniqueness: Globex cannot capture ada@acme.sample
curl -si localhost:5000/scim/v2/Users -H "Authorization: Bearer $GLOBEX" \
  -H 'content-type: application/scim+json' \
  -d '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"ada@acme.sample"}' # 409 uniqueness
```

## Test it

```bash
dotnet test samples/009-scim-provisioning/Provisioning.Api.Tests
```

> Requires the **.NET 10 SDK**. No Docker/database needed.
