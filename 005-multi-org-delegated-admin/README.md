# Sample 005 — Multi-Org & Delegated Admin

A minimal API embedding Sentinel with one realm and two organizations. It shows
the three behaviors that make multi-tenancy real rather than a column on a table:

| Behavior | Where |
|---|---|
| Org context selected **at token mint** (`org` claim), snapshots per (user, org) | `POST /auth/login` with `organizationId` |
| Org switch re-mints a token **without re-authentication** | `POST /auth/org/switch` (built into `MapSentinelAuth()`) |
| Delegated admin fenced **per resource in the domain layer** | `MapSentinelAdmin()` under `/sentinel-admin` |

Seeded world (password `sample-password-1!` for everyone):

| User | Member of | Grants |
|---|---|---|
| `diana@acme.sample` | Acme | `sentinel:org:manage` scoped to Acme (org admin) |
| `rita@realm.sample` | — | `sentinel:global:manage` (realm admin) |
| `mara@both.sample` | Acme + Globex | `reports:org:read` scoped to Acme only |

`GET /reports` answers from the per-(user, org) snapshot: mara gets 200 with an Acme-context
token and 403 after switching the same session to Globex — same user, same session, different
org context.

## Run it

```bash
dotnet run --project samples/005-multi-org-delegated-admin/MultiOrg.Api

# Acme-context token for mara (org selected at mint)
TOKEN=$(curl -s localhost:5000/auth/login -H 'content-type: application/json' \
  -d '{"email":"mara@both.sample","password":"sample-password-1!","organizationId":"11111111-1111-1111-1111-111111111111"}' \
  | jq -r .accessToken)

curl -i localhost:5000/reports -H "Authorization: Bearer $TOKEN"          # 200

# Switch the session to Globex — new token, no re-authentication.
# Built into MapSentinelAuth(): membership re-checked against the live store, the session
# repointed, and the refresh-token family rotated into the new org context.
TOKEN2=$(curl -s localhost:5000/auth/org/switch -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"organizationId":"22222222-2222-2222-2222-222222222222"}' | jq -r .accessToken)

curl -i localhost:5000/reports -H "Authorization: Bearer $TOKEN2"         # 403

# Delegated admin fencing: diana manages Acme, Globex is structurally denied
ADMIN=$(curl -s localhost:5000/auth/login -H 'content-type: application/json' \
  -d '{"email":"diana@acme.sample","password":"sample-password-1!"}' | jq -r .accessToken)
curl -i localhost:5000/sentinel-admin/orgs/11111111-1111-1111-1111-111111111111/users \
  -H "Authorization: Bearer $ADMIN"                                       # 200
curl -i localhost:5000/sentinel-admin/orgs/22222222-2222-2222-2222-222222222222/users \
  -H "Authorization: Bearer $ADMIN"                                       # 403 admin_scope
```

## Test it

```bash
dotnet test samples/005-multi-org-delegated-admin/MultiOrg.Api.Tests
```

> Requires the **.NET 10 SDK**. No Docker/database needed — in-memory stores, ephemeral dev
> signing keys (explicit opt-in).
