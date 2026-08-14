# Sample 015 — Break-Glass & Impersonation

Companion to **[Article 015 — Break-glass & impersonation](https://sentinel.nuvoralabs.com/articles/break-glass-and-impersonation/)**.

Admin governance in one minimal host:

- **Impersonation** — an admin holding `sentinel:global:impersonate` acts as a user on a
  signed, time-boxed token carrying the RFC 8693-style `act` claim; `/profile/me` answers
  with an impersonation **banner** (`{ actorId, expiresAt }`) so the UI can't hide it.
  Flip consent mode on and starting only *requests* — the target gets a single-purpose
  approval token by mail and the access token exists only after approval.
- **Break-glass** — `root@clinic.sample` is an ordinary user flagged with the
  `sentinel:break_glass` attribute and a deliberately broad `*:*:*` grant. The
  `BreakGlassCappingDataSource` decorator intersects its grants with the policy's capped
  patterns (`sentinel:global:*`, `records:global:read`) at snapshot-build time, every
  login alerts the operators + stamps `breakglass.rotation_required` on the ledger, and a
  **drill health check** degrades `/health` when nobody has drilled in 90 days.

Seeded actors (password for all: `governance-demo-password`):

| Email | Role |
|---|---|
| `admin@clinic.sample` | may impersonate (`sentinel:global:impersonate`, `sentinel:global:manage`) |
| `taylor@clinic.sample` | ordinary user (`records:org:read`) |
| `root@clinic.sample` | break-glass account (`*:*:*`, capped) |

## Run it

```bash
dotnet run --project samples/015-break-glass-and-impersonation/Governance.Api

# 1) Log in as the admin
ADMIN=$(curl -s localhost:5000/auth/login -H 'content-type: application/json' \
  -d '{"email":"admin@clinic.sample","password":"governance-demo-password"}' | jq -r .accessToken)

# 2) Start impersonating Taylor (fixed id, reason is mandatory — it goes on the audit chain)
ACT=$(curl -s localhost:5000/sentinel-admin/impersonation/start \
  -H "Authorization: Bearer $ADMIN" -H 'content-type: application/json' \
  -d '{"targetUserId":"00000015-0000-0000-0000-00000000000b","reason":"support case 42"}' | jq -r .accessToken)

# 3) The act token IS Taylor — with the banner
curl -s localhost:5000/profile/me -H "Authorization: Bearer $ACT" | jq .impersonation

# 4) End it
curl -s -X POST localhost:5000/sentinel-admin/impersonation/end -H "Authorization: Bearer $ADMIN" | jq .status

# 5) Break-glass: the login itself rings the alarms (watch the MAIL log lines)
ROOT=$(curl -s localhost:5000/auth/login -H 'content-type: application/json' \
  -d '{"email":"root@clinic.sample","password":"governance-demo-password"}' | jq -r .accessToken)
curl -s localhost:5000/profile/permissions -H "Authorization: Bearer $ROOT" | jq .patterns   # capped, not *:*:*

# 6) The drill health check: Degraded until someone drills
curl -s localhost:5000/health
curl -s -X POST localhost:5000/sentinel-admin/break-glass/drill-login-marker -H "Authorization: Bearer $ROOT" | jq
curl -s localhost:5000/health
```

## Test it

```bash
dotnet test samples/015-break-glass-and-impersonation/Governance.Api.Tests
```

> Requires the **.NET 10 SDK**. No Docker/database needed — in-memory stores, ephemeral dev
> signing keys (explicit opt-in), alert mails recorded in-process.
