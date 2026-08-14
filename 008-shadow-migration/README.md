# Sample 008 — Shadow Migration

Companion to **[Article 008 — Shadow Migration](https://sentinel.nuvoralabs.com/articles/shadow-migration/)**.

The migration story end to end: a legacy **ASP.NET Core Identity** database (real
Identity V3 hashes) is imported into Sentinel's EF Core stores, imported users keep
logging in with their **legacy passwords** (per-credential algorithm tags + transparent
rehash-on-login), and authorization runs in **shadow mode**: the old if-ladder stays
authoritative while Sentinel evaluates the same checks alongside, every disagreement is counted
and emitted as an `authz.shadow_divergence` event, and **cutover is gated on zero divergences**.

The demo deliberately imports an *incomplete* grant mapping (the support role may read tickets
but was never granted `tickets:global:close`) — exactly the mistake shadow mode exists to catch.

## Run it

```bash
dotnet run --project samples/008-shadow-migration/ShadowMigration.Api

# 1) Import the legacy database:
curl -s -X POST localhost:5000/migration/import | jq

# 2) Alice logs in with her LEGACY password:
TOKEN=$(curl -s -X POST localhost:5000/auth/login -H 'content-type: application/json' \
  -d '{"email":"alice@clinic.sample","password":"alices-legacy-password-1"}' | jq -r .accessToken)

# 3) Shadow mode: read agrees, close DIVERGES (legacy allows, Sentinel has no grant yet):
curl -s localhost:5000/tickets -H "Authorization: Bearer $TOKEN"                  # 200
curl -s -X POST localhost:5000/tickets/TCK-1/close -H "Authorization: Bearer $TOKEN"  # 200 (legacy decides)
curl -s localhost:5000/migration/report | jq                                      # divergences: 1

# 4) The gate holds:
curl -s -X POST localhost:5000/migration/cutover | jq                             # 409 cutover_blocked

# 5) Fix the mapping, reset the shadow window, replay, cut over:
curl -s -X POST localhost:5000/migration/grants/close-tickets
curl -s -X POST localhost:5000/migration/shadow/reset
curl -s localhost:5000/tickets -H "Authorization: Bearer $TOKEN" >/dev/null
curl -s -X POST localhost:5000/tickets/TCK-1/close -H "Authorization: Bearer $TOKEN" >/dev/null
curl -s -X POST localhost:5000/migration/cutover | jq                             # 200 — Sentinel decides alone
```

## Test it

```bash
dotnet test samples/008-shadow-migration/ShadowMigration.Api.Tests
```

> Requires the **.NET 10 SDK**. No Docker — SQLite in-memory via the real EF Core adapter.
