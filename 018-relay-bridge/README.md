# Sample 018 — The Relay Bridge

Companion to **[Article 018 — Sentinel meets Relay](https://sentinel.nuvoralabs.com/articles/relay-bridge/)**.

A [Relay](https://github.com/nuvoralabs/nuvora-nexus-relay) application whose
authentication, authorization **and** tenancy come from Sentinel — via
`Nuvora.Nexus.Sentinel.Relay`:

- `UseSentinelRelayAuthContext()` projects the Sentinel principal + permission snapshot
  onto Relay's `AuthContext` (it **replaces** `UseRelayAuthContext()` — never run both).
- `[RequirePermission("tickets:org:read")]` on a Relay command is decided by **Sentinel's
  evaluator** — wildcards match, deny overrides allow, default is deny — not by string
  equality against a claim list. `[RequirePolicy("sentinel")]` runs the same check
  per-dispatch against the live snapshot.
- `AddSentinelRelayTenancy()` maps the token's org claim onto Relay's `TenantContext`:
  the Sentinel org **is** the Relay tenant, no mapping table.

Seeded agents (password for all: `relay-bridge-demo-password`), all members of one org:

| Email | Grants | Outcome |
|---|---|---|
| `rita@support.sample` | `tickets:*:*` | read ✓ close ✓ (wildcard, engine-decided) |
| `ivan@support.sample` | `tickets:org:read` | read ✓ close ✗ (default deny) |
| `nadia@support.sample` | `tickets:*:*` + **deny** `tickets:org:close` | read ✓ close ✗ (deny overrides) |

## Run it

```bash
dotnet run --project samples/018-relay-bridge/RelayBridge.Api

RITA=$(curl -s localhost:5000/auth/login -H 'content-type: application/json' \
  -d '{"email":"rita@support.sample","password":"relay-bridge-demo-password"}' | jq -r .accessToken)

# The handler observes the Sentinel subject as AuthContext.UserId and the org as the tenant
curl -s -X POST localhost:5000/tickets/read  -H "Authorization: Bearer $RITA" | jq
curl -s -X POST localhost:5000/tickets/close -H "Authorization: Bearer $RITA" | jq

# Nadia's wildcard allows read — but her explicit deny wins on close
NADIA=$(curl -s localhost:5000/auth/login -H 'content-type: application/json' \
  -d '{"email":"nadia@support.sample","password":"relay-bridge-demo-password"}' | jq -r .accessToken)
curl -si -X POST localhost:5000/tickets/close -H "Authorization: Bearer $NADIA" | head -1   # 403
```

## Test it

```bash
dotnet test samples/018-relay-bridge/RelayBridge.Api.Tests
```

> Requires the **.NET 10 SDK**. No Docker/database needed. In the monorepo the Relay stack
> builds from the sibling `nuvora-nexus-relay` checkout (transitively through the bridge
> package); in the public examples mirror it comes from the matching NuGet packages.
