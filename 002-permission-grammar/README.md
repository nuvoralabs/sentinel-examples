# Sample 002 — Permission Grammar

Companion to **[Article 002 — Permission Grammar](https://sentinel.nuvoralabs.com/articles/permission-grammar/)**.

The authorization engine with nothing else around it: no login, no tokens, no stores — just
`Nuvora.Nexus.Sentinel.Core`'s grammar and the **single-path evaluator** behind
two endpoints. A hardcoded grant catalog (`GrammarDemo.cs`) exercises every grammar construct:

| Persona | Grant | Construct |
|---|---|---|
| `dr-adams` | `records:org:*` allow | per-segment wildcard |
| `dr-adams` | `records:org:export` **deny** | deny-overrides (beats the wildcard) |
| `dr-adams` | `records:team:annotate` allow | team scope (fails closed without resource teams) |
| `dr-adams` | `labs:org:view_results` allow *if* `resource.department == "cardiology"` | ABAC condition |
| `locum-jones` | `records:org:read` + `records:team:annotate` allow, **no team memberships** | team scope, no overlap |

`POST /check` answers one point decision (`allowed` / `denied_by_grant` / `denied_by_default`,
optionally with the opt-in evaluation trace); `POST /visibility` classifies list visibility
(`granted` / `conditional` / `none`) — derived from the **same** evaluation pass, so a list can
never show more than row-by-row checks would allow.

## Run it

```bash
dotnet run --project samples/002-permission-grammar/Grammar.Api

# Wildcard allow
curl -s localhost:5000/check -H 'content-type: application/json' \
  -d '{"subject":"dr-adams","permission":"records:org:read"}'                        # allowed

# Deny-overrides, with the evaluation trace
curl -s localhost:5000/check -H 'content-type: application/json' \
  -d '{"subject":"dr-adams","permission":"records:org:export","trace":true}'         # denied_by_grant

# ABAC condition on a resource attribute
curl -s localhost:5000/check -H 'content-type: application/json' \
  -d '{"subject":"dr-adams","permission":"labs:org:view_results","resourceAttributes":{"department":"cardiology"}}'

# Team scope: shared team ⇒ allowed; omit resourceTeamIds and it fails closed
curl -s localhost:5000/check -H 'content-type: application/json' \
  -d '{"subject":"dr-adams","permission":"records:team:annotate","resourceTeamIds":["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"]}'

# Visibility, from the same pass: granted / none / conditional
curl -s localhost:5000/visibility -H 'content-type: application/json' \
  -d '{"subject":"dr-adams","service":"records","action":"read","scope":"org"}'      # granted
curl -s localhost:5000/visibility -H 'content-type: application/json' \
  -d '{"subject":"dr-adams","service":"labs","action":"view_results","scope":"org"}' # conditional
```

## Test it

```bash
dotnet test samples/002-permission-grammar/Grammar.Api.Tests
```

> Requires the **.NET 10 SDK**. No Docker/database needed.
