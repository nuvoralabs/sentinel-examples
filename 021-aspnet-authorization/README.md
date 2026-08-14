# Sample 021 — ASP.NET authorization, decided by Sentinel

Companion to **[Article 021 — Migrating ASP.NET authorization](https://sentinel.nuvoralabs.com/articles/aspnet-authorization/)**.

An ordinary controller-based helpdesk API. Every endpoint is guarded the way ASP.NET Core documents
— `[Authorize(Policy = "…")]` and a `[SentinelPermission]` attribute — and every one of those checks
is answered by Sentinel's evaluator, so wildcards, deny-overrides, organization scoping and team
scoping all apply to code that looks entirely conventional.

The point of the sample is the migration path. An application already using policy-based
authorization changes **one line of wiring** — `AddSentinelAuthorization()` — and its existing
`[Authorize(Policy = "helpdesk:global:reports_read")]` attributes start resolving against the real
engine. From there it can move endpoint by endpoint to `[SentinelPermission]`, which can say the
thing a policy name cannot: *which record* this request is about.

Three members of staff, no database:

| | Organization | Team | Holds |
|---|---|---|---|
| `avery@helpdesk.example` | North | Hardware | Read and close North's tickets; read notes for hardware tickets |
| `sam@helpdesk.example` | North | — | The realm-wide report; read every North ticket |
| `olive@helpdesk.example` | South | — | An account, and nothing else |

Password for all three: `correct-horse-battery-staple`.

## Run it

```bash
dotnet run --project samples/021-aspnet-authorization/Helpdesk.Api

# Sign in as the agent
TOKEN=$(curl -s localhost:5000/auth/login -H 'content-type: application/json' \
  -d '{"email":"avery@helpdesk.example","password":"correct-horse-battery-staple"}' | jq -r .accessToken)

NORTH=11111111-1111-1111-1111-1111111111a1
SOUTH=22222222-2222-2222-2222-2222222222a1

# Their own organization's tickets: 200
curl -si -H "authorization: Bearer $TOKEN" localhost:5000/api/orgs/$NORTH/tickets | head -1

# Another organization's, through the identical endpoint: 403.
# The organization is read from the route, so the question asked is about the organization in the
# URL — not whichever one the caller happens to belong to.
curl -si -H "authorization: Bearer $TOKEN" localhost:5000/api/orgs/$SOUTH/tickets | head -1

# Notes on a hardware ticket (their team): 200
curl -si -H "authorization: Bearer $TOKEN" \
  localhost:5000/api/tickets/aaaaaaaa-0000-0000-0000-00000000000a/notes | head -1

# Notes on a billing ticket (not their team): 403.
# The team is a property of the ticket, not part of the URL, so a resolver loads the ticket before
# the question is asked.
curl -si -H "authorization: Bearer $TOKEN" \
  localhost:5000/api/tickets/bbbbbbbb-0000-0000-0000-00000000000b/notes | head -1

# The report is guarded by a plain [Authorize(Policy = "helpdesk:global:reports_read")]: 403 here,
# 200 for the supervisor.
curl -si -H "authorization: Bearer $TOKEN" localhost:5000/api/reports | head -1
```

## What each guard shows

- **`[Authorize(Policy = "helpdesk:global:reports_read")]`** on `GET /api/reports` — the attribute a
  migrating codebase already has, now decided by Sentinel. Nothing about it was rewritten.
- **`[SentinelPermission(…, Organization = "{orgId}")]`** on `GET /api/orgs/{orgId}/tickets` — the
  record's organization comes from the route, so the check is about the organization asked for.
- **`[SentinelPermission(…, ResolverType = typeof(TicketResolver))]`** on the note and close
  endpoints — the facts a check needs are properties of the ticket, so they are looked up first. A
  ticket that does not exist is refused, never checked as though it had no organization at all.
- **`GetSentinelListScope(…)`** on `GET /api/queue` — asks what the caller may see *before* querying,
  so the database is asked once, correctly, instead of fetching everything and filtering afterwards.

## Startup refuses a guard it cannot enforce

`ValidateHelpdeskAsync` publishes the permissions and then checks every mounted endpoint. Try
breaking one and the application will not start:

- Remove `Organization = "{orgId}"` from `ListForOrganization`. An organization-scoped check with
  nothing bound falls back to the caller's own organization and **passes**, while the handler goes on
  to load another organization's records. Startup refuses it, and names the route.
- Point a binding at a route value that does not exist (`Organization = "{orgID}"`). Refused, because
  the check would silently run with no organization at all.
- Guard something with a permission that was never published. Refused — a permission nobody declared
  cannot have been granted to anybody.

## Test it

```bash
dotnet test samples/021-aspnet-authorization/Helpdesk.Api.Tests
```

> Requires the **.NET 10 SDK**. No Docker or database needed.
