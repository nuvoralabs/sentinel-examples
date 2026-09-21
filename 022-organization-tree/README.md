# Sample 022 — The organization tree

A minimal API embedding Sentinel with one tenant that has divisions: a hospital group with
two regions and three clinics. Every capability that exists at a tenant exists at every node,
and one grant placed at a region reaches the clinics beneath it.

```
mercy                (Group)     Mercy Health Group
├── north            (Region)
│   ├── lakeside     (Clinic)
│   └── hillcrest    (Clinic)
└── south            (Region)
    └── bayview      (Clinic)
```

| Behavior | Where |
|---|---|
| Token carries the tenant (`org`) **and** the acting node (`ou`) | `POST /auth/login`, `GET /profile/me` |
| Node switch reaches any node beneath a membership, never a sibling | `POST /auth/org/switch` |
| A grant at a node cascades to its subtree (`Inherit`) | the evaluator, via the node's ancestor path |
| Delegated admin fenced per node; manage at a node covers its subtree | `MapSentinelAdmin()` under `/sentinel-admin` |
| Policies fold realm → root → … → node, and a child may only tighten | `/sentinel-admin/orgs/{id}/policies[/effective]` |
| An app allowed at the root and denied at one clinic | `apps` on `/profile/me` |

Seeded world (password `sample-password-1!` for everyone):

| User | Member of | Grant (one each) |
|---|---|---|
| `rhea@mercy.sample` | Mercy Health Group | `sentinel:org:manage` at the group |
| `nadia@mercy.sample` | North Region | `sentinel:org:manage` at North |
| `leo@mercy.sample` | Lakeside Clinic | `sentinel:org:manage` at Lakeside |
| `mara@mercy.sample` | North Region | `charts:org:read` at North |

Policies: the realm allows 480 idle minutes; North sets 60. Apps: `charts` is allowed at the
group and denied at Hillcrest.

## Run it

```bash
dotnet run --project samples/022-organization-tree/OrgTree.Api

# Mara lands on North (her only membership). The token carries org = group, ou = north.
TOKEN=$(curl -s localhost:5000/auth/login -H 'content-type: application/json' \
  -d '{"email":"mara@mercy.sample","password":"sample-password-1!"}' | jq -r .accessToken)
curl -s localhost:5000/profile/me -H "Authorization: Bearer $TOKEN" | jq '{organizationId, rootOrganizationId, apps}'

# Switch to Lakeside (beneath North): allowed, and the North-level read grant still applies.
LAKESIDE=$(curl -s localhost:5000/sentinel-admin/orgs -H "Authorization: Bearer $TOKEN" | jq -r '.[] | select(.pathKey=="mercy/north/lakeside") | .id')
TOKEN2=$(curl -s localhost:5000/auth/org/switch -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d "{\"organizationId\":\"$LAKESIDE\"}" | jq -r .accessToken)
curl -i localhost:5000/charts -H "Authorization: Bearer $TOKEN2"          # 200

# The region director manages every clinic in North and nothing in South.
DIRECTOR=$(curl -s localhost:5000/auth/login -H 'content-type: application/json' \
  -d '{"email":"nadia@mercy.sample","password":"sample-password-1!"}' | jq -r .accessToken)
curl -i localhost:5000/sentinel-admin/orgs/$LAKESIDE/users -H "Authorization: Bearer $DIRECTOR"   # 200
BAYVIEW=$(curl -s localhost:5000/sentinel-admin/orgs -H "Authorization: Bearer $DIRECTOR" | jq -r '.[] | select(.pathKey=="mercy/south/bayview") | .id')
curl -i localhost:5000/sentinel-admin/orgs/$BAYVIEW/users -H "Authorization: Bearer $DIRECTOR"    # 403 admin_scope

# Policies: Lakeside inherits North's 60 minutes; loosening it is refused.
curl -s localhost:5000/sentinel-admin/orgs/$LAKESIDE/policies/effective -H "Authorization: Bearer $DIRECTOR" | jq
curl -i -X PUT localhost:5000/sentinel-admin/orgs/$LAKESIDE/policies -H "Authorization: Bearer $DIRECTOR" \
  -H 'content-type: application/json' -d '{"session.idle_minutes":120}'                            # 400 policy_loosens_parent
```

## Test it

```bash
dotnet test samples/022-organization-tree/OrgTree.Api.Tests
```

> Requires the **.NET 10 SDK**. No Docker/database needed — in-memory stores, ephemeral dev
> signing keys. The same composition works over the EF Core stores; the tree lives in the
> `sentinel_organizations` table's `parent_id`, `path` and `path_key` columns.
