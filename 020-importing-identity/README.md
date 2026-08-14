# Sample 020 — Importing Identity

Companion to **[Article 020 — Importing identity](https://sentinel.nuvoralabs.com/articles/importing-identity/)**.

Four legacy exports land in Sentinel's **real EF Core stores** (SQLite in-memory) through
one `IImportTarget` — with real hashes, produced by the actual algorithms:

| Source | What's imported | Credential story |
|---|---|---|
| **ASP.NET Core Identity** | users, roles (`imported:support-agent`), claims → attributes | V3 hashes carried verbatim (`aspnet-identity-v3`), verify at login, **rehash to argon2id** |
| **Keycloak** realm export | users, realm roles, groups, clients | `pbkdf2-sha256` re-encoded to PHC format; bcrypt travels verbatim |
| **Auth0** ndjson export | users (`blocked` → Suspended) | bcrypt via `custom_password_hash` |
| **Duende** client config | OIDC clients | `sha256(secret)` is unrecoverable → **rotation-on-migration**: a fresh secret is generated, surfaced once in `GeneratedClientSecrets` |

Every run is **dry-runnable** (`DryRun = true`: full report, zero writes) and **idempotent**
(matched by natural key — email, role key, clientId — re-running updates, never duplicates).

## Run it

```bash
dotnet run --project samples/020-importing-identity/IdentityImport.Api

# 1) Dry run — the triage list. Nothing is written.
curl -s -X POST localhost:5000/migration/dry-run | jq '{dryRun, users: .aspnetIdentity.users, issues: .aspnetIdentity.issues}'

# 2) The real import — note duende.generatedClientSecrets: shown ONCE, never stored in plaintext
curl -s -X POST localhost:5000/migration/import | jq .duende

# 3) Alice's credential still carries the Identity V3 tag…
curl -s localhost:5000/migration/credentials/alice@legacy.sample | jq

# 4) …she logs in with the password she has ALWAYS used…
curl -s localhost:5000/auth/login -H 'content-type: application/json' \
  -d '{"email":"alice@legacy.sample","password":"alices-identity-password-1"}' | jq .status

# 5) …and the login transparently rehashed it to argon2id. No reset-email blast.
curl -s localhost:5000/migration/credentials/alice@legacy.sample | jq

# 6) Re-import is idempotent: updated, not duplicated
curl -s -X POST localhost:5000/migration/import | jq '.aspnetIdentity.users'
```

## Test it

```bash
dotnet test samples/020-importing-identity/IdentityImport.Api.Tests
```

> Requires the **.NET 10 SDK**. No Docker needed — the EF stores run on in-memory SQLite;
> swap the connection string for Postgres/SQL Server in a real migration. Sample 008 continues
> this story with shadow-mode authorization and the zero-divergence cutover gate.
