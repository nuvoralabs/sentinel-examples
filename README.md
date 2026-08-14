# Sentinel Samples

Runnable, test-backed companion projects for the [Sentinel documentation](https://sentinel.nuvoralabs.com/articles/):
`NNN-kebab` numbered, each with its own README, real Sentinel wiring, and a test
project — all in [`Sentinel.Samples.slnx`](./Sentinel.Samples.slnx). Mirrored to the public
[`nuvoralabs/sentinel-examples`](https://github.com/nuvoralabs/sentinel-examples) repository.

| Sample | What it shows | Needs a database? |
|---|---|---|
| [`001-first-login`](./001-first-login) | Embedding Sentinel for password + TOTP login over the httpOnly-cookie transport with CSRF double-submit | No (in-memory) |
| [`002-permission-grammar`](./002-permission-grammar) | The permission grammar + single-path evaluator: wildcards, deny-overrides, ABAC conditions, team scope, visibility from the same pass | No (pure Core) |
| [`003-refresh-token-families`](./003-refresh-token-families) | Refresh-token rotation + family-based reuse detection: replaying a consumed `srt_` token revokes the whole family and emits `token.refresh_reuse_detected` | No (in-memory) |
| [`004-passkeys`](./004-passkeys) | WebAuthn round trip (register + usernameless login) driven by a software authenticator through the real Fido2 verification path | No (in-memory) |
| [`005-multi-org-delegated-admin`](./005-multi-org-delegated-admin) | Multi-org membership, org-switch re-minting, and evaluator-fenced delegated admin over `MapSentinelAdmin()` | No (in-memory) |
| [`006-oidc-server`](./006-oidc-server) | Sentinel as an OAuth2/OIDC authorization server with a second app as relying party: discovery → authorize + PKCE → code → tokens → userinfo | No (in-memory) |
| [`007-workload-federation`](./007-workload-federation) | Secretless CI: exchanging a (fake) GitHub-Actions-style workload OIDC token for a Sentinel access token via a trust configuration | No (in-memory) |
| [`008-shadow-migration`](./008-shadow-migration) | The migration path end to end: ASP.NET Identity import, legacy-hash coexistence, shadow-mode divergence recording, zero-divergence cutover gate | SQLite in-memory (no Docker) |
| [`009-scim-provisioning`](./009-scim-provisioning) | Sentinel's SCIM 2.0 surface: Users + Groups CRUD under `/scim/v2` behind per-org `sct_` bearer tokens — soft-delete, org isolation, realm-wide userName uniqueness | No (in-memory) |
| [`010-saml-both-directions`](./010-saml-both-directions) | One host as SAML IdP AND SP, looped onto itself: pinned-cert verification, both metadata documents, tamper/replay/pin-swap rejections | No (in-memory) |
| [`011-webhooks-that-survive`](./011-webhooks-that-survive) | Webhooks both ways in one app: subscribe over `/sentinel-admin/webhooks`, receive + HMAC-verify signed deliveries, retry/backoff through an outage, dead-letter | No (in-memory) |
| [`012-tamper-evident-audit`](./012-tamper-evident-audit) | The per-realm admin audit hash chain: mutations append, `GET /sentinel-admin/audit` re-verifies on read, tampering flips `chainIntact`, redaction doesn't | No (in-memory) |
| [`013-abuse-protection-layers`](./013-abuse-protection-layers) | The four pre-database login rate-limit layers, the adaptive `captcha_required` band, and per-layer fail-open/fail-closed outage policy | No (in-memory) |
| [`014-adaptive-risk-engine`](./014-adaptive-risk-engine) | Deterministic risk signals + a custom one: step-up at 40 with email-OTP fallback, opaque block at 80, new-device alert mail | No (in-memory) |
| [`015-break-glass-and-impersonation`](./015-break-glass-and-impersonation) | Impersonation with the `act` claim, consent mode and the `/profile/me` banner; break-glass with decorator-capped grants, alarm-on-login and the drill health check | No (in-memory) |
| [`016-gdpr-crypto-shredding`](./016-gdpr-crypto-shredding) | GDPR export + erasure: crypto-shred → anonymize → redact, the audit chain still verifying, the shredder as an app primitive, retention sweeps | No (in-memory) |
| [`017-config-as-code`](./017-config-as-code) | Declarative YAML realm/org/roles/clients applied idempotently at boot: field-level drift diffs, dry-run, secretRef env resolution, prune reported-and-refused | No (in-memory) |
| [`018-relay-bridge`](./018-relay-bridge) | A Relay app on Sentinel auth: `UseSentinelRelayAuthContext`, `[RequirePermission]` decided by the real evaluator (wildcards, deny-overrides), org claim → Relay tenant | No (in-memory) |
| [`019-api-keys-owner-capped`](./019-api-keys-owner-capped) | `snt_` API keys capped to owner ∩ scopes at every use: denies preserved, owner demotion shrinks keys instantly, opaque 401 for revoked/expired | No (in-memory) |
| [`020-importing-identity`](./020-importing-identity) | Four importers, one target: Identity V3 verify + rehash-on-login, Keycloak realm export, Auth0 bcrypt ndjson, Duende secret rotation-on-migration, dry-run reports | SQLite in-memory (no Docker) |

## Prerequisites

- **.NET SDK 10.0** (`net10.0`). Check with `dotnet --version`.
- No Docker required — every sample runs on in-memory stores or in-memory SQLite.

## Build & test everything

```bash
# from libraries/nuvora-nexus-sentinel
dotnet test samples/Sentinel.Samples.slnx
```

## Run a single sample

```bash
dotnet run --project samples/001-first-login/Clinic.Login.Api
```

Each sample directory has its own `README.md` with concrete `curl` commands and expected output.

## How samples reference the library

The samples build in two modes, decided automatically by
[`Directory.Build.props`](./Directory.Build.props) / [`Directory.Build.targets`](./Directory.Build.targets)
(the Relay samples trick):

- **Inside the monorepo** the library source exists at `$(SentinelSrc)`, so samples reference the
  library projects directly via `ProjectReference` — building a sample also builds the packages
  it depends on.
- **In the public examples repo** the source is absent, so those references are rewritten to
  `PackageReference`s against the published `Nuvora.Nexus.Sentinel.*` NuGet packages, pinned to
  `$(SentinelVersion)` from the sync-generated `sentinel-version.props`.
