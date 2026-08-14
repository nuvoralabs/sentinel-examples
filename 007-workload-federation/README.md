# Sample 007 — Workload Federation (Secretless CI)

Workload identity federation: a CI job exchanges the OIDC token its **platform**
minted for it (GitHub Actions, Kubernetes, a cloud managed identity) for a Sentinel access token
— through a **trust configuration**, with **no Sentinel secret in the pipeline**.

The sample hosts a fake GitHub-Actions-style issuer in-process (`FakeCiIdp`: a local RSA key
whose JWKS is served through the injected `IRemoteJwksCache`), one service account
(`ci-deployer`) and one trust:

| Trust field | Value |
|---|---|
| Issuer / JWKS | `https://fake-ci-idp.sample` (in-process) |
| Audience | `sentinel-federation` |
| Subject pattern | `repo:nuvoralabs/*` |
| Claim rules | `repository=nuvoralabs/*`, `ref=refs/heads/master` |

`POST /oidc/workload/token` (RFC 8693-shaped, from `MapSentinelWorkloadFederation()`) validates
the external token against the trust and mints an access token acting as `ci-deployer`;
`POST /deployments` is an ordinary Sentinel-protected endpoint that accepts it. Wrong audience,
unknown issuer, foreign subject, or a failing claim rule ⇒ `invalid_grant`.

## Run it

```bash
dotnet run --project samples/007-workload-federation/WorkloadExchange.Api

# 1) Mint a CI-shaped workload token (SAMPLE-ONLY endpoint standing in for the CI platform)
CI_TOKEN=$(curl -s localhost:5000/fake-idp/token -H 'content-type: application/json' -d '{}' | jq -r .token)

# 2) Exchange it — secretless: the workload proves itself with its platform token
ACCESS=$(curl -s localhost:5000/oidc/workload/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token_type=urn:ietf:params:oauth:token-type:jwt \
  --data-urlencode "subject_token=$CI_TOKEN" | jq -r .access_token)

# 3) Call the protected API with the exchanged token
curl -i -X POST localhost:5000/deployments -H "Authorization: Bearer $ACCESS"   # 200, acts as ci-deployer

# A token for the wrong branch fails the trust's claim rules
BAD=$(curl -s localhost:5000/fake-idp/token -H 'content-type: application/json' \
  -d '{"ref":"refs/heads/feature","sub":"repo:nuvoralabs/nexus:ref:refs/heads/feature"}' | jq -r .token)
curl -i localhost:5000/oidc/workload/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  --data-urlencode "subject_token=$BAD"                                         # 400 invalid_grant
```

## Test it

```bash
dotnet test samples/007-workload-federation/WorkloadExchange.Api.Tests
```

> Requires the **.NET 10 SDK**. No Docker/database needed — in-memory stores, ephemeral dev
> signing keys (explicit opt-in), fake IdP in-process.
