# Sample 003 — Refresh Token Families

Companion to **[Article 003 — Refresh Token Families](https://sentinel.nuvoralabs.com/articles/refresh-token-families/)**.

Sentinel's refresh tokens are opaque, rotating, and **family-based**: every login
starts a family; each `POST /auth/refresh` rotates to a new `srt_` token and consumes the old
one. Presenting a consumed token means it leaked — Sentinel revokes the **whole family**
(the legitimately rotated token included) and emits a `token.refresh_reuse_detected` security
event through the event-sink port. This sample mounts the auth group over the **Bearer**
transport, seeds one user, and exposes the recorded events at `GET /security/events` so
the whole story is walkable with curl.

Demo login: `casey@refresh.example` / `rotate-early-rotate-often`.

## Run it

```bash
dotnet run --project samples/003-refresh-token-families/RefreshFamilies.Api

# 1) Login starts a token family
RT=$(curl -s localhost:5000/auth/login -H 'content-type: application/json' \
  -d '{"email":"casey@refresh.example","password":"rotate-early-rotate-often"}' | jq -r .refreshToken)

# 2) Rotate: a new refresh token replaces the old one
RT2=$(curl -s localhost:5000/auth/refresh -H 'content-type: application/json' \
  -d "{\"refreshToken\":\"$RT\"}" | jq -r .refreshToken)

# 3) Replay the CONSUMED token — reuse detected, whole family revoked
curl -i localhost:5000/auth/refresh -H 'content-type: application/json' \
  -d "{\"refreshToken\":\"$RT\"}"                                   # 401 invalid_refresh_token

# 4) The rotated token died with its family
curl -i localhost:5000/auth/refresh -H 'content-type: application/json' \
  -d "{\"refreshToken\":\"$RT2\"}"                                  # 401

# 5) The security event fired internally
curl -s localhost:5000/security/events | jq                          # ... token.refresh_reuse_detected
```

## Test it

```bash
dotnet test samples/003-refresh-token-families/RefreshFamilies.Api.Tests
```

> Requires the **.NET 10 SDK**. No Docker/database needed.
