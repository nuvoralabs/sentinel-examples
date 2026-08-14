# Sample 010 — SAML in Both Directions

Companion to **[Article 010 — SAML in both directions](https://sentinel.nuvoralabs.com/articles/saml-both-directions/)**.

**One host that is simultaneously a SAML IdP and a SAML SP**, looped onto itself — the
technique Sentinel's own SAML acceptance tests use. A single realm carries both connection
records: the SP-side `SamlIdpConnection` **pins the IdP's signing certificate** (assertions
verify against the pin and nothing else — never against certificates embedded in the
document), and the IdP-side `SamlSpConnection` registers the SP's ACS. Both metadata
documents are served from the same process.

| | |
|---|---|
| User | `alice@samlloop.sample` / `sample-password-1!` |
| SP entity id | `https://sp.samlloop.sample` — metadata at `/auth/saml/metadata` |
| IdP entity id | `https://idp.samlloop.sample` — metadata at `/saml/idp/metadata` |
| The loop | `/auth/saml/self/start` → `/saml/idp/sso` → auto-post → `/auth/saml/acs` |

## Run it

```bash
dotnet run --project samples/010-saml-both-directions/SamlLoop.Api
# (the app binds http://localhost:5010 — the seeded connection URLs match it exactly)

# Both metadata documents, one process:
curl -s localhost:5010/auth/saml/metadata | head -2    # SPSSODescriptor, WantAssertionsSigned
curl -s localhost:5010/saml/idp/metadata | head -2     # IDPSSODescriptor + signing certificate

# The full loop needs a browser: open
#   http://localhost:5010/auth/saml/self/start?redirect_uri=/welcome
# → you land on the host /login page (pre-filled) → sign in → the IdP half issues a signed
# assertion → auto-posts to the ACS → the SP half verifies it against the pinned cert and
# redirects to /welcome with a Sentinel cookie session.
```

## Test it

```bash
dotnet test samples/010-saml-both-directions/SamlLoop.Api.Tests
```

The tests drive the loop headlessly (cookie jar + form scraping) and pin the refusals the
wire only ever reports as `saml_failed`: a tampered assertion (`signature_invalid`), an
authentic assertion against a swapped pin (`signature_invalid` — the pin IS the trust
decision), and a replayed response (single-use RelayState).

> Requires the **.NET 10 SDK**. No Docker/database needed.
