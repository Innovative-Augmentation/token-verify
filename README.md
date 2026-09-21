# `@innovative-augmentation/token-verify`

Shared JWT verification. **One implementation, consumed by both repos** — the platform API and
`ne-scheduling`. That is the whole point of it being a package: the ADR ([`plans/auth.md`](../../plans/auth.md))
chose in-app middleware over gateway validation specifically so the two sides cannot drift apart.

Authentication only. It answers *who is this*, never *may they* — roles are resolved server-side
per request (P1.4 / P1.7) and are deliberately absent from the token, so revoking one takes effect
on the next request rather than at expiry.

## Two planes, two verifiers

Auth here has two issuers, and they are not interchangeable:

| | Plane A | Plane B |
|---|---|---|
| Direction | user → platform | platform → tenant service |
| Issuer | our Cognito pool | the **tenant's** IdP (NE = Entra) |
| Helper | `createCognitoAccessTokenVerifier` | `createEntraVerifier` |

**Create one verifier per plane and mount exactly one per route.** A single middleware accepting
either issuer would let a platform service token be replayed against a user endpoint. Separate
instances make that structurally impossible rather than a thing to remember.

```js
const { createCognitoAccessTokenVerifier } = require('@innovative-augmentation/token-verify');

const planeA = createCognitoAccessTokenVerifier({
  region: 'eu-west-2',
  userPoolId: process.env.COGNITO_USER_POOL_ID,
  clientId: process.env.COGNITO_CLIENT_ID,
});

app.use('/api', planeA.middleware({ onError: (err, req) => log.warn({ code: err.code, path: req.path }) }));
```

On success the middleware sets:

```js
req.auth = { sub, tenantId, claims }
```

`tenantId` comes from the IdP connection at federation time, so it cannot be forged by anything the
caller supplies.

## The Cognito gotcha this exists to absorb

**Cognito access tokens have no `aud` claim.** They carry `client_id`; only *ID* tokens have `aud`.
A verifier configured the obvious way rejects every genuine access token, and the error looks
nothing like the cause.

Hence `audienceClaim`, which is `'aud'` by default (correct for Entra and for ID tokens) and
`'client_id'` for Cognito access tokens. `createCognitoAccessTokenVerifier` sets it for you, along
with a `token_use: 'access'` check so an ID token cannot be presented where an access token is
expected.

## Security properties

- **Algorithms are pinned to RS256.** Without an explicit allow-list `jsonwebtoken` honours the
  token's own `alg` header — the route to `alg: none` and algorithm-confusion forgeries. Covered by
  a test.
- **401s carry no detail.** The reason goes to `onError` for server-side logging (P1.10); the caller
  gets `{ error: 'unauthorized' }` and cannot probe for why a token was rejected.
- Signature, `iss`, audience, `exp`/`nbf` and `token_use` are all checked.
- JWKS responses are cached and rate-limited.

## Tests

```
npm test --workspace @innovative-augmentation/token-verify
```

Sixteen cases, no network: a fake JWKS client is injected via the `jwksClient` option. Coverage
includes the forgery paths (`alg: none`, wrong signing key, mismatched issuer/audience, expired,
missing `kid`) and an explicit plane-separation case asserting a Plane B token fails against a
Plane A verifier.

## Installing it from another repo

Published to **GitHub Packages**, so the scope must match the org — hence
`@innovative-augmentation/` rather than a shorter `@ial/`.

Consumers need an `.npmrc` pointing the scope at GitHub and a token with `read:packages`:

```
@innovative-augmentation:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

Pin with semver (`^0.1.0`) so upgrades are deliberate and visible in the lockfile. Releases are cut
by pushing a `token-verify-v*` tag.

**This only holds the Node consumers together.** A tenant service written in anything else cannot
use it, so the durable artifact is the *token contract* — issuer, audience claim, required claims,
permitted algorithms, `token_use` — with this package as the reference implementation. Conformance
vectors are what prove another implementation matches.

## Consumers

- **Platform API** — Plane A, once the app lands in `apps/`.
- **`ne-scheduling`** — both planes (P1.11.1 and P1.11.2). It serves logged-in users *and* is a
  tenant service the platform calls, so it mounts two verifiers on different routes.
