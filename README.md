# `@innovative-augmentation/token-verify`

Shared JWT verification. **One implementation, consumed by both repos** — the platform API and
`ne-scheduling`. That is the whole point of it being a package: the ADR ([`plans/auth.md`](../../plans/auth.md))
chose in-app middleware over gateway validation specifically so the two sides cannot drift apart.

It implements the **token contract** (`contracts/v1/token.contract.json`, v1 as amended 2026-10-01):
the checks, and the contract's rejection codes, so a log line means the same thing whichever
implementation wrote it.

Authentication is what it *decides*: every failure is a **401**. On Plane B it also *reads* what the
tenant has granted — `permissionsFor` — but whether that is enough for a route is the caller's
decision, and a shortfall is a **403** (see [401 vs 403](#401-vs-403)). Plane A users carry no
permissions in the token: their roles are resolved server-side per request (P1.4 / P1.7), so
revoking one takes effect on the next request rather than at expiry.

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

### Plane B on Entra

```js
const { createEntraVerifier } = require('@innovative-augmentation/token-verify');

const planeB = createEntraVerifier({
  tenantId: process.env.ENTRA_TENANT_ID,          // the tenant's directory id
  audience: process.env.CAPABILITY_API_AUDIENCE,  // this service's Application ID URI
  clientId: process.env.PLATFORM_CLIENT_ID,       // the PLATFORM's app id in that directory
  maxTokenLifetimeSec: 2 * 60 * 60,
});
```

`clientId` is **required** from 0.3.0. Without it the verifier would accept any service principal in
the tenant's directory that holds a role (contract rule `entra_app_token`, below).

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
- **An unsigned token is `algorithm_mismatch`** (from 0.3.0; it was `invalid_token`). It was always
  refused; the code is now the one the contract names.
- **On Plane B with Entra, the token must be an application token for our app in the tenant's
  directory** (from 0.3.0, contract rule `entra_app_token`): `azp` (or, when `azp` is absent,
  `appid`) equals `clientId`, `tid` equals `tenantId`, and `idtyp` is `app` — or `idtyp` is absent
  and `scp` is absent too. Signature, issuer and audience alone admit any service principal in the
  directory that holds a role, and a *user* token too if a role was ever made assignable to users,
  because a user's roles arrive in the same `roles` claim. `idtyp` is an optional claim the tenant
  may not have enabled; a delegated token always carries `scp`, so its absence stands in. These run
  only after the signature verifies.
- **A token's lifetime must be bounded** (from 0.3.0). `jsonwebtoken` checks `exp` only when it is
  present, so before 0.3.0 a correctly signed token with no `exp` — or one expiring in the year
  3000 — was accepted for ever. Now `exp` and `iat` must both be numbers, `iat` may not be in the
  future beyond `clockToleranceSec`, and `exp - iat` may not exceed `maxTokenLifetimeSec`. These run
  only after the signature verifies, so the codes below only ever describe genuinely issued tokens.

### Lifetime options and error codes

| Option | Default | Notes |
|---|---|---|
| `maxTokenLifetimeSec` | `7200` (2 h) | Ceiling on `exp - iat`. Must be a positive number ≤ `86400`; anything else throws at construction. **Set it lower per plane** to match the issuer. |
| `clockToleranceSec` | `5` | Applied to `exp`, `nbf` and the future-`iat` check alike. Not applied to `exp - iat`, which is the issuer's own arithmetic. |

Two hours sits just above the longest *default* lifetime of either issuer: Cognito access tokens
default to 60 min (the platform pool issues 30), and Entra access tokens are a random 60–90 min
with `iat` backdated ~5 min, so `exp - iat` reaches about 95 min. A one-hour default would reject
genuine Entra tokens. The 24 h hard cap is the most either issuer can be configured to mint.

The contract caps `exp - iat` at 24 h (rule `lifetime_bounded`); this package's 2 h default is
stricter, and `maxTokenLifetimeSec: 86400` gives exactly the contract's cap.

**`issued_in_future` is in the contract (2026-10-01 amendment).** As first drafted,
`lifetime_bounded` bounded `exp - iat` but did not forbid a future `iat`, so a token with `iat` a
day short of an `exp` in 2100 satisfied it and lived for decades. The amendment closes that with
the tolerance `expiry_enforced` already allows (at most 5 s), and this package applies the same
tolerance (`clockToleranceSec`) to `exp`, `nbf` and `iat` alike.

## Error codes

Every code is a rejection of the TOKEN: the middleware answers **401** `{ error: 'unauthorized' }`
and passes the error, with its `code`, to `onError` for the log. The code never goes in the
response (contract rule `reason_is_not_returned`): a probe that is told why its token failed is
being helped to fix it. `TokenVerificationError` carries `code` and `httpStatus: 401`.

| `err.code` | Contract rule | Meaning |
|---|---|---|
| `missing_token` | — | no token, or an empty one |
| `invalid_token` | — | not a JWT, or a bad signature |
| `no_kid` | `kid_required` | header carries no `kid`; no key lookup is attempted |
| `key_lookup_failed` | `kid_required` | `kid` not in the issuer's JWKS |
| `algorithm_mismatch` | `algorithms_pinned` | `alg` not in `algorithms`, including `none` |
| `issuer_mismatch` | `issuer_exact` | `iss` is not exactly the configured issuer |
| `audience_mismatch` | `audience_claim_is_configured` | wrong audience, or the audience in the wrong claim |
| `wrong_token_use` | `token_use_enforced_when_set` | `token_use` absent or different, where one is configured |
| `expired` | `expiry_enforced` | `exp` passed (beyond `clockToleranceSec`) |
| `not_yet_valid` | `expiry_enforced` | `nbf` in the future |
| `no_expiry` | `expiry_required` | `exp` missing, or not a finite number (string, `null`) |
| `no_iat` | `lifetime_bounded` | `iat` missing, or not a finite number |
| `issued_in_future` | `lifetime_bounded` | `iat` later than now + `clockToleranceSec` |
| `lifetime_exceeded` | `lifetime_bounded` | `exp - iat` above `maxTokenLifetimeSec` |
| `wrong_client` | `entra_app_token` | `azp` (or `appid`) is not the platform's client id |
| `wrong_tenant` | `entra_app_token` | `tid` is not the tenant's directory |
| `not_an_app_token` | `entra_app_token` | `idtyp` is not `app`, or is absent while `scp` is present |

## Plane B permissions

```js
const { permissionsFor } = require('@innovative-augmentation/token-verify');
const { permissions } = require('./contracts/v1/token.contract.json');

const granted = permissionsFor(claims, { permissions, idp: 'entra' });
// Cognito: permissionsFor(claims, { permissions, idp: 'cognito', scopePrefix: RESOURCE_SERVER_ID })
if (!granted.includes('orders:read')) {
  return res.status(403).json({ error: 'insufficient_scope', required: 'orders:read' });
}
```

**You pass the contract's `permissions` section; the package holds no copy of it.** The contract is
the one place the vocabulary and the Entra role map are agreed, and a copy here would be a second
place for them to drift. `permissionsFor` applies the section exactly:

| IdP | Claim read | Normalised |
|---|---|---|
| Entra | `roles` (an array) | exact lookup in the section's `map`; anything else dropped |
| Cognito | `scope` (a space-separated string) | keep entries starting `<scopePrefix>/`, strip that, keep exact members of `vocabulary` |

The map as the contract states it today:

| Entra app role | Permission |
|---|---|
| `orders.read` | `orders:read` |
| `customers.read` | `customers:read` |
| `vehicles.read` | `vehicles:read` |
| `drivers.read` | `drivers:read` |
| `telemetry.read` | `telemetry:read` |
| `loads.write` | `loads:write` |

- **Nothing is rewritten.** No "dot to colon", no case folding: `Orders.Read`, `orders.read.all` and a
  bare `orders:read` in `roles` all grant nothing. A string rule would turn any role somebody adds
  later into a permission nobody reviewed (contract rule `exact_vocabulary`).
- **One claim per IdP.** Entra is never read from `scope`, Cognito never from `roles`
  (`one_claim_per_idp`).
- A claim in the wrong shape (a string `roles`, an array `scope`) grants nothing.
- A section that is not the contract's shape throws a `TypeError` instead of quietly granting
  nothing to everyone.
- Call it only with claims `verify` returned.

### 401 vs 403

| Outcome | Status | Body | Why |
|---|---|---|---|
| any `TokenVerificationError` | **401** | `{ "error": "unauthorized" }` | the caller has not proved who they are; the code goes to the log only |
| verified, but `permissionsFor` lacks the route's permission | **403** | `{ "error": "insufficient_scope" }` (advised) | the caller *is* who they say; a 401 would send them to fetch a new token carrying the same grants, so the retry could never succeed and the missing grant would never be named |

The 403 is the caller's to send (contract rule `insufficient_permission_is_403`). An unmapped role
is a 403, not a 401: the token is fine and the grant is absent.

- JWKS responses are cached and rate-limited.

## Upgrading from 0.2.x to 0.3.0

`^0.2.0` does **not** pick up 0.3.0 — a caret on a `0.x` version pins the minor — so each consumer
upgrades deliberately. 0.3.0 is the first release since 0.2.0, and it carries both the bounded
lifetime and the rest of the contract's 2026-10-01 amendment. What you must change:

1. **`createEntraVerifier` needs `clientId`** — the platform's application (client) id in the
   tenant's directory. It throws at construction without one. A verifier built with
   `createVerifier` for an Entra issuer should pass `entraApp: { clientId, tenantId }`.
2. **Tokens newly refused (401)**, after the signature verifies:
   - no `exp`, or a non-numeric one → `no_expiry`;
   - no `iat`, or a non-numeric one → `no_iat`;
   - `iat` in the future beyond `clockToleranceSec` → `issued_in_future`;
   - `exp - iat` over `maxTokenLifetimeSec` (default **2 h**; at most 24 h) → `lifetime_exceeded`.
     Pass `maxTokenLifetimeSec` explicitly if an issuer is configured longer, and justify it;
   - on Entra: another client (`wrong_client`), another directory (`wrong_tenant`), or a user or
     delegated token (`not_an_app_token`).
3. **A changed code**: an unsigned (`alg: none`) token is now `algorithm_mismatch`, not
   `invalid_token`. Alerts or dashboards keyed on the old code need updating.
4. **Permissions, if you read them yourself**: replace your own role or scope parsing with
   `permissionsFor(claims, { permissions, idp })`, passing the contract's `permissions` section, and
   answer a missing permission with **403**, never 401.
5. **Names changed while 0.3.0 was unreleased.** Anything written against the 0.3.0 branch before
   this change and matching on `no_issued_at` or `token_lifetime_exceeded` must match `no_iat` and
   `lifetime_exceeded`, the contract's names.

Nothing changes for Plane A Cognito verifiers beyond item 2: no permission is read from a user
token, and `entra_app_token` does not apply.

## Tests

```
npm test
```

No network: a fake JWKS client is injected via the `jwksClient` option, and every key is
generated per run. Coverage includes the forgery paths (`alg: none`, wrong signing key, mismatched
issuer/audience, expired, missing `kid`), the lifetime rules (no `exp`, non-numeric `exp`/`iat`,
missing `iat`, ten-year and year-3000 tokens, future `iat`, the ceiling boundary), every
`entra_app_token` case, `permissionsFor` against the contract's section and against altered
sections (to prove the map comes from the caller), and an explicit plane-separation case asserting
a Plane B token fails against a Plane A verifier.

The contract's language-neutral conformance vectors hold this package to the contract from the
platform repository.

## Installing it from another repo

Published to the **public npm registry**, with provenance, so no `.npmrc` or token is needed:

```
npm install @innovative-augmentation/token-verify@^0.3.0
```

Pin with semver so upgrades are deliberate and visible in the lockfile.

**This only holds the Node consumers together.** A tenant service written in anything else cannot
use it, so the durable artifact is the *token contract* — issuer, audience claim, required claims,
permitted algorithms, `token_use` — with this package as the reference implementation. Conformance
vectors are what prove another implementation matches.

## Consumers

- **Platform API** — Plane A, once the app lands in `apps/`.
- **`ne-scheduling`** — both planes (P1.11.1 and P1.11.2). It serves logged-in users *and* is a
  tenant service the platform calls, so it mounts two verifiers on different routes.
