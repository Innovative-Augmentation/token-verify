'use strict';

/**
 * The checks the token contract added in its 2026-10-01 amendment that this package
 * enforces: `entra_app_token`, and the contract's names for the lifetime codes. The
 * contract's `permissions` section (what a caller may DO, answered 403) is not this
 * module's to decide, so nothing here grants or refuses a permission.
 *
 * Every identifier here is a sentinel. No real directory, client or pool id belongs
 * in a public repository's tests, and none is needed: the keys are generated per run.
 */

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');

const {
  createVerifier,
  createEntraVerifier,
  createCognitoAccessTokenVerifier,
  TokenVerificationError,
} = require('../src/index.js');

const KID = 'contract-test-key';
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});
const jwksClient = {
  getSigningKey(kid, cb) {
    if (kid !== KID) return cb(new Error('unknown kid'));
    cb(null, { getPublicKey: () => publicKey });
  },
};

const TENANT = '00000000-0000-0000-0000-0000000000aa';
const OTHER_TENANT = '00000000-0000-0000-0000-0000000000bb';
const CLIENT = 'test-platform-client';
const AUDIENCE = 'api://test-capabilities.invalid';
const ENTRA_ISSUER = `https://login.microsoftonline.com/${TENANT}/v2.0`;

const COGNITO_ISSUER = 'https://cognito-idp.eu-west-2.amazonaws.com/eu-west-2_TEST';
const COGNITO_CLIENT = 'test-cognito-client';

const now = () => Math.floor(Date.now() / 1000);

// Signs exactly the payload given — no claim added or coerced — so a test states
// every claim the token carries.
function signRaw(payload, header = {}) {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const input = `${b64({ alg: 'RS256', typ: 'JWT', kid: KID, ...header })}.${b64(payload)}`;
  const sig = crypto.sign('sha256', Buffer.from(input), privateKey).toString('base64url');
  return `${input}.${sig}`;
}

function entraClaims(overrides = {}) {
  const iat = now() - 60;
  const claims = {
    sub: 'platform-service',
    iss: ENTRA_ISSUER,
    aud: AUDIENCE,
    azp: CLIENT,
    tid: TENANT,
    idtyp: 'app',
    roles: ['orders.read'],
    iat,
    exp: iat + 3600,
    ...overrides,
  };
  // `undefined` in an override means "leave this claim out of the token".
  for (const k of Object.keys(claims)) if (claims[k] === undefined) delete claims[k];
  return claims;
}

function entraVerifier(extra = {}) {
  return createEntraVerifier({ tenantId: TENANT, audience: AUDIENCE, clientId: CLIENT, jwksClient, ...extra });
}

function cognitoClaims(overrides = {}) {
  const iat = now() - 60;
  const claims = {
    sub: 'user-1',
    iss: COGNITO_ISSUER,
    client_id: COGNITO_CLIENT,
    token_use: 'access',
    iat,
    exp: iat + 3600,
    ...overrides,
  };
  for (const k of Object.keys(claims)) if (claims[k] === undefined) delete claims[k];
  return claims;
}

const rejectsWith = (code) => (e) => {
  assert.ok(e instanceof TokenVerificationError, `expected TokenVerificationError, got ${e && e.name}`);
  assert.equal(e.code, code);
  assert.equal(e.httpStatus, 401);
  return true;
};

// ── entra_app_token ────────────────────────────────────────────────────────────

test('ENTRA: an app token for our client in our directory is accepted', async () => {
  const claims = await entraVerifier().verify(signRaw(entraClaims()));
  assert.equal(claims.azp, CLIENT);
});

test('ENTRA: wrong azp is wrong_client', async () => {
  await assert.rejects(entraVerifier().verify(signRaw(entraClaims({ azp: 'someone-else' }))), rejectsWith('wrong_client'));
});

test('ENTRA: appid stands in for azp on a v1-style token — right one accepted, wrong one refused', async () => {
  await entraVerifier().verify(signRaw(entraClaims({ azp: undefined, appid: CLIENT })));
  await assert.rejects(
    entraVerifier().verify(signRaw(entraClaims({ azp: undefined, appid: 'someone-else' }))),
    rejectsWith('wrong_client')
  );
});

test('ENTRA: neither azp nor appid is wrong_client — absence is not a match', async () => {
  await assert.rejects(entraVerifier().verify(signRaw(entraClaims({ azp: undefined }))), rejectsWith('wrong_client'));
});

test('ENTRA: azp is read when present, so a wrong azp is not rescued by a right appid', async () => {
  await assert.rejects(
    entraVerifier().verify(signRaw(entraClaims({ azp: 'someone-else', appid: CLIENT }))),
    rejectsWith('wrong_client')
  );
});

test('ENTRA: wrong or missing tid is wrong_tenant', async () => {
  await assert.rejects(entraVerifier().verify(signRaw(entraClaims({ tid: OTHER_TENANT }))), rejectsWith('wrong_tenant'));
  await assert.rejects(entraVerifier().verify(signRaw(entraClaims({ tid: undefined }))), rejectsWith('wrong_tenant'));
});

test('ENTRA: a user token (idtyp user) is not_an_app_token, even holding a valid role', async () => {
  await assert.rejects(
    entraVerifier().verify(signRaw(entraClaims({ idtyp: 'user', scp: 'user_impersonation' }))),
    rejectsWith('not_an_app_token')
  );
  await assert.rejects(entraVerifier().verify(signRaw(entraClaims({ idtyp: 'user' }))), rejectsWith('not_an_app_token'));
});

test('ENTRA: no idtyp but an scp is a delegated token — not_an_app_token', async () => {
  await assert.rejects(
    entraVerifier().verify(signRaw(entraClaims({ idtyp: undefined, scp: 'user_impersonation' }))),
    rejectsWith('not_an_app_token')
  );
});

test('ENTRA: no idtyp and no scp is accepted — idtyp is an optional claim the tenant may not enable', async () => {
  await entraVerifier().verify(signRaw(entraClaims({ idtyp: undefined })));
});

test('ENTRA: the checks run in contract order — wrong client is reported before wrong tenant', async () => {
  await assert.rejects(
    entraVerifier().verify(signRaw(entraClaims({ azp: 'someone-else', tid: OTHER_TENANT, idtyp: 'user' }))),
    rejectsWith('wrong_client')
  );
});

test('ENTRA: createEntraVerifier requires clientId, and options cannot switch the app checks off', async () => {
  assert.throws(() => createEntraVerifier({ tenantId: TENANT, audience: AUDIENCE, jwksClient }), /clientId is required/);
  const v = entraVerifier({ entraApp: null });
  await assert.rejects(v.verify(signRaw(entraClaims({ azp: 'someone-else' }))), rejectsWith('wrong_client'));
});

test('ENTRA: entraApp on createVerifier needs both ids', () => {
  const base = { issuer: ENTRA_ISSUER, audience: AUDIENCE, jwksClient };
  assert.throws(() => createVerifier({ ...base, entraApp: { clientId: CLIENT } }), /entraApp/);
  assert.throws(() => createVerifier({ ...base, entraApp: { tenantId: TENANT } }), /entraApp/);
});

test('ENTRA: the app checks run only after the signature — a forgery is invalid_token, not wrong_client', async () => {
  const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const forged = jwt.sign(entraClaims({ azp: 'someone-else' }), other.privateKey, { algorithm: 'RS256', keyid: KID });
  await assert.rejects(entraVerifier().verify(forged), rejectsWith('invalid_token'));
});

// ── Cognito and Plane A are unchanged ──────────────────────────────────────────

test('COGNITO: entra_app_token does not apply — a Cognito token has no azp, tid or idtyp', async () => {
  const v = createCognitoAccessTokenVerifier({
    region: 'eu-west-2',
    userPoolId: 'eu-west-2_TEST',
    clientId: COGNITO_CLIENT,
    jwksClient,
  });
  const claims = await v.verify(signRaw(cognitoClaims()));
  assert.equal(claims.azp, undefined);
  assert.equal(claims.tid, undefined);
});

test('ENTRA: roles do not affect authentication — an app token with no roles still verifies', async () => {
  // Whether the caller may call a capability is the permission question, answered
  // 403 by whoever holds the data. Refusing it here would turn that 403 into a 401.
  await entraVerifier().verify(signRaw(entraClaims({ roles: undefined })));
  await entraVerifier().verify(signRaw(entraClaims({ roles: ['orders.read.all'] })));
});

// ── lifetime codes, under the contract's names ─────────────────────────────────

test('LIFETIME: the contract cap — exactly 24h is accepted at the 24h ceiling, one second over is lifetime_exceeded', async () => {
  const v = entraVerifier({ maxTokenLifetimeSec: 86400 });
  const iat = now() - 60;
  await v.verify(signRaw(entraClaims({ iat, exp: iat + 86400 })));
  await assert.rejects(v.verify(signRaw(entraClaims({ iat, exp: iat + 86401 }))), rejectsWith('lifetime_exceeded'));
});

test('LIFETIME: no exp is no_expiry and no iat is no_iat on Plane B too', async () => {
  await assert.rejects(entraVerifier().verify(signRaw(entraClaims({ exp: undefined }))), rejectsWith('no_expiry'));
  await assert.rejects(entraVerifier().verify(signRaw(entraClaims({ iat: undefined }))), rejectsWith('no_iat'));
});

// ── algorithms_pinned: the contract's code for an unsigned token ───────────────

test('ALGORITHMS: alg none is algorithm_mismatch, not invalid_token', async () => {
  const forged = jwt.sign(entraClaims(), null, { algorithm: 'none', keyid: KID });
  await assert.rejects(entraVerifier().verify(forged), rejectsWith('algorithm_mismatch'));
});

test('ALGORITHMS: a permitted alg with its signature stripped is invalid_token', async () => {
  const token = signRaw(entraClaims());
  const stripped = token.slice(0, token.lastIndexOf('.') + 1);
  await assert.rejects(entraVerifier().verify(stripped), rejectsWith('invalid_token'));
});

// ── reason_is_not_returned: the new codes are 401s like every other ────────────

test('MIDDLEWARE: an Entra app-token refusal is an undifferentiated 401; the code goes to onError only', async () => {
  const logged = [];
  const mw = entraVerifier().middleware({ onError: (e) => logged.push(e.code) });
  for (const overrides of [{ azp: 'someone-else' }, { tid: OTHER_TENANT }, { idtyp: 'user' }]) {
    const req = { headers: { authorization: `Bearer ${signRaw(entraClaims(overrides))}` } };
    let status = null;
    let body = null;
    await new Promise((resolve, reject) => {
      const res = {
        status(c) {
          status = c;
          return this;
        },
        json(b) {
          body = b;
          resolve();
        },
      };
      mw(req, res, () => reject(new Error('next() called for a refused token')));
    });
    assert.equal(status, 401);
    assert.deepEqual(body, { error: 'unauthorized' });
  }
  assert.deepEqual(logged, ['wrong_client', 'wrong_tenant', 'not_an_app_token']);
});

test('ENTRA: createEntraVerifier requires tenantId', () => {
  assert.throws(() => createEntraVerifier({ audience: AUDIENCE, clientId: CLIENT, jwksClient }), /tenantId is required/);
});
