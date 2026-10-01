'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');

const {
  createVerifier,
  createCognitoAccessTokenVerifier,
  DEFAULT_MAX_TOKEN_LIFETIME_SEC,
} = require('../src/index.js');

const KID = 'test-key-1';
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

// A second, unrelated key — used to prove a valid-looking token signed by the wrong
// issuer is rejected.
const other = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

const fakeJwks = {
  getSigningKey(kid, cb) {
    if (kid !== KID) return cb(new Error('unknown kid'));
    cb(null, { getPublicKey: () => publicKey });
  },
};

const ISSUER = 'https://cognito-idp.eu-west-2.amazonaws.com/eu-west-2_TEST';
const CLIENT_ID = 'test-client-id';

function sign(payload, opts = {}) {
  return jwt.sign(payload, opts.key || privateKey, {
    algorithm: 'RS256',
    keyid: KID,
    expiresIn: '5m',
    issuer: ISSUER,
    ...opts.signOpts,
  });
}

// Signs an arbitrary payload exactly as given. jsonwebtoken's sign() validates
// claim types and will not produce `exp: "never"` or `exp: null`, but a hostile
// or broken issuer can — so the tests that matter here cannot go through it.
function signRaw(payload) {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const input = `${b64({ alg: 'RS256', typ: 'JWT', kid: KID })}.${b64(payload)}`;
  const sig = crypto.sign('sha256', Buffer.from(input), privateKey).toString('base64url');
  return `${input}.${sig}`;
}

const nowSec = () => Math.floor(Date.now() / 1000);
const baseClaims = () => ({ sub: 'user-1', client_id: CLIENT_ID, token_use: 'access', iss: ISSUER });

function cognitoVerifier(overrides = {}) {
  return createVerifier({
    issuer: ISSUER,
    audience: CLIENT_ID,
    audienceClaim: 'client_id',
    tokenUse: 'access',
    jwksClient: fakeJwks,
    ...overrides,
  });
}

test('accepts a well-formed Cognito access token', async () => {
  const v = cognitoVerifier();
  const token = sign({ sub: 'user-1', client_id: CLIENT_ID, token_use: 'access' });
  const claims = await v.verify(token);
  assert.equal(claims.sub, 'user-1');
});

test('accepts client_id as audience where there is no aud claim at all', async () => {
  // The Cognito trap: access tokens carry client_id, never aud. A verifier that
  // insists on aud rejects every genuine access token.
  const v = cognitoVerifier();
  const token = sign({ sub: 'user-1', client_id: CLIENT_ID, token_use: 'access' });
  const claims = await v.verify(token);
  assert.equal(claims.aud, undefined);
  assert.equal(claims.client_id, CLIENT_ID);
});

test('rejects a token signed by a different key (wrong issuer in practice)', async () => {
  const v = cognitoVerifier();
  const token = sign({ sub: 'user-1', client_id: CLIENT_ID, token_use: 'access' }, { key: other.privateKey });
  await assert.rejects(() => v.verify(token), /invalid signature|TokenVerificationError/);
});

test('rejects a mismatched issuer', async () => {
  const v = cognitoVerifier();
  const token = sign(
    { sub: 'user-1', client_id: CLIENT_ID, token_use: 'access' },
    { signOpts: { issuer: 'https://evil.example.com' } }
  );
  await assert.rejects(() => v.verify(token), (e) => e.code === 'issuer_mismatch');
});

test('rejects a mismatched audience', async () => {
  const v = cognitoVerifier();
  const token = sign({ sub: 'user-1', client_id: 'someone-elses-client', token_use: 'access' });
  await assert.rejects(() => v.verify(token), (e) => e.code === 'audience_mismatch');
});

test('rejects an ID token where an access token is required', async () => {
  const v = cognitoVerifier();
  const token = sign({ sub: 'user-1', client_id: CLIENT_ID, token_use: 'id' });
  await assert.rejects(() => v.verify(token), (e) => e.code === 'wrong_token_use');
});

test('rejects an expired token', async () => {
  const v = cognitoVerifier();
  const token = sign(
    { sub: 'user-1', client_id: CLIENT_ID, token_use: 'access' },
    { signOpts: { expiresIn: '-1m' } }
  );
  await assert.rejects(() => v.verify(token), (e) => e.code === 'expired');
});

test('rejects the alg:none / unsigned token forgery', async () => {
  const v = cognitoVerifier();
  const forged = jwt.sign({ sub: 'attacker', client_id: CLIENT_ID, token_use: 'access', iss: ISSUER }, null, {
    algorithm: 'none',
  });
  await assert.rejects(() => v.verify(forged));
});

test('rejects a token with no kid in the header', async () => {
  const v = cognitoVerifier();
  const token = jwt.sign({ sub: 'user-1', client_id: CLIENT_ID, token_use: 'access' }, privateKey, {
    algorithm: 'RS256',
    issuer: ISSUER,
    expiresIn: '5m',
  });
  await assert.rejects(() => v.verify(token), (e) => e.code === 'no_kid');
});

test('rejects an absent token', async () => {
  const v = cognitoVerifier();
  await assert.rejects(() => v.verify(null), (e) => e.code === 'missing_token');
});

test('PLANE SEPARATION: a Plane B token is rejected by a Plane A verifier', async () => {
  // The guardrail this package exists to enforce structurally. A token minted for a
  // tenant service must not authenticate against a user route.
  const planeA = cognitoVerifier();
  const planeBToken = sign(
    { sub: 'platform-service', aud: 'ne-capability-api' },
    { signOpts: { issuer: 'https://login.microsoftonline.com/ne-tenant/v2.0' } }
  );
  await assert.rejects(() => planeA.verify(planeBToken));
});

test('middleware attaches req.auth and calls next on success', async () => {
  const v = cognitoVerifier();
  const token = sign({ sub: 'user-1', client_id: CLIENT_ID, token_use: 'access', 'custom:tenant_id': 'northern-energy' });
  const req = { headers: { authorization: `Bearer ${token}` } };
  const res = {};

  await new Promise((resolve, reject) => {
    v.middleware()(req, res, (err) => (err ? reject(err) : resolve()));
  });

  assert.equal(req.auth.sub, 'user-1');
  assert.equal(req.auth.tenantId, 'northern-energy');
});

test('middleware 401s without leaking the reason', async () => {
  const v = cognitoVerifier();
  const req = { headers: { authorization: 'Bearer garbage' } };
  let status = null;
  let body = null;
  const res = {
    status(c) {
      status = c;
      return this;
    },
    json(b) {
      body = b;
    },
  };

  let captured = null;
  await new Promise((resolve) => {
    const mw = v.middleware({ onError: (e) => { captured = e; resolve(); } });
    mw(req, res, () => resolve());
  });

  assert.equal(status, 401);
  assert.deepEqual(body, { error: 'unauthorized' });
  // The reason reaches the logger but not the caller.
  assert.ok(captured);
  assert.equal(JSON.stringify(body).includes(captured.code), false);
});

test('middleware 401s when the Authorization header is missing entirely', async () => {
  const v = cognitoVerifier();
  const req = { headers: {} };
  let status = null;
  const res = { status(c) { status = c; return this; }, json() {} };
  await new Promise((resolve) => v.middleware({ onError: () => resolve() })(req, res, () => resolve()));
  assert.equal(status, 401);
});

test('createCognitoAccessTokenVerifier derives issuer and jwks uri correctly', () => {
  const v = createCognitoAccessTokenVerifier({
    region: 'eu-west-2',
    userPoolId: 'eu-west-2_INZnyXnVs',
    clientId: 'abc',
    jwksClient: fakeJwks,
  });
  assert.ok(v.verify);
  assert.ok(v.middleware);
});

test('config errors fail loudly at construction', () => {
  assert.throws(() => createVerifier({ audience: 'a', jwksUri: 'u' }), /issuer is required/);
  assert.throws(() => createVerifier({ issuer: 'i', jwksUri: 'u' }), /audience is required/);
  assert.throws(() => createVerifier({ issuer: 'i', audience: 'a' }), /jwksUri is required/);
});

// ── Bounded lifetime (0.3.0) ────────────────────────────────────────────────
// jsonwebtoken only checks `exp` when present. Each test below is a correctly
// SIGNED token from the trusted key, so the signature cannot be what rejects it.

test('control: the raw signer produces a token the verifier accepts', async () => {
  // Without this, every rejection below could be the helper's fault, not the rule's.
  const v = cognitoVerifier();
  const iat = nowSec();
  const claims = await v.verify(signRaw({ ...baseClaims(), iat, exp: iat + 300 }));
  assert.equal(claims.sub, 'user-1');
});

test('LIFETIME: rejects a correctly signed token with no exp', async () => {
  const v = cognitoVerifier();
  const token = signRaw({ ...baseClaims(), iat: nowSec() });
  await assert.rejects(() => v.verify(token), (e) => e.code === 'no_expiry');
});

test('LIFETIME: rejects a non-numeric exp (string and null)', async () => {
  const v = cognitoVerifier();
  for (const exp of ['9999999999', 'never', null]) {
    const token = signRaw({ ...baseClaims(), iat: nowSec(), exp });
    await assert.rejects(() => v.verify(token), (e) => e.code === 'no_expiry', `exp=${JSON.stringify(exp)}`);
  }
});

test('LIFETIME: rejects a token with no iat', async () => {
  const v = cognitoVerifier();
  const token = signRaw({ ...baseClaims(), exp: nowSec() + 300 });
  await assert.rejects(() => v.verify(token), (e) => e.code === 'no_iat');
});

test('LIFETIME: rejects a non-numeric iat (string and null)', async () => {
  // NaN cannot be written in JSON at all — JSON.stringify(NaN) is null — so null
  // is how a NaN-producing issuer actually arrives.
  const v = cognitoVerifier();
  for (const iat of [String(nowSec()), null]) {
    const token = signRaw({ ...baseClaims(), iat, exp: nowSec() + 300 });
    await assert.rejects(() => v.verify(token), (e) => e.code === 'no_iat', `iat=${JSON.stringify(iat)}`);
  }
});

test('LIFETIME: rejects a ten-year token', async () => {
  const v = cognitoVerifier();
  const token = sign(
    { sub: 'user-1', client_id: CLIENT_ID, token_use: 'access' },
    { signOpts: { expiresIn: '3650d' } }
  );
  await assert.rejects(() => v.verify(token), (e) => e.code === 'lifetime_exceeded');
});

test('LIFETIME: rejects a token expiring in the year 3000', async () => {
  const v = cognitoVerifier();
  const token = signRaw({ ...baseClaims(), iat: nowSec(), exp: Date.UTC(3000, 0, 1) / 1000 });
  await assert.rejects(() => v.verify(token), (e) => e.code === 'lifetime_exceeded');
});

test('LIFETIME: rejects an iat pushed into the future to shrink exp - iat', async () => {
  // The way round the ceiling: a far-future exp paired with an iat just below it.
  const v = cognitoVerifier();
  const iat = nowSec() + 10 * 365 * 24 * 3600;
  const token = signRaw({ ...baseClaims(), iat, exp: iat + 300 });
  await assert.rejects(() => v.verify(token), (e) => e.code === 'issued_in_future');
});

test('LIFETIME: an iat within clock tolerance is accepted, just beyond it is not', async () => {
  const v = cognitoVerifier({ clockToleranceSec: 30 });
  const within = nowSec() + 20;
  await v.verify(signRaw({ ...baseClaims(), iat: within, exp: within + 300 }));
  const beyond = nowSec() + 60;
  await assert.rejects(
    () => v.verify(signRaw({ ...baseClaims(), iat: beyond, exp: beyond + 300 })),
    (e) => e.code === 'issued_in_future'
  );
});

test('LIFETIME: the ceiling is inclusive — exactly max passes, one second over fails', async () => {
  const v = cognitoVerifier({ maxTokenLifetimeSec: 3600 });
  const iat = nowSec();
  await v.verify(signRaw({ ...baseClaims(), iat, exp: iat + 3600 }));
  await assert.rejects(
    () => v.verify(signRaw({ ...baseClaims(), iat, exp: iat + 3601 })),
    (e) => e.code === 'lifetime_exceeded'
  );
});

test('LIFETIME: the default admits a genuine Entra-shaped token (90 min + 5 min backdated iat)', async () => {
  // Entra issues 60-90 min and backdates iat ~5 min. A default that refused this
  // would break Plane B for NE on upgrade.
  assert.equal(DEFAULT_MAX_TOKEN_LIFETIME_SEC, 7200);
  const v = cognitoVerifier();
  const iat = nowSec() - 300;
  await v.verify(signRaw({ ...baseClaims(), iat, exp: iat + 95 * 60 }));
});

test('LIFETIME: a plane can set the ceiling lower than the default', async () => {
  const v = cognitoVerifier({ maxTokenLifetimeSec: 30 * 60 });
  const token = sign({ sub: 'user-1', client_id: CLIENT_ID, token_use: 'access' }, { signOpts: { expiresIn: '60m' } });
  await assert.rejects(() => v.verify(token), (e) => e.code === 'lifetime_exceeded');
});

test('LIFETIME: the wrappers pass maxTokenLifetimeSec through', async () => {
  const v = createCognitoAccessTokenVerifier({
    region: 'eu-west-2',
    userPoolId: 'eu-west-2_TEST',
    clientId: CLIENT_ID,
    jwksClient: fakeJwks,
    maxTokenLifetimeSec: 60,
  });
  const token = sign({ sub: 'user-1', client_id: CLIENT_ID, token_use: 'access' });
  await assert.rejects(() => v.verify(token), (e) => e.code === 'lifetime_exceeded');
});

test('LIFETIME: a forged token with no exp still fails on its signature, not its lifetime', async () => {
  // The lifetime codes must only ever describe tokens a trusted key signed.
  const v = cognitoVerifier();
  const token = jwt.sign({ ...baseClaims(), iat: nowSec() }, other.privateKey, { algorithm: 'RS256', keyid: KID });
  await assert.rejects(() => v.verify(token), (e) => e.code === 'invalid_token');
});

test('config: maxTokenLifetimeSec must be a positive finite number no greater than 24h', () => {
  const base = { issuer: 'i', audience: 'a', jwksClient: fakeJwks };
  for (const bad of [0, -1, NaN, Infinity, null, '3600', 24 * 3600 + 1]) {
    assert.throws(
      () => createVerifier({ ...base, maxTokenLifetimeSec: bad }),
      /maxTokenLifetimeSec/,
      `maxTokenLifetimeSec=${String(bad)}`
    );
  }
  assert.ok(createVerifier({ ...base, maxTokenLifetimeSec: 24 * 3600 }));
  assert.ok(createVerifier({ ...base, maxTokenLifetimeSec: 1 }));
});
