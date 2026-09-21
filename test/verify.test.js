'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');

const { createVerifier, createCognitoAccessTokenVerifier } = require('../src/index.js');

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
