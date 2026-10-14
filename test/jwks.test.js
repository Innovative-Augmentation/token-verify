'use strict';

/**
 * JWKS behaviour through the real jwks-rsa client, against a JWKS server on
 * 127.0.0.1 started by the test itself. No network beyond loopback: the other test
 * files inject a fake key client, which cannot show rotation, a refresh on a kid
 * miss, or what happens when the rate limit runs out.
 */

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const http = require('node:http');
const jwt = require('jsonwebtoken');

const { createVerifier } = require('../src/index.js');

const ISSUER = 'https://issuer.test.invalid';
const AUDIENCE = 'test-audience';

const newKey = (kid) => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg: 'RS256' };
  return { kid, privateKey, jwk };
};

const sign = (key, kid = key.kid) =>
  jwt.sign({ sub: 'svc' }, key.privateKey, { algorithm: 'RS256', keyid: kid, issuer: ISSUER, audience: AUDIENCE, expiresIn: '5m' });

/** A JWKS endpoint whose key set the test can change, and whose hits it can count. */
async function jwksServer(initial) {
  const state = { keys: [...initial], hits: 0 };
  const server = http.createServer((req, res) => {
    state.hits += 1;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ keys: state.keys.map((k) => k.jwk) }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  state.uri = `http://127.0.0.1:${server.address().port}/jwks.json`;
  state.close = () => new Promise((resolve) => server.close(resolve));
  return state;
}

const verifierFor = (uri) => createVerifier({ issuer: ISSUER, audience: AUDIENCE, jwksUri: uri });

test('JWKS: a key that appears after startup verifies — a kid miss refreshes the set', async (t) => {
  const first = newKey('kid-1');
  const second = newKey('kid-2');
  const server = await jwksServer([first]);
  t.after(server.close);
  const v = verifierFor(server.uri);

  await v.verify(sign(first));
  // Rotation: the issuer publishes a new key. Its kid is not in our cache.
  server.keys.push(second);
  const claims = await v.verify(sign(second));
  assert.equal(claims.sub, 'svc');
  // The old key keeps working while the issuer still publishes it.
  await v.verify(sign(first));
});

test('JWKS: a kid the issuer does not publish is key_lookup_failed', async (t) => {
  const server = await jwksServer([newKey('kid-1')]);
  t.after(server.close);
  const v = verifierFor(server.uri);
  const stranger = newKey('kid-unknown');
  await assert.rejects(
    () => v.verify(sign(stranger)),
    (e) => e.code === 'key_lookup_failed' && e.httpStatus === 401
  );
});

test('JWKS: a key rotated out of the set stops verifying once it is no longer cached', async (t) => {
  const first = newKey('kid-1');
  const server = await jwksServer([first]);
  t.after(server.close);
  // cacheMaxAgeMs: 1 so the cached entry expires and the next lookup goes back to the issuer.
  const v = createVerifier({ issuer: ISSUER, audience: AUDIENCE, jwksUri: server.uri, cacheMaxAgeMs: 1 });
  await v.verify(sign(first));
  server.keys = [newKey('kid-2')];
  await new Promise((resolve) => setTimeout(resolve, 20));
  await assert.rejects(() => v.verify(sign(first)), (e) => e.code === 'key_lookup_failed');
});

test('JWKS: when the rate limit is spent the lookup fails closed, without another request', async (t) => {
  const known = newKey('kid-1');
  const server = await jwksServer([known]);
  t.after(server.close);
  const v = verifierFor(server.uri); // jwksRequestsPerMinute: 10, set by createVerifier

  // Unknown kids are never cached, so each one costs a request to the issuer.
  for (let i = 0; i < 10; i += 1) {
    await assert.rejects(() => v.verify(sign(newKey(`probe-${i}`))), (e) => e.code === 'key_lookup_failed');
  }
  assert.equal(server.hits, 10);

  // The allowance is gone. A genuine token whose key is not yet cached is refused
  // rather than waved through, and the issuer is not asked again.
  await assert.rejects(
    () => v.verify(sign(known)),
    (e) => e.code === 'key_lookup_failed' && e.httpStatus === 401
  );
  assert.equal(server.hits, 10);
});
