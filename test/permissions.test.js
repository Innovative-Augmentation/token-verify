'use strict';

/**
 * permissionsFor — reading Plane B grants out of a verified token by the map the
 * CALLER passes in. The package holds no copy of the map, so these tests pass the
 * token contract's `permissions` section as data, and then deliberately different
 * sections to prove the answer comes from what was passed and not from anything
 * remembered here.
 */

const test = require('node:test');
const assert = require('node:assert');

const { permissionsFor } = require('../src/index.js');

// The `permissions` section of the token contract (v1, amended 2026-10-01), as a
// consumer would parse it. Only the fields permissionsFor reads.
const CONTRACT_PERMISSIONS = Object.freeze({
  vocabulary: ['orders:read', 'customers:read', 'vehicles:read', 'drivers:read', 'telemetry:read', 'loads:write'],
  idps: {
    cognito: { claim: 'scope' },
    entra: {
      claim: 'roles',
      map: {
        'orders.read': 'orders:read',
        'customers.read': 'customers:read',
        'vehicles.read': 'vehicles:read',
        'drivers.read': 'drivers:read',
        'telemetry.read': 'telemetry:read',
        'loads.write': 'loads:write',
      },
    },
  },
});

const SCOPE_PREFIX = 'https://capabilities.test.invalid';
const entra = (claims) => permissionsFor(claims, { permissions: CONTRACT_PERMISSIONS, idp: 'entra' });
const cognito = (claims) =>
  permissionsFor(claims, { permissions: CONTRACT_PERMISSIONS, idp: 'cognito', scopePrefix: SCOPE_PREFIX });

// ── Entra: the exact map ───────────────────────────────────────────────────────

test('ENTRA: each role in the map grants exactly its permission', () => {
  for (const [role, permission] of Object.entries(CONTRACT_PERMISSIONS.idps.entra.map)) {
    assert.deepEqual(entra({ roles: [role] }), [permission], role);
  }
  const all = entra({ roles: Object.keys(CONTRACT_PERMISSIONS.idps.entra.map) });
  assert.deepEqual([...all].sort(), [...CONTRACT_PERMISSIONS.vocabulary].sort());
});

test('ENTRA: anything the map does not name grants nothing — no rewriting, no case folding', () => {
  for (const role of [
    'Orders.Read',
    'ORDERS.READ',
    'orders.read.all',
    'orders:read',
    'orders.write',
    ' orders.read',
    'orders.read ',
    'orders_read',
    '__proto__',
    'constructor',
    'toString',
    'hasOwnProperty',
  ]) {
    assert.deepEqual(entra({ roles: [role] }), [], JSON.stringify(role));
  }
});

test('ENTRA: one unknown role does not spoil the known ones beside it', () => {
  assert.deepEqual(entra({ roles: ['orders.read.all', 'customers.read', 'Admin'] }), ['customers:read']);
});

test('ENTRA: roles in the wrong shape grant nothing', () => {
  for (const roles of ['orders.read', { 'orders.read': true }, null, 1, [['orders.read']], [null, 7], undefined]) {
    assert.deepEqual(entra({ roles }), [], JSON.stringify(roles));
  }
});

test('ENTRA: one claim only — scope is never read', () => {
  assert.deepEqual(entra({ scope: `${SCOPE_PREFIX}/orders:read orders:read orders.read` }), []);
});

test('ENTRA: duplicates collapse, and the result is frozen', () => {
  const granted = entra({ roles: ['orders.read', 'orders.read'] });
  assert.deepEqual(granted, ['orders:read']);
  assert.ok(Object.isFrozen(granted));
});

// ── Cognito: per-capability scopes ─────────────────────────────────────────────

test('COGNITO: a scope under our resource server, stripped, is the permission', () => {
  for (const p of CONTRACT_PERMISSIONS.vocabulary) {
    assert.deepEqual(cognito({ scope: `${SCOPE_PREFIX}/${p}` }), [p], p);
  }
  const all = CONTRACT_PERMISSIONS.vocabulary.map((p) => `${SCOPE_PREFIX}/${p}`).join(' ');
  assert.deepEqual([...cognito({ scope: all })].sort(), [...CONTRACT_PERMISSIONS.vocabulary].sort());
});

test('COGNITO: unqualified, foreign, Entra-idiom and lookalike scopes grant nothing', () => {
  for (const scope of [
    'orders:read',
    'https://elsewhere.invalid/orders:read',
    `${SCOPE_PREFIX}/orders.read`,
    `${SCOPE_PREFIX}x/orders:read`,
    `${SCOPE_PREFIX}/Orders:Read`,
    `${SCOPE_PREFIX}/orders:read:all`,
    `${SCOPE_PREFIX}//orders:read`,
    `${SCOPE_PREFIX}/__proto__`,
    '',
  ]) {
    assert.deepEqual(cognito({ scope }), [], JSON.stringify(scope));
  }
});

test('COGNITO: a scope that is not a string grants nothing', () => {
  for (const scope of [[`${SCOPE_PREFIX}/orders:read`], null, 7, undefined]) {
    assert.deepEqual(cognito({ scope }), [], JSON.stringify(scope));
  }
});

test('COGNITO: one claim only — roles are never read', () => {
  assert.deepEqual(cognito({ roles: ['orders.read', 'orders:read'] }), []);
});

test('COGNITO: scopePrefix is required, and without a trailing slash', () => {
  for (const scopePrefix of [undefined, '', `${SCOPE_PREFIX}/`, 7]) {
    assert.throws(
      () => permissionsFor({}, { permissions: CONTRACT_PERMISSIONS, idp: 'cognito', scopePrefix }),
      /scopePrefix/,
      String(scopePrefix)
    );
  }
});

// ── The map comes from the caller, not from the package ────────────────────────

test('SOURCE: a different section gives a different answer — nothing is remembered here', () => {
  const narrowed = {
    vocabulary: ['orders:read'],
    idps: { cognito: { claim: 'scope' }, entra: { claim: 'roles', map: { 'orders.read': 'orders:read' } } },
  };
  assert.deepEqual(permissionsFor({ roles: ['orders.read', 'customers.read'] }, { permissions: narrowed, idp: 'entra' }), [
    'orders:read',
  ]);
  assert.deepEqual(
    permissionsFor(
      { scope: `${SCOPE_PREFIX}/orders:read ${SCOPE_PREFIX}/customers:read` },
      { permissions: narrowed, idp: 'cognito', scopePrefix: SCOPE_PREFIX }
    ),
    ['orders:read']
  );
});

test('SOURCE: the claim each IdP reads is the one the section names', () => {
  const renamed = {
    vocabulary: ['orders:read'],
    idps: { entra: { claim: 'app_roles', map: { 'orders.read': 'orders:read' } } },
  };
  assert.deepEqual(permissionsFor({ roles: ['orders.read'] }, { permissions: renamed, idp: 'entra' }), []);
  assert.deepEqual(permissionsFor({ app_roles: ['orders.read'] }, { permissions: renamed, idp: 'entra' }), ['orders:read']);
});

test('SECTION: a malformed or missing section fails loudly rather than granting nothing', () => {
  const bad = [
    undefined,
    null,
    {},
    { vocabulary: [], idps: CONTRACT_PERMISSIONS.idps },
    { vocabulary: CONTRACT_PERMISSIONS.vocabulary },
    { vocabulary: CONTRACT_PERMISSIONS.vocabulary, idps: { entra: { claim: 'roles' } } },
    { vocabulary: CONTRACT_PERMISSIONS.vocabulary, idps: { entra: { map: CONTRACT_PERMISSIONS.idps.entra.map } } },
    // A map sending a role to something the vocabulary does not define.
    { vocabulary: ['orders:read'], idps: { entra: { claim: 'roles', map: { 'orders.write': 'orders:write' } } } },
  ];
  for (const permissions of bad) {
    assert.throws(() => permissionsFor({ roles: ['orders.read'] }, { permissions, idp: 'entra' }), TypeError, JSON.stringify(permissions));
  }
});

test('SECTION: an idp the section does not define is refused', () => {
  for (const idp of [undefined, 'okta', 'Entra', '__proto__']) {
    assert.throws(() => permissionsFor({}, { permissions: CONTRACT_PERMISSIONS, idp }), TypeError, String(idp));
  }
});
