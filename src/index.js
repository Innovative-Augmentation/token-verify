'use strict';

/**
 * Shared JWT verification — one implementation, consumed by the platform API and by
 * ne-scheduling across repos. See plans/auth.md.
 *
 * Deliberately issuer-agnostic, because auth here has TWO PLANES with two issuers:
 *
 *   Plane A  user   -> platform          tokens issued by our Cognito pool
 *   Plane B  platform -> tenant service  tokens issued by the TENANT's IdP (NE = Entra)
 *
 * You create a SEPARATE verifier per plane and mount exactly one per route. That is
 * not a stylistic choice: a single middleware that accepts either issuer would let a
 * platform service token be replayed against a user endpoint. Keeping the instances
 * distinct makes the planes structurally un-swappable rather than relying on care.
 *
 * This module authenticates only. It answers "who is this?" and never "may they?" —
 * roles are resolved server-side per request (P1.4/P1.7) and are deliberately absent
 * from the token so that revoking one takes effect on the next request.
 */

const jwt = require('jsonwebtoken');
const jwksRsa = require('jwks-rsa');

class TokenVerificationError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'TokenVerificationError';
    this.code = code;
  }
}

/**
 * @param {object}   opts
 * @param {string}   opts.issuer         Expected `iss`. Exact match.
 * @param {string}   opts.audience       Expected audience value.
 * @param {string}   opts.jwksUri        JWKS endpoint of the issuer.
 * @param {string}  [opts.audienceClaim] Claim carrying the audience. 'aud' by default;
 *                                       use 'client_id' for COGNITO ACCESS TOKENS, which
 *                                       carry no `aud` at all — only Cognito *ID* tokens
 *                                       do. Verifying `aud` against an access token fails
 *                                       for a reason that looks nothing like the cause.
 * @param {string}  [opts.tokenUse]      If set, require this `token_use` ('access' | 'id').
 *                                       Cognito-specific; stops an ID token being presented
 *                                       where an access token is expected.
 * @param {string[]}[opts.algorithms]    Permitted algorithms. Defaults to RS256 only.
 * @param {number}  [opts.clockToleranceSec]
 * @param {number}  [opts.cacheMaxAgeMs] JWKS cache lifetime.
 * @param {object}  [opts.jwksClient]    Injectable key client (tests).
 */
function createVerifier(opts = {}) {
  const {
    issuer,
    audience,
    jwksUri,
    audienceClaim = 'aud',
    tokenUse = null,
    // Pinned. Without an explicit allow-list, jsonwebtoken will honour the token's own
    // `alg` header — which is how algorithm-confusion and `alg: none` attacks work.
    algorithms = ['RS256'],
    clockToleranceSec = 5,
    cacheMaxAgeMs = 10 * 60 * 1000,
    jwksClient,
  } = opts;

  if (!issuer) throw new TypeError('createVerifier: issuer is required');
  if (!audience) throw new TypeError('createVerifier: audience is required');
  if (!jwksUri && !jwksClient) throw new TypeError('createVerifier: jwksUri is required');

  const client =
    jwksClient ||
    jwksRsa({
      jwksUri,
      cache: true,
      cacheMaxAge: cacheMaxAgeMs,
      rateLimit: true,
      jwksRequestsPerMinute: 10,
    });

  function getKey(header, callback) {
    if (!header || !header.kid) {
      return callback(new TokenVerificationError('token header has no kid', 'no_kid'));
    }
    client.getSigningKey(header.kid, (err, key) => {
      if (err) return callback(err);
      callback(null, key.getPublicKey ? key.getPublicKey() : key.publicKey || key.rsaPublicKey);
    });
  }

  /**
   * Verify a raw token string. Resolves with the claims, rejects with
   * TokenVerificationError. Callers should not surface the reason to clients.
   */
  function verify(token) {
    return new Promise((resolve, reject) => {
      if (!token) {
        return reject(new TokenVerificationError('no token supplied', 'missing_token'));
      }

      const verifyOpts = {
        issuer,
        algorithms,
        clockTolerance: clockToleranceSec,
      };
      // Only let jsonwebtoken check `aud` when that is genuinely where the audience
      // lives; otherwise we check the configured claim ourselves below.
      if (audienceClaim === 'aud') verifyOpts.audience = audience;

      jwt.verify(token, getKey, verifyOpts, (err, claims) => {
        if (err) {
          return reject(new TokenVerificationError(err.message, mapCode(err)));
        }

        if (audienceClaim !== 'aud' && claims[audienceClaim] !== audience) {
          return reject(
            new TokenVerificationError(
              `expected ${audienceClaim} to be ${audience}`,
              'audience_mismatch'
            )
          );
        }

        if (tokenUse && claims.token_use !== tokenUse) {
          return reject(
            new TokenVerificationError(
              `expected token_use ${tokenUse}, got ${claims.token_use}`,
              'wrong_token_use'
            )
          );
        }

        resolve(claims);
      });
    });
  }

  /**
   * Express middleware. Attaches `req.auth = { sub, tenantId, claims }` on success.
   *
   * On failure it responds 401 with no detail — the reason goes to `onError` for
   * server-side logging (P1.10) and never to the caller, so a probe cannot use the
   * response to learn why a token was rejected.
   */
  function middleware({ onError = null } = {}) {
    return function tokenVerifyMiddleware(req, res, next) {
      const header = req.headers && req.headers.authorization;
      const token =
        header && header.startsWith('Bearer ') ? header.slice('Bearer '.length).trim() : null;

      verify(token)
        .then((claims) => {
          req.auth = {
            sub: claims.sub,
            // Derived from the IdP connection at federation time, so it cannot be
            // forged by anything the caller supplies. See plans/auth.md.
            tenantId: claims['custom:tenant_id'] || claims.tenant_id || null,
            claims,
          };
          next();
        })
        .catch((err) => {
          if (onError) onError(err, req);
          res.status(401).json({ error: 'unauthorized' });
        });
    };
  }

  return { verify, middleware };
}

function mapCode(err) {
  if (err.name === 'TokenExpiredError') return 'expired';
  if (err.name === 'NotBeforeError') return 'not_yet_valid';
  // jsonwebtoken wraps anything thrown by the key callback as "error in secret or
  // public key callback: <message>", discarding the original error object — so the
  // code has to be recovered from the message rather than read off the cause.
  if (/public key callback/i.test(err.message)) {
    if (/no kid/i.test(err.message)) return 'no_kid';
    return 'key_lookup_failed';
  }
  if (/audience/i.test(err.message)) return 'audience_mismatch';
  if (/issuer/i.test(err.message)) return 'issuer_mismatch';
  if (/algorithm/i.test(err.message)) return 'algorithm_mismatch';
  return 'invalid_token';
}

/**
 * Plane A convenience wrapper. Cognito access tokens carry `client_id` rather than
 * `aud`, so the defaults here differ from the generic case on purpose.
 */
function createCognitoAccessTokenVerifier({ region, userPoolId, clientId, ...rest }) {
  const issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
  return createVerifier({
    issuer,
    audience: clientId,
    audienceClaim: 'client_id',
    tokenUse: 'access',
    jwksUri: `${issuer}/.well-known/jwks.json`,
    ...rest,
  });
}

/**
 * Plane B convenience wrapper. The tenant's directory is the issuer — not ours.
 * Entra uses the standard `aud` claim, so the generic defaults apply.
 */
function createEntraVerifier({ tenantId, audience, ...rest }) {
  return createVerifier({
    issuer: `https://login.microsoftonline.com/${tenantId}/v2.0`,
    audience,
    jwksUri: `https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`,
    ...rest,
  });
}

module.exports = {
  createVerifier,
  createCognitoAccessTokenVerifier,
  createEntraVerifier,
  TokenVerificationError,
};
