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

/**
 * Ceiling on `exp - iat` when the caller sets none: two hours.
 *
 * Chosen to sit just above the longest DEFAULT lifetime either issuer we verify
 * actually mints, so the default refuses nothing genuine and everything immortal:
 *
 *   Cognito access tokens   60 min by default (the platform pool issues 30).
 *   Entra access tokens     a random 60-90 min, with `iat`/`nbf` backdated about
 *                           5 min for skew, so `exp - iat` reaches roughly 95 min.
 *
 * One hour would therefore reject a large share of genuine Entra tokens; two
 * leaves headroom without approaching "a day". Each plane is expected to set it
 * LOWER to match its own issuer — the platform's session policy holds Plane A to
 * 60 min (plans/session-security.md).
 */
const DEFAULT_MAX_TOKEN_LIFETIME_SEC = 2 * 60 * 60;

/**
 * The most `maxTokenLifetimeSec` may be raised to. A day is the longest either
 * Cognito's app-client setting or an Entra token-lifetime policy can issue, so
 * anything above it is not accommodating an issuer — it is reopening the hole
 * this check closes, and is refused at construction rather than honoured.
 */
const MAX_TOKEN_LIFETIME_CEILING_SEC = 24 * 60 * 60;

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
 * @param {number}  [opts.clockToleranceSec] Allowed skew, applied to `exp`, `nbf` and
 *                                       the issued-in-the-future check on `iat`.
 * @param {number}  [opts.maxTokenLifetimeSec] Ceiling on `exp - iat`. Defaults to
 *                                       DEFAULT_MAX_TOKEN_LIFETIME_SEC (2 h); must be a
 *                                       positive number no greater than 24 h. Set it
 *                                       lower per plane to match the issuer.
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
    maxTokenLifetimeSec = DEFAULT_MAX_TOKEN_LIFETIME_SEC,
    cacheMaxAgeMs = 10 * 60 * 1000,
    jwksClient,
  } = opts;

  if (!issuer) throw new TypeError('createVerifier: issuer is required');
  if (!audience) throw new TypeError('createVerifier: audience is required');
  if (!jwksUri && !jwksClient) throw new TypeError('createVerifier: jwksUri is required');
  // Validated rather than trusted: `undefined` is replaced by the default above, but
  // `null`, `'3600'`, NaN, 0 or Infinity would each make the comparison below
  // quietly pass or quietly fail everything. A misconfigured ceiling should stop
  // the process at boot, not decide token outcomes at runtime.
  if (
    typeof maxTokenLifetimeSec !== 'number' ||
    !Number.isFinite(maxTokenLifetimeSec) ||
    maxTokenLifetimeSec <= 0 ||
    maxTokenLifetimeSec > MAX_TOKEN_LIFETIME_CEILING_SEC
  ) {
    throw new TypeError(
      `createVerifier: maxTokenLifetimeSec must be a positive number of seconds no greater than ${MAX_TOKEN_LIFETIME_CEILING_SEC}`
    );
  }

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

        // Lifetime is checked only once the signature has verified, so these codes
        // describe tokens a trusted issuer genuinely minted — never a forgery.
        const lifetimeError = checkLifetime(claims, { maxTokenLifetimeSec, clockToleranceSec });
        if (lifetimeError) return reject(lifetimeError);

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

/**
 * jsonwebtoken checks `exp` only when it is present, and treats a token without
 * one as never expiring. So a correctly signed token with no `exp` — or with one
 * set in the year 3000 — was accepted for ever by anything holding a key we trust.
 * Requiring `exp` alone would not close that: the far-future token is the same
 * hole. Bounding `exp - iat` does, and that needs `iat`, so both are required.
 *
 * Absence and malformation are treated alike (a string, null, or anything not a
 * finite number is "no exp"): an issuer that cannot write a NumericDate has not
 * told us when the token ends either. The codes match @innovative-augmentation/
 * session, which applies the same rules at the platform's spine, so a log line
 * means the same thing whichever layer refused.
 *
 * Returns a TokenVerificationError, or null when the lifetime is acceptable.
 */
function checkLifetime(claims, { maxTokenLifetimeSec, clockToleranceSec }) {
  const exp = numericDate(claims.exp);
  if (exp === null) {
    return new TokenVerificationError('token carries no numeric exp', 'no_expiry');
  }

  const iat = numericDate(claims.iat);
  if (iat === null) {
    return new TokenVerificationError(
      'token carries no numeric iat, so its lifetime cannot be bounded',
      'no_issued_at'
    );
  }

  // Without this an issuer could set `iat` close to a far-future `exp` and pass the
  // lifetime check below. The same tolerance as `exp`/`nbf`, so the three clock
  // checks cannot disagree about whose clock is wrong.
  const nowSec = Math.floor(Date.now() / 1000);
  if (iat > nowSec + clockToleranceSec) {
    return new TokenVerificationError('token was issued in the future', 'issued_in_future');
  }

  // No tolerance here: both values come from the issuer's own clock, so skew
  // between us and it does not enter into their difference.
  const lifetimeSec = exp - iat;
  if (lifetimeSec > maxTokenLifetimeSec) {
    return new TokenVerificationError(
      `token lifetime ${lifetimeSec}s exceeds the ${maxTokenLifetimeSec}s ceiling`,
      'token_lifetime_exceeded'
    );
  }

  return null;
}

function numericDate(v) {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

function mapCode(err) {
  // jsonwebtoken refuses a present-but-non-numeric `exp` itself, before our own
  // check runs. Same failure as a missing one, so the same code.
  if (err.message === 'invalid exp value') return 'no_expiry';
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
  DEFAULT_MAX_TOKEN_LIFETIME_SEC,
  MAX_TOKEN_LIFETIME_CEILING_SEC,
};
