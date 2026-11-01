import { createHmac, timingSafeEqual } from 'node:crypto';

export class WebhookVerificationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'WebhookVerificationError';
    this.code = code; // MISSING_SIGNATURE | MALFORMED_SIGNATURE | BAD_SIGNATURE | TIMESTAMP_TOO_OLD | MISSING_TIMESTAMP
  }
}

const fail = (code, msg) => { throw new WebhookVerificationError(code, msg); };

function rawBody(body) {
  if (typeof body === 'string' || Buffer.isBuffer(body)) return body;
  throw new TypeError('body must be the RAW request body (string or Buffer), not a parsed object. In Express use express.raw({ type: "*/*" }) or capture req.rawBody.');
}
const secretList = (s) => {
  const list = (Array.isArray(s) ? s : [s]).filter((x) => typeof x === 'string' && x.length);
  if (!list.length) throw new TypeError('secret is required (a string, or an array of strings for rotation)');
  return list;
};
const mac = (secret, data, algo, enc) => createHmac(algo, secret).update(data).digest(enc);

function safeEqual(a, b) {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
/** True if `expected` matches the HMAC of `data` under any of the secrets. Constant-time per comparison. */
function matches(secrets, data, given, algo, enc) {
  let ok = false;
  for (const s of secrets) if (safeEqual(mac(s, data, algo, enc), given)) ok = true; // no early exit
  return ok;
}
function checkAge(tsSeconds, tolerance, now) {
  if (!Number.isFinite(tsSeconds)) fail('MALFORMED_SIGNATURE', 'Timestamp is not a number');
  if (Math.abs(Math.floor(now / 1000) - tsSeconds) > tolerance) fail('TIMESTAMP_TOO_OLD', `Timestamp is outside the ${tolerance}s tolerance`);
}

/** Generic HMAC check. Returns true or throws. encoding: 'hex' (default) | 'base64'. prefix e.g. 'sha256='. */
export function verifyHmac(body, signature, secret, { algorithm = 'sha256', encoding = 'hex', prefix = '' } = {}) {
  body = rawBody(body);
  const secrets = secretList(secret);
  if (!signature) fail('MISSING_SIGNATURE', 'Signature header is missing');
  let given = String(signature).trim();
  if (prefix) {
    if (!given.startsWith(prefix)) fail('MALFORMED_SIGNATURE', `Signature must start with "${prefix}"`);
    given = given.slice(prefix.length);
  }
  if (!matches(secrets, body, given, algorithm, encoding)) fail('BAD_SIGNATURE', 'Signature does not match');
  return true;
}

export const verifyGitHub = (body, header, secret) => verifyHmac(body, header, secret, { prefix: 'sha256=' });
export const verifyShopify = (body, header, secret) => verifyHmac(body, header, secret, { encoding: 'base64' });

/** Stripe-Signature: t=timestamp,v1=sig[,v1=sig2]. Signed payload is `${t}.${body}`. */
export function verifyStripe(body, header, secret, { tolerance = 300, now = Date.now() } = {}) {
  body = rawBody(body);
  const secrets = secretList(secret);
  if (!header) fail('MISSING_SIGNATURE', 'Stripe-Signature header is missing');
  const parts = String(header).split(',').map((p) => p.split('='));
  const t = parts.find(([k]) => k.trim() === 't')?.[1];
  const sigs = parts.filter(([k]) => k.trim() === 'v1').map(([, v]) => v);
  if (!t || !sigs.length) fail('MALFORMED_SIGNATURE', 'Stripe-Signature must contain t= and v1=');
  const signed = `${t}.${body.toString()}`;
  let ok = false;
  for (const sig of sigs) if (matches(secrets, signed, sig, 'sha256', 'hex')) ok = true;
  if (!ok) fail('BAD_SIGNATURE', 'Signature does not match');
  checkAge(Number(t), tolerance, now); // checked after the signature so an attacker learns nothing from timing of old-vs-bad
  return true;
}

/** Slack: X-Slack-Signature "v0=hex" over `v0:${timestamp}:${body}`, X-Slack-Request-Timestamp in seconds. */
export function verifySlack(body, { signature, timestamp }, secret, { tolerance = 300, now = Date.now() } = {}) {
  body = rawBody(body);
  const secrets = secretList(secret);
  if (!signature) fail('MISSING_SIGNATURE', 'X-Slack-Signature header is missing');
  if (!timestamp) fail('MISSING_TIMESTAMP', 'X-Slack-Request-Timestamp header is missing');
  checkAge(Number(timestamp), tolerance, now);
  if (!String(signature).startsWith('v0=')) fail('MALFORMED_SIGNATURE', 'Signature must start with "v0="');
  if (!matches(secrets, `v0:${timestamp}:${body.toString()}`, String(signature).slice(3), 'sha256', 'hex')) fail('BAD_SIGNATURE', 'Signature does not match');
  return true;
}

/**
 * One call for any provider, straight from request headers (case-insensitive).
 * provider: 'stripe' | 'github' | 'shopify' | 'slack'
 */
export function verify(provider, { body, headers, secret, tolerance, now }) {
  const h = Object.fromEntries(Object.entries(headers ?? {}).map(([k, v]) => [k.toLowerCase(), Array.isArray(v) ? v[0] : v]));
  const opts = { ...(tolerance !== undefined && { tolerance }), ...(now !== undefined && { now }) };
  switch (provider) {
    case 'stripe': return verifyStripe(body, h['stripe-signature'], secret, opts);
    case 'github': return verifyGitHub(body, h['x-hub-signature-256'], secret);
    case 'shopify': return verifyShopify(body, h['x-shopify-hmac-sha256'], secret);
    case 'slack': return verifySlack(body, { signature: h['x-slack-signature'], timestamp: h['x-slack-request-timestamp'] }, secret, opts);
    default: throw new TypeError(`Unknown provider "${provider}". Use stripe, github, shopify, slack, or verifyHmac()`);
  }
}

/** Express/Connect middleware. Needs the raw body on req.rawBody, or req.body as Buffer/string (express.raw). */
export function webhookMiddleware(provider, secret, options = {}) {
  return (req, res, next) => {
    try {
      verify(provider, { body: req.rawBody ?? req.body, headers: req.headers, secret, ...options });
      next();
    } catch (e) {
      if (e instanceof WebhookVerificationError) return res.status(400).json({ error: { code: e.code, message: e.message } });
      next(e);
    }
  };
}
