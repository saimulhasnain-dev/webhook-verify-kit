import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { verify, verifyGitHub, verifyHmac, verifyShopify, verifySlack, verifyStripe, webhookMiddleware, WebhookVerificationError } from './index.js';

const hmac = (s, d, enc = 'hex') => createHmac('sha256', s).update(d).digest(enc);
const body = '{"id":"evt_1","amount":1000}';
const codeOf = (fn) => { try { fn(); } catch (e) { assert.ok(e instanceof WebhookVerificationError, String(e)); return e.code; } return 'NO_ERROR'; };

test('GitHub: valid, tampered body, wrong secret, missing, bad prefix', () => {
  const sig = 'sha256=' + hmac('s3', body);
  assert.equal(verifyGitHub(body, sig, 's3'), true);
  assert.equal(codeOf(() => verifyGitHub(body + ' ', sig, 's3')), 'BAD_SIGNATURE');
  assert.equal(codeOf(() => verifyGitHub(body, sig, 'other')), 'BAD_SIGNATURE');
  assert.equal(codeOf(() => verifyGitHub(body, undefined, 's3')), 'MISSING_SIGNATURE');
  assert.equal(codeOf(() => verifyGitHub(body, hmac('s3', body), 's3')), 'MALFORMED_SIGNATURE');
});

test('Shopify: base64 HMAC, Buffer body', () => {
  assert.equal(verifyShopify(Buffer.from(body), hmac('k', body, 'base64'), 'k'), true);
  assert.equal(codeOf(() => verifyShopify(body, hmac('k', body), 'k')), 'BAD_SIGNATURE');
});

test('Stripe: valid, replay window, multiple v1, malformed', () => {
  const t = 1_700_000_000;
  const header = `t=${t},v1=${hmac('whsec', `${t}.${body}`)}`;
  assert.equal(verifyStripe(body, header, 'whsec', { now: t * 1000 + 10_000 }), true);
  assert.equal(codeOf(() => verifyStripe(body, header, 'whsec', { now: t * 1000 + 301_000 })), 'TIMESTAMP_TOO_OLD');
  assert.equal(verifyStripe(body, header, 'whsec', { now: t * 1000 + 301_000, tolerance: 600 }), true);
  assert.equal(verifyStripe(body, `t=${t},v1=deadbeef,v1=${hmac('whsec', `${t}.${body}`)}`, 'whsec', { now: t * 1000 }), true);
  assert.equal(codeOf(() => verifyStripe(body, `t=${t},v1=${hmac('x', `${t}.${body}`)}`, 'whsec', { now: t * 1000 })), 'BAD_SIGNATURE');
  assert.equal(codeOf(() => verifyStripe(body, 'garbage', 'whsec')), 'MALFORMED_SIGNATURE');
  // forging a fresh timestamp on an old signature must fail
  assert.equal(codeOf(() => verifyStripe(body, `t=${t + 5},v1=${hmac('whsec', `${t}.${body}`)}`, 'whsec', { now: t * 1000 })), 'BAD_SIGNATURE');
});

test('Slack: valid, stale, missing timestamp', () => {
  const ts = '1700000000';
  const signature = 'v0=' + hmac('slack', `v0:${ts}:${body}`);
  assert.equal(verifySlack(body, { signature, timestamp: ts }, 'slack', { now: 1_700_000_100_000 }), true);
  assert.equal(codeOf(() => verifySlack(body, { signature, timestamp: ts }, 'slack', { now: 1_700_001_000_000 })), 'TIMESTAMP_TOO_OLD');
  assert.equal(codeOf(() => verifySlack(body, { signature }, 'slack')), 'MISSING_TIMESTAMP');
  assert.equal(codeOf(() => verifySlack(body, { signature: 'v1=x', timestamp: ts }, 'slack', { now: 1_700_000_000_000 })), 'MALFORMED_SIGNATURE');
});

test('secret rotation: old or new secret accepted', () => {
  const sig = 'sha256=' + hmac('old', body);
  assert.equal(verifyGitHub(body, sig, ['new', 'old']), true);
  assert.equal(codeOf(() => verifyGitHub(body, sig, ['new', 'newer'])), 'BAD_SIGNATURE');
});

test('parsed object body and missing secret are programming errors', () => {
  assert.throws(() => verifyGitHub({ id: 1 }, 'sha256=x', 's'), /RAW request body/);
  assert.throws(() => verifyGitHub(body, 'sha256=x', ''), /secret is required/);
  assert.throws(() => verify('paypal', { body, headers: {}, secret: 's' }), /Unknown provider/);
});

test('verify() reads headers case-insensitively', () => {
  const sig = 'sha256=' + hmac('s', body);
  assert.equal(verify('github', { body, headers: { 'X-Hub-Signature-256': sig }, secret: 's' }), true);
  assert.equal(verify('github', { body, headers: { 'x-hub-signature-256': [sig] }, secret: 's' }), true);
});

test('generic verifyHmac with sha1 and different length signature', () => {
  const s1 = createHmac('sha1', 'k').update(body).digest('hex');
  assert.equal(verifyHmac(body, s1, 'k', { algorithm: 'sha1' }), true);
  assert.equal(codeOf(() => verifyHmac(body, 'ab', 'k')), 'BAD_SIGNATURE');
});

test('middleware: 400 on bad signature, next() on good, uses rawBody', () => {
  const mw = webhookMiddleware('github', 's');
  const res = { status(c) { this.code = c; return this; }, json(b) { this.body = b; return this; } };
  let called = 0;
  mw({ rawBody: body, headers: { 'x-hub-signature-256': 'sha256=' + hmac('s', body) } }, res, () => called++);
  assert.equal(called, 1);
  mw({ rawBody: body, headers: { 'x-hub-signature-256': 'sha256=00' } }, res, () => called++);
  assert.equal(called, 1);
  assert.equal(res.code, 400);
  assert.equal(res.body.error.code, 'BAD_SIGNATURE');
});
