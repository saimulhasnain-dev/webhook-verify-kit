# webhook-verify-kit

Verify incoming webhooks the right way in a few lines. Handles Stripe, GitHub, Shopify, Slack and any generic HMAC scheme, with constant-time comparison, replay protection and secret rotation. Zero dependencies, TypeScript types included.

## What it does

Webhook endpoints are public URLs. Anyone can POST to them, so you must check the signature before trusting the payload. Doing this by hand goes wrong in familiar ways: comparing with `===` (timing attack), verifying a re-serialised JSON body instead of the raw bytes, forgetting the timestamp check (replay attacks), or breaking when you rotate a secret. This package does those parts correctly and throws a `WebhookVerificationError` with a stable `code` when anything is off.

## Install

```sh
npm install webhook-verify-kit
```

## Usage

```js
import { verify } from 'webhook-verify-kit';

// body MUST be the raw request body (string or Buffer)
verify('stripe', { body: rawBody, headers: req.headers, secret: process.env.STRIPE_WEBHOOK_SECRET });
// returns true, or throws WebhookVerificationError
```

## API

- `verify(provider, { body, headers, secret, tolerance?, now? })` provider is `'stripe' | 'github' | 'shopify' | 'slack'`. Header names are case-insensitive.
- `verifyStripe(body, stripeSignatureHeader, secret, { tolerance = 300 })`: signed payload `t.body`, rejects timestamps older than `tolerance` seconds, accepts several `v1` signatures.
- `verifyGitHub(body, xHubSignature256, secret)`
- `verifyShopify(body, xShopifyHmacSha256, secret)`
- `verifySlack(body, { signature, timestamp }, secret, { tolerance = 300 })`
- `verifyHmac(body, signature, secret, { algorithm = 'sha256', encoding = 'hex', prefix = '' })` for any other provider.
- `webhookMiddleware(provider, secret, options?)` Express/Connect middleware: responds 400 with `{ error: { code, message } }` on failure, otherwise calls `next()`.
- `secret` may be a string or an array of strings, so you can accept the old and new secret during rotation.
- Error codes: `MISSING_SIGNATURE`, `MALFORMED_SIGNATURE`, `BAD_SIGNATURE`, `TIMESTAMP_TOO_OLD`, `MISSING_TIMESTAMP`.
- Passing a parsed object as `body`, an empty secret or an unknown provider throws a `TypeError`: those are programming mistakes, not attacks.

## Where to use it

- Any HTTP endpoint that receives webhooks from Stripe, GitHub, Shopify or Slack.
- Your own webhooks to customers: use `verifyHmac` on the receiving side with the same scheme.
- Serverless handlers (Lambda, Cloud Functions, Vercel) where you get the raw body as a string.

## Integrate

```js
import express from 'express';
import { webhookMiddleware } from 'webhook-verify-kit';

const app = express();
// raw body is required: do NOT use express.json() on this route
app.post('/webhooks/stripe', express.raw({ type: '*/*' }),
  webhookMiddleware('stripe', process.env.STRIPE_WEBHOOK_SECRET),
  (req, res) => {
    const event = JSON.parse(req.body.toString());
    // handle event ...
    res.sendStatus(200);
  });
```

Manual use with your own error handling:

```js
import { verify, WebhookVerificationError } from 'webhook-verify-kit';
try { verify('github', { body, headers, secret }); }
catch (e) { if (e instanceof WebhookVerificationError) return reply(400, e.code); throw e; }
```

## Limitations

- It checks the signature and timestamp; it does not de-duplicate events. Store event ids if a repeat delivery must not run twice.
- Replay protection works only for providers that sign a timestamp (Stripe, Slack). GitHub and Shopify signatures have no timestamp.
- Only HMAC schemes are covered; providers using public-key signatures (for example some Twilio or PayPal flows) are not.
