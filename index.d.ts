export type VerifyErrorCode = 'MISSING_SIGNATURE' | 'MALFORMED_SIGNATURE' | 'BAD_SIGNATURE' | 'TIMESTAMP_TOO_OLD' | 'MISSING_TIMESTAMP';
export class WebhookVerificationError extends Error { readonly code: VerifyErrorCode }
type Body = string | Buffer;
type Secret = string | string[];
export interface TimeOptions { tolerance?: number; now?: number }
export function verifyHmac(body: Body, signature: string | undefined, secret: Secret, options?: { algorithm?: string; encoding?: 'hex' | 'base64'; prefix?: string }): true;
export function verifyGitHub(body: Body, header: string | undefined, secret: Secret): true;
export function verifyShopify(body: Body, header: string | undefined, secret: Secret): true;
export function verifyStripe(body: Body, header: string | undefined, secret: Secret, options?: TimeOptions): true;
export function verifySlack(body: Body, headers: { signature?: string; timestamp?: string }, secret: Secret, options?: TimeOptions): true;
export function verify(provider: 'stripe' | 'github' | 'shopify' | 'slack', input: { body: Body; headers: Record<string, string | string[] | undefined>; secret: Secret } & TimeOptions): true;
export function webhookMiddleware(provider: 'stripe' | 'github' | 'shopify' | 'slack', secret: Secret, options?: TimeOptions): (req: any, res: any, next: (err?: unknown) => void) => void;
