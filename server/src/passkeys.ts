import { randomBytes } from 'node:crypto';
import type { Context } from 'hono';
import { config } from './config.js';
import { db } from './db.js';

// the origin the browser sees. PUBLIC_URL wins, otherwise what the proxy (when trusted) or the request says
export function publicOrigin(c: Context): string {
  if (config.publicUrl) return new URL(config.publicUrl).origin;
  const proto = (config.trustProxy && c.req.header('x-forwarded-proto')?.split(',')[0].trim()) || (config.cookieSecure ? 'https' : 'http');
  const host = (config.trustProxy && c.req.header('x-forwarded-host')?.split(',')[0].trim()) || c.req.header('host') || 'localhost';
  return `${proto}://${host}`;
}
export const rpId = (c: Context) => new URL(publicOrigin(c)).hostname;

// one-shot challenges, five minutes
const pending = new Map<string, { kind: 'register' | 'login'; userId?: number; until: number }>();
export function newChallenge(kind: 'register' | 'login', userId?: number): string {
  const now = Date.now();
  for (const [k, v] of pending) if (v.until < now) pending.delete(k);
  if (pending.size > 5000) throw new Error('too many sign-ins in flight, try again in a minute');
  const challenge = randomBytes(32).toString('base64url');
  pending.set(challenge, { kind, userId, until: now + 5 * 60_000 });
  return challenge;
}
export function takeChallenge(challenge: string, kind: 'register' | 'login', userId?: number): boolean {
  const p = pending.get(challenge);
  if (!p) return false;
  pending.delete(challenge);
  return p.kind === kind && p.until > Date.now() && p.userId === userId;
}
// the challenge the browser signed, read before the signature is checked to know which one to take
export function challengeOf(clientDataJSON: unknown): string {
  try { return JSON.parse(Buffer.from(String(clientDataJSON), 'base64url').toString('utf8')).challenge ?? ''; } catch { return ''; }
}

export interface Passkey { id: string; user_id: number; name: string; public_key: string; alg: number; counter: number; created_at: number; last_used_at: number | null }
export const passkeysOf = (userId: number) =>
  db.prepare('SELECT id, name, created_at, last_used_at FROM passkeys WHERE user_id = ? ORDER BY created_at').all(userId) as Pick<Passkey, 'id' | 'name' | 'created_at' | 'last_used_at'>[];
export const passkeyById = (id: string) => db.prepare('SELECT * FROM passkeys WHERE id = ?').get(id) as Passkey | undefined;
export const hasPasskey = (userId: number) => !!db.prepare('SELECT 1 FROM passkeys WHERE user_id = ? LIMIT 1').get(userId);
