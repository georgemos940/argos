import { constants, createHash, createPublicKey, randomBytes, verify } from 'node:crypto';
import { db, getSetting } from './db.js';
import { hashPassword, type Role } from './auth.js';

// openid connect, authorization code + pkce. any provider with discovery: authentik, keycloak, authelia,
// google, entra id, okta, zitadel, pocket id

export interface SsoSettings {
  enabled: boolean;
  issuer: string;
  clientId: string;
  clientSecret: string;
  label: string;
  // comma separated, empty means any
  allowedDomains: string;
  // sign-ins of people without an account here create one
  autoCreate: boolean;
  defaultRole: Role;
  // roles from a groups claim; when set, the provider decides the role on every sign-in
  groupsClaim: string;
  adminGroup: string;
  operatorGroup: string;
  viewerGroup: string;
}

export const SSO_DEFAULTS: SsoSettings = {
  enabled: false, issuer: '', clientId: '', clientSecret: '', label: 'SSO', allowedDomains: '', autoCreate: false, defaultRole: 'viewer',
  groupsClaim: '', adminGroup: '', operatorGroup: '', viewerGroup: '',
};
export const ssoSettings = (): SsoSettings => ({ ...SSO_DEFAULTS, ...getSetting<Partial<SsoSettings>>('sso', {}) });
export const ssoReady = (s = ssoSettings()) => s.enabled && !!s.issuer && !!s.clientId;

interface Discovery { issuer: string; authorization_endpoint: string; token_endpoint: string; jwks_uri: string }
const cache = new Map<string, { at: number; data: any }>();
async function getJson(url: string, ttl: number, fresh = false): Promise<any> {
  const hit = cache.get(url);
  if (!fresh && hit && Date.now() - hit.at < ttl) return hit.data;
  const r = await fetch(url, { signal: AbortSignal.timeout(8000), headers: { Accept: 'application/json' } });
  if (!r.ok) throw new Error(`${new URL(url).host} answered ${r.status}`);
  const data = await r.json();
  cache.set(url, { at: Date.now(), data });
  return data;
}

export async function discover(issuer: string): Promise<Discovery> {
  const d = await getJson(`${issuer.replace(/\/+$/, '')}/.well-known/openid-configuration`, 3600_000);
  for (const k of ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri']) if (typeof d[k] !== 'string') throw new Error(`discovery has no ${k}`);
  return d;
}

// state -> what the callback needs; the state also sits in a cookie so only the browser that started can finish
const pending = new Map<string, { verifier: string; nonce: string; linkUserId?: number; until: number }>();

export async function startSignIn(s: SsoSettings, redirectUri: string, linkUserId?: number): Promise<{ url: string; state: string }> {
  const d = await discover(s.issuer);
  const now = Date.now();
  for (const [k, v] of pending) if (v.until < now) pending.delete(k);
  if (pending.size > 5000) throw new Error('too many sign-ins in flight');
  const state = randomBytes(24).toString('base64url');
  const nonce = randomBytes(24).toString('base64url');
  const verifier = randomBytes(48).toString('base64url');
  pending.set(state, { verifier, nonce, linkUserId, until: now + 10 * 60_000 });
  const u = new URL(d.authorization_endpoint);
  const scope = ['openid', 'email', 'profile', ...(s.groupsClaim === 'groups' ? ['groups'] : [])].join(' ');
  for (const [k, v] of Object.entries({
    response_type: 'code', client_id: s.clientId, redirect_uri: redirectUri, scope, state, nonce,
    code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256',
  })) u.searchParams.set(k, v);
  return { url: u.toString(), state };
}

const b64json = (s: string) => JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));

export async function verifyIdToken(idToken: string, d: Discovery, clientId: string, nonce: string): Promise<Record<string, any>> {
  const parts = idToken.split('.');
  if (parts.length !== 3) throw new Error('id token is not a jwt');
  const [h, p, sig] = parts;
  const header = b64json(h);
  const claims = b64json(p);
  const find = (jwks: any) => (jwks.keys ?? []).find((k: any) => (header.kid ? k.kid === header.kid : true) && (!k.use || k.use === 'sig'));
  let jwk = find(await getJson(d.jwks_uri, 3600_000));
  // keys rotate: an unknown kid gets one fresh fetch
  if (!jwk) jwk = find(await getJson(d.jwks_uri, 0, true));
  if (!jwk) throw new Error('id token signed with an unknown key');
  const key = createPublicKey({ key: jwk, format: 'jwk' });
  const data = Buffer.from(`${h}.${p}`);
  const s = Buffer.from(sig, 'base64url');
  const ok = header.alg === 'RS256' ? verify('sha256', data, key, s)
    : header.alg === 'PS256' ? verify('sha256', data, { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, s)
    : header.alg === 'ES256' ? verify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, s)
    : header.alg === 'EdDSA' ? verify(null, data, key, s)
    : (() => { throw new Error(`id token alg ${header.alg} not supported`); })();
  if (!ok) throw new Error('id token signature is wrong');
  const now = Date.now() / 1000;
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (claims.iss !== d.issuer) throw new Error('id token from another issuer');
  if (!aud.includes(clientId) || (aud.length > 1 && claims.azp && claims.azp !== clientId)) throw new Error('id token for another client');
  if (typeof claims.exp !== 'number' || claims.exp < now - 60) throw new Error('id token expired');
  if (typeof claims.iat === 'number' && claims.iat > now + 120) throw new Error('id token from the future, check the clock');
  if (claims.nonce !== nonce) throw new Error('id token nonce mismatch');
  if (typeof claims.sub !== 'string' || !claims.sub) throw new Error('id token without a subject');
  return claims;
}

export async function finishSignIn(s: SsoSettings, redirectUri: string, q: { code?: string; state?: string; error?: string; error_description?: string }, cookieState?: string) {
  if (q.error) throw new Error(q.error_description || q.error);
  if (!q.state || !q.code || q.state !== cookieState) throw new Error('sign-in was not started in this browser, start again');
  const p = pending.get(q.state);
  pending.delete(q.state);
  if (!p || p.until < Date.now()) throw new Error('sign-in took too long, start again');
  const d = await discover(s.issuer);
  const r = await fetch(d.token_endpoint, {
    method: 'POST',
    signal: AbortSignal.timeout(10_000),
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json',
      Authorization: `Basic ${Buffer.from(`${encodeURIComponent(s.clientId)}:${encodeURIComponent(s.clientSecret)}`).toString('base64')}`,
    },
    body: new URLSearchParams({ grant_type: 'authorization_code', code: q.code, redirect_uri: redirectUri, code_verifier: p.verifier, client_id: s.clientId }),
  });
  const body = await r.json().catch(() => ({}));
  if (!r.ok || typeof body.id_token !== 'string') throw new Error(`token exchange failed: ${body.error_description ?? body.error ?? r.status}`);
  return { claims: await verifyIdToken(body.id_token, d, s.clientId, p.nonce), linkUserId: p.linkUserId };
}

const list = (v: string) => v.split(',').map((x) => x.trim().toLowerCase()).filter(Boolean);

// the role the provider gives, null when its groups give none
export function roleFromGroups(s: SsoSettings, claims: Record<string, any>): Role | null | undefined {
  if (!s.groupsClaim) return undefined;
  const raw = claims[s.groupsClaim];
  const groups = (Array.isArray(raw) ? raw : typeof raw === 'string' ? raw.split(/[\s,]+/) : []).map((g) => String(g).toLowerCase());
  const has = (g: string) => !!g && groups.includes(g.toLowerCase());
  if (has(s.adminGroup)) return 'admin';
  if (has(s.operatorGroup)) return 'operator';
  if (!s.viewerGroup || has(s.viewerGroup)) return 'viewer';
  return null;
}

/** Map a verified sign-in to a local account: by subject, or link, or create. */
export function resolveUser(s: SsoSettings, claims: Record<string, any>, linkUserId?: number): { id: number; username: string; created: boolean } {
  const sub = `${claims.iss}|${claims.sub}`;
  const email = typeof claims.email === 'string' ? claims.email.toLowerCase() : '';
  const domains = list(s.allowedDomains);
  if (domains.length) {
    if (!email || claims.email_verified === false) throw new Error('your account has no verified email');
    if (!domains.includes(email.split('@')[1] ?? '')) throw new Error(`${email} is not allowed here`);
  }
  const groupRole = roleFromGroups(s, claims);
  if (groupRole === null) throw new Error('your groups give no access to Argos');

  if (linkUserId) {
    const taken = db.prepare('SELECT id FROM users WHERE oidc_sub = ? AND id != ?').get(sub, linkUserId);
    if (taken) throw new Error('that SSO account is already linked to another user');
    db.prepare('UPDATE users SET oidc_sub = ?, email = coalesce(nullif(?, \'\'), email) WHERE id = ?').run(sub, email, linkUserId);
    const u = db.prepare('SELECT username FROM users WHERE id = ?').get(linkUserId) as { username: string };
    return { id: linkUserId, username: u.username, created: false };
  }

  const found = db.prepare('SELECT id, username, role FROM users WHERE oidc_sub = ?').get(sub) as { id: number; username: string; role: Role } | undefined;
  if (found) {
    if (groupRole && groupRole !== found.role) {
      const admins = (db.prepare("SELECT COUNT(*) n FROM users WHERE role = 'admin'").get() as { n: number }).n;
      if (!(found.role === 'admin' && admins <= 1)) db.prepare('UPDATE users SET role = ? WHERE id = ?').run(groupRole, found.id);
    }
    return { id: found.id, username: found.username, created: false };
  }
  if (!s.autoCreate) throw new Error('no Argos account is linked to this SSO account. Ask an admin, or sign in with your password and link it in Settings');

  const base = String(claims.preferred_username || email.split('@')[0] || claims.name || 'user').toLowerCase().replace(/[^\w.-]+/g, '-').replace(/^[-.]+|[-.]+$/g, '').slice(0, 28) || 'user';
  let username = base.length >= 3 ? base : `${base}-sso`;
  for (let i = 2; db.prepare('SELECT 1 FROM users WHERE username = ?').get(username); i++) username = `${base}-${i}`;
  // no usable password: these accounts sign in through the provider
  const r = db.prepare('INSERT INTO users (username, pass_hash, role, created_at, oidc_sub, email) VALUES (?, ?, ?, ?, ?, ?)')
    .run(username, hashPassword(randomBytes(32).toString('hex')), groupRole ?? s.defaultRole, Date.now(), sub, email || null);
  return { id: Number(r.lastInsertRowid), username, created: true };
}
