import './setup.js';
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { finishSignIn, resolveUser, roleFromGroups, startSignIn, SSO_DEFAULTS, type SsoSettings } from '../src/sso.js';
import { db } from '../src/db.js';

// a tiny openid provider: discovery, jwks, and a token endpoint that checks pkce
const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...(publicKey.export({ format: 'jwk' }) as object), kid: 'k1', use: 'sig', alg: 'RS256' };
const codes = new Map<string, { challenge: string; nonce: string; claims: object }>();
let next: object = {};
let tamper = (t: string) => t;

const jwt = (claims: object) => {
  const h = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'k1', typ: 'JWT' })).toString('base64url');
  const p = Buffer.from(JSON.stringify(claims)).toString('base64url');
  return `${h}.${p}.${sign('sha256', Buffer.from(`${h}.${p}`), privateKey).toString('base64url')}`;
};

let ISS = '';
const idp: Server = createServer((req, res) => {
  const url = new URL(req.url!, ISS);
  const json = (o: object, status = 200) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
  if (url.pathname === '/.well-known/openid-configuration')
    return json({ issuer: ISS, authorization_endpoint: `${ISS}/authorize`, token_endpoint: `${ISS}/token`, jwks_uri: `${ISS}/jwks` });
  if (url.pathname === '/jwks') return json({ keys: [jwk] });
  if (url.pathname === '/token') {
    let body = '';
    req.on('data', (d) => (body += d));
    req.on('end', () => {
      const f = new URLSearchParams(body);
      const auth = Buffer.from(String(req.headers.authorization).replace('Basic ', ''), 'base64').toString();
      const c = codes.get(f.get('code') ?? '');
      if (auth !== 'argos:s3cret' || !c) return json({ error: 'invalid_grant' }, 400);
      if (createHash('sha256').update(f.get('code_verifier') ?? '').digest('base64url') !== c.challenge) return json({ error: 'invalid_grant', error_description: 'pkce' }, 400);
      const now = Math.floor(Date.now() / 1000);
      json({ id_token: tamper(jwt({ iss: ISS, aud: 'argos', iat: now, exp: now + 300, nonce: c.nonce, ...c.claims })) });
    });
    return;
  }
  json({ error: 'not found' }, 404);
});
await new Promise<void>((r) => idp.listen(0, '127.0.0.1', () => r()));
ISS = `http://127.0.0.1:${(idp.address() as any).port}`;
after(() => idp.close());

const settings = (over: Partial<SsoSettings> = {}): SsoSettings => ({ ...SSO_DEFAULTS, enabled: true, issuer: ISS, clientId: 'argos', clientSecret: 's3cret', ...over });
const REDIRECT = 'https://argos.example.com/api/auth/sso/callback';

// what the browser does: go to the provider, come back with a code
async function signIn(s: SsoSettings, claims: object, o: { link?: number; cookie?: string } = {}) {
  const { url, state } = await startSignIn(s, REDIRECT, o.link);
  const u = new URL(url);
  assert.equal(u.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(u.searchParams.get('redirect_uri'), REDIRECT);
  const code = randomBytes(8).toString('hex');
  codes.set(code, { challenge: u.searchParams.get('code_challenge')!, nonce: u.searchParams.get('nonce')!, claims });
  return finishSignIn(s, REDIRECT, { code, state }, o.cookie ?? state);
}

test('sso: a new person gets an account only when auto-create is on', async () => {
  const claims = { sub: 'u-1', email: 'Maria@Example.com', email_verified: true, preferred_username: 'maria' };
  const r = await signIn(settings(), claims);
  assert.throws(() => resolveUser(settings(), r.claims), /no Argos account is linked/);
  const r2 = await signIn(settings({ autoCreate: true }), claims);
  const u = resolveUser(settings({ autoCreate: true }), r2.claims);
  assert.equal(u.username, 'maria');
  assert.equal(u.created, true);
  const row = db.prepare('SELECT role, email FROM users WHERE id = ?').get(u.id) as any;
  assert.deepEqual([row.role, row.email], ['viewer', 'maria@example.com']);
  // second time it is the same account
  const again = resolveUser(settings({ autoCreate: true }), (await signIn(settings(), claims)).claims);
  assert.equal(again.id, u.id);
});

test('sso: groups decide the role, domains who may come in', async () => {
  const s = settings({ autoCreate: true, groupsClaim: 'groups', adminGroup: 'argos-admins', operatorGroup: 'soc', viewerGroup: 'staff', allowedDomains: 'example.com' });
  assert.equal(roleFromGroups(s, { groups: ['staff', 'soc'] }), 'operator');
  assert.equal(roleFromGroups(s, { groups: ['ARGOS-ADMINS'] }), 'admin');
  assert.equal(roleFromGroups(s, { groups: ['marketing'] }), null);
  const u = resolveUser(s, (await signIn(s, { sub: 'u-2', email: 'nik@example.com', groups: ['soc'] })).claims);
  assert.equal((db.prepare('SELECT role FROM users WHERE id = ?').get(u.id) as any).role, 'operator');
  await assert.rejects(async () => resolveUser(s, (await signIn(s, { sub: 'u-3', email: 'x@evil.com', groups: ['soc'] })).claims), /not allowed/);
  await assert.rejects(async () => resolveUser(s, (await signIn(s, { sub: 'u-4', email: 'y@example.com', groups: ['marketing'] })).claims), /no access/);
});

test('sso: linking an existing account', async () => {
  const id = Number(db.prepare("INSERT INTO users (username, pass_hash, role, created_at) VALUES ('george', 'x:y', 'admin', 0)").run().lastInsertRowid);
  const r = await signIn(settings(), { sub: 'u-9', email: 'george@example.com' }, { link: id });
  assert.equal(r.linkUserId, id);
  assert.equal(resolveUser(settings(), r.claims, r.linkUserId).id, id);
  assert.equal(resolveUser(settings(), (await signIn(settings(), { sub: 'u-9' })).claims).username, 'george');
});

test('sso: refused when the browser, the token or the provider do not line up', async () => {
  await assert.rejects(signIn(settings(), { sub: 'z' }, { cookie: 'someone-elses-state' }), /not started in this browser/);
  tamper = (t) => t.slice(0, -4) + 'AAAA';
  await assert.rejects(signIn(settings(), { sub: 'z' }), /signature/);
  tamper = (t) => t;
  await assert.rejects(signIn(settings(), { sub: 'z', aud: 'other-app' }), /another client/);
  await assert.rejects(signIn(settings(), { sub: 'z', exp: 1 }), /expired/);
  await assert.rejects(signIn(settings(), { sub: 'z', nonce: 'replayed' }), /nonce/);
  await assert.rejects(signIn(settings({ clientSecret: 'wrong' }), { sub: 'z' }), /token exchange failed/);
  // a state is good once
  const { url, state } = await startSignIn(settings(), REDIRECT);
  const code = 'once';
  codes.set(code, { challenge: new URL(url).searchParams.get('code_challenge')!, nonce: new URL(url).searchParams.get('nonce')!, claims: { sub: 'z' } });
  await finishSignIn(settings(), REDIRECT, { code, state }, state);
  await assert.rejects(finishSignIn(settings(), REDIRECT, { code, state }, state), /took too long|start again/);
});
