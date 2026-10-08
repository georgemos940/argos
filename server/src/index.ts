import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { serveStatic } from '@hono/node-server/serve-static';
import { streamSSE } from 'hono/streaming';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { bodyLimit } from 'hono/body-limit';
import { readFileSync } from 'node:fs';
import { config } from './config.js';
import { db, audit, getSetting, setSetting } from './db.js';
import {
  burnPasswordCheck, checkPassword, checkTotp, clearFailures, clientIp, createSession, destroySession, endOtherSessions,
  hashPassword, markTotpOk, newTotpSecret, recordFailure, require2faForAll, requireRole, sessionFor, tooManyFailures,
  userCount, type User,
} from './auth.js';
import { addDecision, deleteDecision, deleteDecisionsFor, getAlert, getAlerts, lapiHealth } from './lapi.js';
import { recentAlerts, slim, summarize } from './stats.js';
import { SAMPLE as GRAFANA_SAMPLE, checkToken, relay, relayState, setRelayWebhook } from './grafana-relay.js';
import { cscli, explain, parsePlan, readCrowdsecFile, simulationStatus } from './cscli.js';
import {
  DEFAULT_POLICY, EMPTY_RULES, POLICY_MARK, applyFile, backupOf, cleanPolicy, cleanRules, guessPolicy, renderPolicy, renderRules, restartAndWait,
  type IgnoreRule, type Policy,
} from './policy.js';
import { checkContent } from './docker.js';
import {
  PRESETS as BLOCKLIST_PRESETS, disable as disableBlocklist, listAll as listBlocklists, refresh as refreshBlocklist,
  remove as removeBlocklist, startBlocklists, upsert as upsertBlocklist,
} from './blocklists.js';
import { query, range, scalar } from './prom.js';
import { cloudflareConfigured, setLevel, zones } from './cloudflare.js';
import {
  EMBED_FIELDS, defaultEmbed, notifySettings, onAlert, sendDiscord, sendDiscordDigest, startNotifier, vars, type EmbedStyle, type NotifySettings,
} from './notifier.js';
import { reputation, type RepMode } from './reputation.js';
import { mountDemo } from './demo.js';
import {
  digestMessage, digestSettings, publicChannels, removeChannel, saveChannel, send as sendToChannel, sendDigest, startDigest,
  listChannels, type DigestSettings,
} from './channels.js';

type Env = { Variables: { user: User } };
const app = new Hono<Env>();
const viewer = requireRole('viewer');
const operator = requireRole('operator');
const admin = requireRole('admin');
const who = (c: any) => (c.get('user') as User).username;
const ip = (c: any) => clientIp(c);
const enrolling = requireRole('viewer', { enrolling: true });

// details only for signed-in users, a stranger gets nothing about the internals
app.onError((err, c) => {
  console.error('[api]', c.req.method, c.req.path, err.message);
  return c.json({ error: sessionFor(c) ? err.message : 'internal error' }, 500);
});

const CSP = [
  "default-src 'self'", "script-src 'self'", "style-src 'self' 'unsafe-inline'", "img-src 'self' data: https:",
  "font-src 'self' data:", "connect-src 'self'", "worker-src 'self'", "manifest-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'", "object-src 'none'",
].join('; ');

app.use('*', async (c, next) => {
  await next();
  c.header('X-Frame-Options', 'DENY');
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('Referrer-Policy', 'no-referrer');
  c.header('Content-Security-Policy', CSP);
  c.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  c.header('Cross-Origin-Opener-Policy', 'same-origin');
  c.header('Cross-Origin-Resource-Policy', 'same-origin');
  if (config.cookieSecure) c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  if (c.req.path.startsWith('/api/')) c.header('Cache-Control', 'no-store');
});

app.use('/api/*', bodyLimit({ maxSize: 1024 * 1024, onError: (c) => c.json({ error: 'request too large' }, 413) }));
app.use('/hooks/*', bodyLimit({ maxSize: 1024 * 1024, onError: (c) => c.json({ error: 'request too large' }, 413) }));

// csrf: a write must come from our own page. browsers will not send this header cross-site
// without a cors preflight, and we answer none
app.use('/api/*', async (c, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(c.req.method)) return next();
  if (c.req.header('x-argos') !== '1') return c.json({ error: 'missing request header' }, 403);
  const origin = c.req.header('origin');
  if (origin) {
    let host = '';
    try { host = new URL(origin).host; } catch { /* bad origin */ }
    const self = c.req.header('x-forwarded-host') && config.trustProxy ? c.req.header('x-forwarded-host') : c.req.header('host');
    if (host !== self) return c.json({ error: 'cross-site request refused' }, 403);
  }
  return next();
});

if (config.demo) mountDemo(app);

// ---------------------------------------------------------------- auth
const setupToken = randomBytes(12).toString('hex');
if (userCount() === 0 && !config.demo) console.log(`[setup] no users yet. Setup token: ${setupToken}`);

app.get('/api/auth/me', (c) => {
  const s = sessionFor(c);
  return c.json({
    setup: userCount() === 0,
    user: s ? { username: s.user.username, role: s.user.role, totp: !!s.user.totp_secret } : null,
    needsTotp: !!s && !!s.user.totp_secret && !s.totpOk,
    mustEnroll: !!s && !s.user.totp_secret && require2faForAll(),
    instance: config.instanceName,
    home: [config.homeLon, config.homeLat],
  });
});

app.post('/api/auth/setup', async (c) => {
  if (userCount() > 0) return c.json({ error: 'already set up' }, 400);
  if (tooManyFailures(ip(c))) return c.json({ error: 'too many attempts, try again in 15 minutes' }, 429);
  const { token, username, password } = await c.req.json();
  const a = Buffer.from(String(token ?? '')); const b = Buffer.from(setupToken);
  if (a.length !== b.length || !timingSafeEqual(a, b)) { recordFailure(ip(c)); return c.json({ error: 'wrong setup token' }, 403); }
  if (!/^[\w.-]{3,32}$/.test(username) || String(password).length < 10)
    return c.json({ error: 'username 3-32 chars, password 10+ chars' }, 400);
  const r = db.prepare('INSERT INTO users (username, pass_hash, role, created_at) VALUES (?, ?, ?, ?)')
    .run(username, hashPassword(password), 'admin', Date.now());
  createSession(c, Number(r.lastInsertRowid), true);
  audit(username, 'setup', username);
  return c.json({ ok: true });
});

app.post('/api/auth/login', async (c) => {
  const { username, password } = await c.req.json();
  const name = String(username ?? '').slice(0, 64);
  if (tooManyFailures(ip(c), name)) return c.json({ error: 'too many attempts, try again in 15 minutes' }, 429);
  const u = db.prepare('SELECT * FROM users WHERE username = ?').get(name) as any;
  const ok = u ? checkPassword(String(password ?? ''), u.pass_hash) : (burnPasswordCheck(String(password ?? '')), false);
  if (!ok) {
    recordFailure(ip(c), name);
    audit(name, 'login.failed', ip(c));
    return c.json({ error: 'wrong username or password' }, 401);
  }
  clearFailures(ip(c), name);
  createSession(c, u.id, !u.totp_secret);
  audit(u.username, 'login', ip(c));
  return c.json({ totp: !!u.totp_secret });
});

app.post('/api/auth/totp', async (c) => {
  const s = sessionFor(c);
  if (!s || !s.user.totp_secret) return c.json({ error: 'not signed in' }, 401);
  if (tooManyFailures(ip(c))) return c.json({ error: 'too many attempts' }, 429);
  const { code } = await c.req.json();
  if (!checkTotp(s.user.totp_secret, String(code))) {
    recordFailure(ip(c), s.user.username);
    audit(s.user.username, '2fa.failed', ip(c));
    return c.json({ error: 'wrong code' }, 401);
  }
  markTotpOk(s.sid);
  return c.json({ ok: true });
});

app.post('/api/auth/logout', (c) => { destroySession(c); return c.json({ ok: true }); });

app.post('/api/auth/totp/enroll', enrolling, (c) => {
  const secret = newTotpSecret();
  const u = c.get('user');
  return c.json({ secret, uri: `otpauth://totp/Argos:${encodeURIComponent(u.username)}?secret=${secret}&issuer=Argos` });
});

app.post('/api/auth/totp/confirm', enrolling, async (c) => {
  const { secret, code } = await c.req.json();
  if (!/^[A-Z2-7]{16,64}$/.test(String(secret)) || !checkTotp(String(secret), String(code))) return c.json({ error: 'wrong code' }, 400);
  db.prepare('UPDATE users SET totp_secret = ? WHERE id = ?').run(secret, c.get('user').id);
  const s = sessionFor(c)!;
  markTotpOk(s.sid);
  endOtherSessions(s.user.id, s.sid);
  audit(who(c), '2fa.enabled');
  return c.json({ ok: true });
});

app.post('/api/auth/totp/disable', viewer, async (c) => {
  const u = c.get('user');
  const { code } = await c.req.json();
  if (!u.totp_secret || !checkTotp(u.totp_secret, String(code))) return c.json({ error: 'wrong code' }, 400);
  db.prepare('UPDATE users SET totp_secret = NULL WHERE id = ?').run(u.id);
  endOtherSessions(u.id, sessionFor(c)?.sid);
  audit(who(c), '2fa.disabled');
  return c.json({ ok: true });
});

app.post('/api/auth/password', enrolling, async (c) => {
  const { current, next } = await c.req.json();
  const row = db.prepare('SELECT pass_hash FROM users WHERE id = ?').get(c.get('user').id) as any;
  if (!checkPassword(String(current), row.pass_hash)) return c.json({ error: 'current password is wrong' }, 400);
  if (String(next).length < 10) return c.json({ error: 'password must be 10+ chars' }, 400);
  db.prepare('UPDATE users SET pass_hash = ? WHERE id = ?').run(hashPassword(next), c.get('user').id);
  endOtherSessions(c.get('user').id, sessionFor(c)?.sid);
  audit(who(c), 'password.changed');
  return c.json({ ok: true });
});

// ---------------------------------------------------------------- overview
app.get('/api/overview', viewer, async (c) => {
  const window = (c.req.query('window') ?? '24h') as '24h' | '7d' | '30d';
  const [alerts, byOrigin, lapiUp] = await Promise.all([
    recentAlerts(window),
    query('sum by (origin) (cs_active_decisions)').catch(() => []),
    lapiHealth(),
  ]);
  const active = Object.fromEntries(byOrigin.map((s) => [s.metric.origin ?? 'unknown', s.value]));
  return c.json({
    ...summarize(alerts, window),
    active,
    lapiUp,
    latest: alerts.slice(0, 30).map(slim),
  });
});

// sidebar badges, new since last seen
app.get('/api/nav', viewer, async (c) => {
  const since = (k: string) => Math.max(Number(c.req.query(k)) || 0, Date.now() - 86400_000);
  const [alerts, lapiUp] = await Promise.all([recentAlerts('24h'), lapiHealth()]);
  const at = (a: { created_at?: string; start_at: string }) => new Date(a.created_at ?? a.start_at).getTime();
  const a0 = since('alertsSeen');
  const b0 = since('bansSeen');
  return c.json({
    alerts: alerts.filter((a) => at(a) > a0).length,
    bans: alerts.filter((a) => a.decisions?.length && at(a) > b0).length,
    lapiUp,
  });
});

app.get('/api/stream', viewer, (c) =>
  streamSSE(c, async (stream) => {
    const off = onAlert((a) => { stream.writeSSE({ event: 'alert', data: JSON.stringify(a) }); });
    stream.onAbort(() => { off(); });
    while (!stream.aborted) {
      await stream.writeSSE({ event: 'ping', data: String(Date.now()) });
      await stream.sleep(25_000);
    }
  }),
);

// ---------------------------------------------------------------- alerts
app.get('/api/alerts', viewer, async (c) => {
  const q = c.req.query();
  const alerts = await getAlerts({
    since: q.since || '24h', ip: q.ip, scenario: q.scenario, limit: Math.min(Number(q.limit ?? 500), 2000),
  });
  const text = (q.q ?? '').toLowerCase();
  const filtered = text
    ? alerts.filter((a) => `${a.scenario} ${a.source.value} ${a.source.cn} ${a.source.as_name}`.toLowerCase().includes(text))
    : alerts;
  return c.json(filtered.map(slim));
});

app.get('/api/alerts/:id', viewer, async (c) => c.json(await getAlert(Number(c.req.param('id')))));

// ---------------------------------------------------------------- decisions
app.get('/api/decisions', viewer, async (c) => {
  const alerts = await getAlerts({ has_active_decision: true, limit: 3000 });
  const rows = alerts.flatMap((a) => (a.decisions ?? []).map((d) => ({
    id: d.id, type: d.type, scope: d.scope, value: d.value, duration: d.duration, origin: d.origin,
    reason: d.scenario ?? a.scenario, alertId: a.id, cn: a.source.cn, as_name: a.source.as_name,
    events: a.events_count, at: a.start_at,
  })));
  return c.json(rows);
});

const DUR = /^\d{1,4}(s|m|h)$/;
app.post('/api/decisions', operator, async (c) => {
  const { scope, value, duration, reason, type } = await c.req.json();
  if (!['Ip', 'Range', 'Country', 'As'].includes(scope)) return c.json({ error: 'bad scope' }, 400);
  if (!DUR.test(String(duration))) return c.json({ error: 'duration like 4h, 30m, 720h' }, 400);
  if (!String(value).trim()) return c.json({ error: 'value required' }, 400);
  await addDecision({ scope, value: String(value).trim(), duration, reason: String(reason || 'manual'), type: type === 'captcha' ? 'captcha' : 'ban', by: who(c) });
  audit(who(c), 'decision.add', `${scope}:${value}`, { duration, reason, type });
  return c.json({ ok: true });
});

app.delete('/api/decisions/:id', operator, async (c) => {
  const r = await deleteDecision(Number(c.req.param('id')));
  audit(who(c), 'decision.delete', c.req.param('id'));
  return c.json(r);
});

app.post('/api/decisions/unban', operator, async (c) => {
  const { values } = (await c.req.json()) as { values: string[] };
  let n = 0;
  for (const v of values.slice(0, 500)) {
    const r = await deleteDecisionsFor(v.includes('/') ? 'range' : 'ip', v);
    n += Number(r?.nbDeleted ?? 0);
  }
  audit(who(c), 'decision.unban', values.slice(0, 20).join(','), { count: values.length, deleted: n });
  return c.json({ deleted: n });
});

// ---------------------------------------------------------------- ip profile
app.get('/api/ip/:ip', viewer, async (c) => {
  const value = c.req.param('ip');
  const [alerts, rep] = await Promise.all([getAlerts({ ip: value, since: '2160h', limit: 500 }), reputation(value)]);
  return c.json({ ip: value, alerts, reputation: rep.rep, reputationError: rep.error ?? null });
});

// ---------------------------------------------------------------- allowlists
app.get('/api/allowlists', viewer, async (c) => {
  const lists = ((await cscli(['allowlists', 'list'])) ?? []) as any[];
  const detailed = await Promise.all(lists.map(async (l) => {
    const d = await cscli(['allowlists', 'inspect', l.name]).catch(() => null);
    return { ...l, items: d?.items ?? [] };
  }));
  return c.json(detailed);
});

const NAME = /^[\w.-]{1,40}$/;
const ENTRY = /^[0-9a-fA-F:.]+(\/\d{1,3})?$/;
app.post('/api/allowlists', admin, async (c) => {
  const { name, description } = await c.req.json();
  if (!NAME.test(name)) return c.json({ error: 'bad name' }, 400);
  await cscli(['allowlists', 'create', name, '--description', String(description || name)], false);
  audit(who(c), 'allowlist.create', name);
  return c.json({ ok: true });
});
app.delete('/api/allowlists/:name', admin, async (c) => {
  const name = c.req.param('name');
  if (!NAME.test(name)) return c.json({ error: 'bad name' }, 400);
  await cscli(['allowlists', 'delete', name], false);
  audit(who(c), 'allowlist.delete', name);
  return c.json({ ok: true });
});
app.post('/api/allowlists/:name/:op', operator, async (c) => {
  const { name, op } = c.req.param();
  const { values, comment } = (await c.req.json()) as { values: string[]; comment?: string };
  if (!NAME.test(name) || !['add', 'remove'].includes(op)) return c.json({ error: 'bad request' }, 400);
  const clean = values.map((v) => v.trim()).filter((v) => ENTRY.test(v));
  if (!clean.length) return c.json({ error: 'no valid IPs/ranges' }, 400);
  const args = ['allowlists', op, name, ...clean];
  if (op === 'add' && comment) args.push('--comment', String(comment).slice(0, 100));
  await cscli(args, false);
  audit(who(c), `allowlist.${op}`, name, { values: clean, comment });
  return c.json({ ok: true, count: clean.length });
});

// ---------------------------------------------------------------- infrastructure
app.get('/api/infra', viewer, async (c) => {
  const [bouncers, machines, metrics] = await Promise.all([
    cscli(['bouncers', 'list']).catch(() => []),
    cscli(['machines', 'list']).catch(() => []),
    cscli(['metrics']).catch(() => null),
  ]);
  return c.json({ bouncers, machines, metrics });
});

app.get('/api/hub', viewer, async (c) => c.json(await cscli(['hub', 'list'])));

const HUB_TYPES = ['scenarios', 'collections', 'parsers', 'postoverflows', 'contexts', 'appsec-rules', 'appsec-configs'];
app.post('/api/hub/:type/:op', admin, async (c) => {
  const { type, op } = c.req.param();
  const { name } = await c.req.json();
  if (!HUB_TYPES.includes(type) || !['install', 'remove'].includes(op) || !/^[A-Za-z0-9][\w.-]*\/[A-Za-z0-9][\w-]*(?:\.[\w-]+)*$/.test(name))
    return c.json({ error: 'bad request' }, 400);
  await cscli([type, op, name], false);
  audit(who(c), `hub.${op}`, `${type}/${name}`);
  return c.json({ ok: true, note: 'restart crowdsec to apply' });
});
// dry run
app.get('/api/hub/plan', admin, async (c) => {
  await cscli(['hub', 'update'], false);
  const out = String(await cscli(['hub', 'upgrade', '--dry-run'], false));
  return c.json(parsePlan(out));
});

app.post('/api/hub/update', admin, async (c) => {
  await cscli(['hub', 'update'], false);
  audit(who(c), 'hub.update');
  return c.json({ ok: true });
});

app.post('/api/hub/upgrade', admin, async (c) => {
  const out = String(await cscli(['hub', 'upgrade'], false));
  const plan = parsePlan(out);
  const count = plan.steps.reduce((n, s) => n + s.items.length, 0);
  const restart = await restartAndWait();
  audit(who(c), 'hub.upgrade', `${count} items`, { restart });
  return c.json({ ok: true, count, ...restart });
});

app.get('/api/hub/store', viewer, async (c) => {
  const all = (await cscli(['hub', 'list', '-a'])) as Record<string, any[]>;
  const out: Record<string, { name: string; description: string; installed: boolean; status: string; version?: string }[]> = {};
  for (const t of ['collections', 'scenarios', 'parsers', 'postoverflows', 'appsec-rules', 'appsec-configs']) {
    out[t] = (all[t] ?? []).map((i) => ({
      name: i.name, description: i.description ?? '', status: i.status ?? '',
      installed: /enabled/.test(i.status ?? '') && !/disabled/.test(i.status ?? ''), version: i.local_version || undefined,
    }));
  }
  return c.json(out);
});

app.get('/api/simulation', viewer, async (c) => c.json(await simulationStatus()));
app.post('/api/simulation', admin, async (c) => {
  const { scenario, enabled } = await c.req.json();
  await cscli(['simulation', enabled ? 'enable' : 'disable', scenario ? String(scenario) : '--global'], false);
  audit(who(c), `simulation.${enabled ? 'enable' : 'disable'}`, scenario ?? 'global');
  return c.json({ ...(await restartAndWait()), status: await simulationStatus() });
});

app.post('/api/explain', operator, async (c) => {
  const { log, type } = await c.req.json();
  return c.json({ output: await explain(String(log ?? ''), String(type || 'traefik')) });
});

app.get('/api/console', admin, async (c) => c.json(await cscli(['console', 'status']).catch((e) => ({ error: e.message }))));
app.post('/api/console/enroll', admin, async (c) => {
  const { key, name } = await c.req.json();
  await cscli(['console', 'enroll', String(key).trim(), '--name', String(name || config.instanceName)], false);
  audit(who(c), 'console.enroll', String(name || config.instanceName));
  return c.json(await restartAndWait());
});
app.post('/api/console/option', admin, async (c) => {
  const { name, enabled } = await c.req.json();
  if (!['custom', 'manual', 'tainted', 'context', 'console_management'].includes(name)) return c.json({ error: 'unknown option' }, 400);
  await cscli(['console', enabled ? 'enable' : 'disable', name], false);
  audit(who(c), `console.${enabled ? 'enable' : 'disable'}`, name);
  return c.json(await restartAndWait());
});

// ---------------------------------------------------------------- blocklists
app.get('/api/blocklists', viewer, (c) => c.json(listBlocklists()));
app.put('/api/blocklists/:id', admin, async (c) => {
  const id = c.req.param('id');
  if (!/^[a-z0-9-]{2,40}$/.test(id)) return c.json({ error: 'id: 2-40 lowercase letters, digits, dashes' }, 400);
  const body = await c.req.json();
  const preset = BLOCKLIST_PRESETS.some((p) => p.id === id);
  // presets keep url and name
  const b = upsertBlocklist({
    id, enabled: !!body.enabled, refreshHours: body.refreshHours, type: body.type,
    ...(preset ? {} : { name: String(body.name || id).slice(0, 60), url: String(body.url ?? ''), description: String(body.description ?? '').slice(0, 300) }),
  });
  audit(who(c), 'blocklist.update', id, { enabled: b.enabled, refreshHours: b.refreshHours, type: b.type });
  if (!b.enabled) { await disableBlocklist(id); return c.json(listBlocklists()); }
  await refreshBlocklist(id, who(c));
  return c.json(listBlocklists());
});
app.post('/api/blocklists/:id/refresh', admin, async (c) => {
  await refreshBlocklist(c.req.param('id'), who(c));
  return c.json(listBlocklists());
});
app.delete('/api/blocklists/:id', admin, async (c) => {
  const id = c.req.param('id');
  if (BLOCKLIST_PRESETS.some((p) => p.id === id)) return c.json({ error: 'built-in lists can only be turned off' }, 400);
  await disableBlocklist(id);
  removeBlocklist(id);
  audit(who(c), 'blocklist.delete', id);
  return c.json(listBlocklists());
});

// ---------------------------------------------------------------- waf (appsec)
app.get('/api/waf', viewer, async (c) => {
  const [metrics, alerts] = await Promise.all([
    cscli(['metrics', 'show', 'appsec']).catch(() => null),
    getAlerts({ since: '168h', limit: 3000 }),
  ]);
  const engines = metrics?.appsec ?? metrics?.['appsec-engine'] ?? metrics ?? {};
  const waf = alerts.filter((a) => /appsec|vpatch|crs/i.test(a.scenario));
  return c.json({ metrics: metrics ?? {}, engines, alerts: waf.map(slim) });
});

// ---------------------------------------------------------------- ban policy, ignore rules, bouncer usage
const backupInfo = (kind: 'profiles' | 'whitelists') => { const b = backupOf(kind); return b ? { at: b.at } : null; };

app.get('/api/policy', viewer, async (c) => {
  const live = await readCrowdsecFile('profiles');
  const managed = !!live?.startsWith(POLICY_MARK);
  const policy = managed ? cleanPolicy(getSetting<Policy>('policy', DEFAULT_POLICY)) : guessPolicy(live);
  return c.json({ live, managed, policy, generated: renderPolicy(policy), backup: backupInfo('profiles') });
});
app.post('/api/policy/preview', viewer, async (c) => c.json({ generated: renderPolicy(cleanPolicy(await c.req.json())) }));
app.put('/api/policy', admin, async (c) => {
  const body = await c.req.json();
  const raw = typeof body.raw === 'string';
  const policy = raw ? null : cleanPolicy(body.policy);
  const content = raw ? checkContent(body.raw) : renderPolicy(policy!);
  if (raw && !content.trim()) return c.json({ error: 'profiles.yaml cannot be empty' }, 400);
  const r = await applyFile('profiles', content, renderPolicy(DEFAULT_POLICY));
  if (policy) setSetting('policy', policy);
  audit(who(c), 'policy.apply', raw ? 'raw' : 'form', policy ?? undefined);
  return c.json(r);
});
app.post('/api/policy/restore', admin, async (c) => {
  const b = backupOf('profiles');
  if (!b) return c.json({ error: 'no previous profiles.yaml kept' }, 404);
  const r = await applyFile('profiles', b.content, renderPolicy(DEFAULT_POLICY));
  audit(who(c), 'policy.restore', new Date(b.at).toISOString());
  return c.json(r);
});

app.get('/api/ignore-rules', viewer, async (c) => {
  const rules = getSetting<IgnoreRule[]>('ignoreRules', []);
  const live = await readCrowdsecFile('whitelists');
  return c.json({ rules, live, inSync: live === renderRules(rules), backup: backupInfo('whitelists') });
});
app.put('/api/ignore-rules', admin, async (c) => {
  const rules = cleanRules((await c.req.json()).rules);
  const r = await applyFile('whitelists', renderRules(rules), EMPTY_RULES);
  setSetting('ignoreRules', rules);
  audit(who(c), 'ignore-rules.apply', `${rules.filter((x) => x.enabled).length} rules`);
  return c.json({ ...r, rules });
});

const ORIGINS: Record<string, string> = { CAPI: 'Community blocklist', crowdsec: 'CrowdSec detections', cscli: 'Manual and Argos', 'cscli-import': 'Imported', console: 'CrowdSec Console' };
app.get('/api/bouncer-metrics', viewer, async (c) => {
  const raw = await cscli(['metrics', 'show', 'bouncers']).catch((e) => ({ error: e.message }));
  if (raw?.error) return c.json({ error: raw.error, bouncers: [] });
  const sum = (o: any) => Object.values(o ?? {}).reduce((n: number, v) => n + (Number(v) || 0), 0);
  const bouncers = Object.entries((raw?.bouncers ?? {}) as Record<string, Record<string, any>>).map(([name, origins]) => {
    const processed = { bytes: 0, packets: 0 };
    const rows = [];
    for (const [origin, m] of Object.entries(origins)) {
      if (m.processed) { processed.bytes += Number(m.processed.byte) || 0; processed.packets += Number(m.processed.packet) || 0; }
      if (!m.dropped && !m.active_decisions) continue;
      rows.push({
        origin: origin || 'unknown',
        label: ORIGINS[origin] ?? (origin.startsWith('lists:') ? origin.slice(6) : origin || 'unknown'),
        bytes: Number(m.dropped?.byte) || 0, packets: Number(m.dropped?.packet) || 0, active: sum(m.active_decisions),
      });
    }
    rows.sort((a, b) => b.packets - a.packets || b.active - a.active);
    return { name, processed, origins: rows, dropped: rows.reduce((n, r) => n + r.packets, 0) };
  });
  return c.json({ bouncers });
});

app.post('/api/crowdsec/restart', admin, async (c) => {
  const r = await restartAndWait();
  audit(who(c), 'crowdsec.restart', undefined, r);
  return c.json(r);
});

// ---------------------------------------------------------------- cloudflare / traffic
app.get('/api/cloudflare', viewer, async (c) => {
  if (!cloudflareConfigured()) return c.json({ configured: false, zones: [] });
  const [zs, rps] = await Promise.all([zones(), config.zoneRpsQuery ? query(config.zoneRpsQuery).catch(() => []) : []]);
  const rpsBy = Object.fromEntries(rps.map((s) => [s.metric.zone, s.value]));
  return c.json({ configured: true, zones: zs.map((z) => ({ ...z, rps: rpsBy[z.name] ?? null })) });
});

app.post('/api/cloudflare/:id', operator, async (c) => {
  const { level } = await c.req.json();
  if (!['under_attack', 'medium', 'high'].includes(level)) return c.json({ error: 'bad level' }, 400);
  await setLevel(c.req.param('id'), level);
  audit(who(c), 'cloudflare.level', c.req.param('id'), { level });
  return c.json({ ok: true });
});

app.get('/api/traffic', viewer, async (c) => {
  const [perZone, codes, headroomNow] = await Promise.all([
    config.zoneRpsQuery ? range(config.zoneRpsQuery, 3600, 30).catch(() => []) : [],
    range('sum by (code) (rate(traefik_entrypoint_requests_total{entrypoint="websecure",code=~"403|429|5.."}[2m]))', 3600, 60).catch(() => []),
    scalar('100 - avg(rate(node_cpu_seconds_total{mode="idle"}[1m])) * 100'),
  ]);
  return c.json({ perZone, codes, cpu: headroomNow });
});

// ---------------------------------------------------------------- notifications
app.get('/api/notifications', admin, (c) => {
  const s = notifySettings();
  return c.json({ ...s, webhook: s.webhook ? `${s.webhook.slice(0, 45)}…` : '', hasWebhook: !!s.webhook, embedDefaults: defaultEmbed });
});

function cleanEmbed(e: Partial<EmbedStyle> | undefined, cur: EmbedStyle): EmbedStyle {
  const n = { ...cur, ...(e ?? {}) };
  for (const u of [n.avatarUrl, n.linkBase]) if (u && !/^https?:\/\/[^\s]+$/.test(u)) throw new Error(`not a URL: ${u}`);
  return {
    username: String(n.username).slice(0, 80), avatarUrl: String(n.avatarUrl), title: String(n.title).slice(0, 256),
    description: String(n.description).slice(0, 2000), colorBan: String(n.colorBan), colorAlert: String(n.colorAlert),
    fields: (n.fields ?? []).filter((f) => (EMBED_FIELDS as readonly string[]).includes(f)), footer: String(n.footer).slice(0, 200),
    linkBase: String(n.linkBase), timestamp: !!n.timestamp,
  };
}

app.put('/api/notifications', admin, async (c) => {
  const body = (await c.req.json()) as Partial<NotifySettings> & { webhook?: string };
  const cur = notifySettings();
  for (const re of [body.scenarioInclude, body.scenarioExclude]) if (re) new RegExp(re);
  const next: NotifySettings = {
    ...cur, ...body,
    webhook: body.webhook && !body.webhook.endsWith('…') ? body.webhook : cur.webhook,
    minEvents: Math.max(1, Number(body.minEvents ?? cur.minEvents)),
    cooldownMinutes: Math.max(1, Number(body.cooldownMinutes ?? cur.cooldownMinutes)),
    maxPerHour: Math.min(120, Math.max(1, Number(body.maxPerHour ?? cur.maxPerHour))),
    embed: cleanEmbed(body.embed, cur.embed),
  };
  delete (next as any).hasWebhook;
  delete (next as any).embedDefaults;
  if (next.webhook && !/^https:\/\/(discord|discordapp)\.com\/api\/webhooks\//.test(next.webhook))
    return c.json({ error: 'not a Discord webhook URL' }, 400);
  setSetting('notify', next);
  audit(who(c), 'notifications.update', undefined, { ...next, webhook: next.webhook ? 'set' : '' });
  return c.json({ ok: true });
});

async function sampleAlert() {
  const recent = await getAlerts({ since: '168h', limit: 30 });
  return recent.find((a) => a.decisions?.length && !a.scenario.startsWith('manual ')) ?? recent[0];
}

app.get('/api/notifications/sample', admin, async (c) => {
  const a = await sampleAlert();
  if (!a) return c.json({ vars: null });
  return c.json({ vars: vars(a), banned: !!a.decisions?.length, at: a.stop_at });
});

// uses the unsaved embed from the editor
app.post('/api/notifications/test', admin, async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const s = notifySettings();
  if (!s.webhook) return c.json({ error: 'no webhook saved yet' }, 400);
  const sample = await sampleAlert();
  if (!sample) return c.json({ error: 'no alert to use as a sample' }, 400);
  await sendDiscord({ ...s, mention: body.mention ?? s.mention, embed: cleanEmbed(body.embed, s.embed) }, [sample]);
  return c.json({ ok: true });
});

// ---------------------------------------------------------------- channels and digest
app.get('/api/channels', admin, (c) => c.json(publicChannels()));
app.put('/api/channels', admin, async (c) => {
  const ch = saveChannel(await c.req.json());
  audit(who(c), 'channel.save', `${ch.type}:${ch.name}`);
  return c.json(publicChannels());
});
app.delete('/api/channels/:id', admin, (c) => {
  removeChannel(c.req.param('id'));
  audit(who(c), 'channel.delete', c.req.param('id'));
  return c.json(publicChannels());
});
app.post('/api/channels/:id/test', admin, async (c) => {
  const ch = listChannels().find((x) => x.id === c.req.param('id'));
  if (!ch) return c.json({ error: 'no such channel' }, 404);
  await sendToChannel(ch, { title: 'Argos test', lines: ['If you can read this, the channel works.'], severity: 'default' }, { test: true });
  return c.json({ ok: true });
});

app.get('/api/digest', admin, async (c) => {
  const window = c.req.query('window') === '24h' ? '24h' : '7d';
  return c.json({ settings: digestSettings(), preview: (await digestMessage(window)).msg });
});
app.put('/api/digest', admin, async (c) => {
  const b = (await c.req.json()) as Partial<DigestSettings>;
  const cur = digestSettings();
  const next: DigestSettings = {
    daily: b.daily ?? cur.daily, weekly: b.weekly ?? cur.weekly, discord: b.discord ?? cur.discord,
    hour: Math.min(23, Math.max(0, Math.round(Number(b.hour ?? cur.hour)))),
    weekday: Math.min(6, Math.max(0, Math.round(Number(b.weekday ?? cur.weekday)))),
  };
  setSetting('digest', next);
  audit(who(c), 'digest.update', undefined, next);
  return c.json({ settings: next });
});
app.post('/api/digest/send', admin, async (c) => {
  const window = (await c.req.json().catch(() => ({}))).window === '24h' ? '24h' : '7d';
  const errors = await sendDigest(window, sendDiscordDigest);
  return c.json({ ok: !errors.length, errors });
});

// ---------------------------------------------------------------- grafana alert relay
app.post('/hooks/grafana', async (c) => {
  if (!checkToken(c.req.header('authorization'))) return c.json({ error: 'unauthorized' }, 401);
  const n = await relay(await c.req.json());
  return c.json({ ok: true, sent: n });
});
app.get('/api/grafana-relay', admin, (c) => {
  const s = relayState();
  return c.json({ webhookSet: !!s.webhook, lastAt: s.lastAt, lastStatus: s.lastStatus, sent: s.sent, token: s.token, port: config.port });
});
app.put('/api/grafana-relay', admin, async (c) => {
  const { webhook } = await c.req.json();
  setRelayWebhook(String(webhook ?? '').trim());
  audit(who(c), 'grafana-relay.update');
  return c.json({ ok: true });
});
app.post('/api/grafana-relay/test', admin, async (c) => {
  const resolved = (await c.req.json().catch(() => ({}))).resolved;
  const a = GRAFANA_SAMPLE.alerts[0];
  await relay({ status: resolved ? 'resolved' : 'firing', alerts: [{ ...a, status: resolved ? 'resolved' : 'firing', endsAt: resolved ? new Date().toISOString() : a.endsAt,
    labels: { ...a.labels, alertname: `TEST · ${a.labels.alertname}` } }] });
  return c.json({ ok: true });
});

// ---------------------------------------------------------------- settings, users, audit
app.get('/api/settings', admin, (c) => c.json({
  ctiKeySet: !!getSetting('cti.key', ''),
  abuseKeySet: !!getSetting('abuse.key', ''),
  repMode: getSetting<RepMode>('rep.mode', 'auto'),
  require2fa: require2faForAll(),
}));
app.put('/api/settings', admin, async (c) => {
  const { ctiKey, abuseKey, repMode, require2fa } = await c.req.json();
  const changed: string[] = [];
  if (typeof require2fa === 'boolean') {
    if (require2fa && !c.get('user').totp_secret) return c.json({ error: 'turn on 2FA for your own account first' }, 400);
    setSetting('auth.require2fa', require2fa); changed.push(`require2fa=${require2fa}`);
  }
  if (typeof ctiKey === 'string' && ctiKey.trim()) { setSetting('cti.key', ctiKey.trim()); changed.push('cti.key'); }
  if (typeof abuseKey === 'string' && abuseKey.trim()) { setSetting('abuse.key', abuseKey.trim()); changed.push('abuse.key'); }
  if (['auto', 'cti', 'abuseipdb'].includes(repMode)) { setSetting('rep.mode', repMode); changed.push(`rep.mode=${repMode}`); }
  audit(who(c), 'settings.update', changed.join(','));
  return c.json({ ok: true });
});

app.get('/api/users', admin, (c) =>
  c.json(db.prepare('SELECT id, username, role, totp_secret IS NOT NULL AS totp, created_at FROM users ORDER BY id').all()));
app.post('/api/users', admin, async (c) => {
  const { username, password, role } = await c.req.json();
  if (!/^[\w.-]{3,32}$/.test(username) || String(password).length < 10 || !['admin', 'operator', 'viewer'].includes(role))
    return c.json({ error: 'username 3-32 chars, password 10+, role admin/operator/viewer' }, 400);
  db.prepare('INSERT INTO users (username, pass_hash, role, created_at) VALUES (?, ?, ?, ?)')
    .run(username, hashPassword(password), role, Date.now());
  audit(who(c), 'user.create', username, { role });
  return c.json({ ok: true });
});
app.patch('/api/users/:id', admin, async (c) => {
  const { role, resetTotp } = await c.req.json();
  const id = Number(c.req.param('id'));
  const admins = (db.prepare("SELECT COUNT(*) n FROM users WHERE role = 'admin'").get() as { n: number }).n;
  const target = db.prepare('SELECT role FROM users WHERE id = ?').get(id) as { role: string } | undefined;
  if (!target) return c.json({ error: 'no such user' }, 404);
  if (role && role !== 'admin' && target.role === 'admin' && admins <= 1) return c.json({ error: 'cannot demote the last admin' }, 400);
  if (role && ['admin', 'operator', 'viewer'].includes(role)) db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, id);
  if (resetTotp) { db.prepare('UPDATE users SET totp_secret = NULL WHERE id = ?').run(id); endOtherSessions(id); }
  audit(who(c), 'user.update', String(id), { role, resetTotp });
  return c.json({ ok: true });
});
app.delete('/api/users/:id', admin, (c) => {
  const id = Number(c.req.param('id'));
  if (id === c.get('user').id) return c.json({ error: 'cannot delete yourself' }, 400);
  endOtherSessions(id);
  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  audit(who(c), 'user.delete', String(id));
  return c.json({ ok: true });
});

app.get('/api/audit', admin, (c) =>
  c.json(db.prepare('SELECT * FROM audit ORDER BY id DESC LIMIT ?').all(Math.min(Number(c.req.query('limit') ?? 300), 2000))));

// ---------------------------------------------------------------- web app
app.use('/assets/*', serveStatic({ root: './dist/web' }));
app.use('/logo.png', serveStatic({ path: './dist/web/logo.png' }));
app.use('/icons/*', serveStatic({ root: './dist/web' }));
app.use('/manifest.webmanifest', serveStatic({ path: './dist/web/manifest.webmanifest' }));
// the worker must always be fresh or an old one keeps serving an old app
app.use('/sw.js', serveStatic({ path: './dist/web/sw.js', onFound: (_p, c) => { c.header('Cache-Control', 'no-cache'); } }));
let indexHtml = '';
try { indexHtml = readFileSync('./dist/web/index.html', 'utf8'); } catch { indexHtml = '<p>web app not built</p>'; }
app.get('*', (c) => (c.req.path.startsWith('/api/') ? c.json({ error: 'not found' }, 404) : c.html(indexHtml)));

if (!config.demo) {
  startNotifier();
  startBlocklists();
  startDigest(sendDiscordDigest);
}
serve({ fetch: app.fetch, port: config.port, hostname: '0.0.0.0' }, (i) => console.log(`Argos on :${i.port}`));
