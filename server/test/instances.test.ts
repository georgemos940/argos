import './setup.js';
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { Hono } from 'hono';
import { MAIN, current, inInstance, instanceById, pickInstance, saveInstance, scoped, type Instance } from '../src/instances.js';
import { getAlerts } from '../src/lapi.js';
import { recentAlerts } from '../src/stats.js';
import { audit, db } from '../src/db.js';

// two fake local apis, each with its own machine and its own alerts
function fakeLapi(name: string, user: string): { server: Server; url: () => string; logins: number } {
  const state = { logins: 0 };
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (d) => (body += d));
    req.on('end', () => {
      if (req.url === '/v1/watchers/login') {
        const { machine_id, password } = JSON.parse(body);
        if (machine_id !== user || password !== `${user}-pw`) { res.writeHead(401); return res.end('{}'); }
        state.logins++;
        res.writeHead(200);
        return res.end(JSON.stringify({ token: `tok-${name}`, expire: new Date(Date.now() + 3600_000).toISOString() }));
      }
      if (req.headers.authorization !== `Bearer tok-${name}`) { res.writeHead(401); return res.end('{}'); }
      res.writeHead(200);
      res.end(JSON.stringify([{ id: 1, scenario: `${name}/scenario`, message: '', events_count: 1, start_at: '', stop_at: '', source: { scope: 'Ip', value: '192.0.2.1' } }]));
    });
  }).listen(0, '127.0.0.1');
  return { server, url: () => `http://127.0.0.1:${(server.address() as any).port}`, get logins() { return state.logins; } };
}

const a = fakeLapi('alpha', 'argos-a');
const b = fakeLapi('beta', 'argos-b');
await new Promise((r) => setTimeout(r, 50));
after(() => { a.server.close(); b.server.close(); });

const inst = (id: string, lapi: ReturnType<typeof fakeLapi>, user: string): Instance =>
  ({ id, name: id.toUpperCase(), lapiUrl: lapi.url(), lapiUser: user, lapiPassword: `${user}-pw`, dockerProxyUrl: '', dockerProxyToken: '', container: 'crowdsec', promUrl: '' });

test('each instance talks to its own lapi with its own login', async () => {
  saveInstance(inst('alpha', a, 'argos-a'));
  saveInstance(inst('beta', b, 'argos-b'));
  const [ra, rb] = await Promise.all([
    inInstance(instanceById('alpha')!, () => getAlerts()),
    inInstance(instanceById('beta')!, () => getAlerts()),
  ]);
  assert.equal(ra[0].scenario, 'alpha/scenario');
  assert.equal(rb[0].scenario, 'beta/scenario');
  // tokens are cached per instance, not shared
  await inInstance(instanceById('alpha')!, () => getAlerts());
  assert.equal(a.logins, 1);
  assert.equal(b.logins, 1);
  // and so is the alert cache
  const [ca, cb] = await Promise.all([inInstance(instanceById('alpha')!, () => recentAlerts('24h')), inInstance(instanceById('beta')!, () => recentAlerts('24h'))]);
  assert.notEqual(ca[0].scenario, cb[0].scenario);
});

test('the request header picks the instance, unknown ones fall back to main', async () => {
  const app = new Hono();
  app.use('*', pickInstance);
  app.get('/which', (c) => c.json({ id: current().id, key: scoped('policy') }));
  const which = async (h?: string) => (await app.request('/which', { headers: h ? { 'X-Argos-Instance': h } : {} })).json();
  assert.deepEqual(await which(), { id: MAIN, key: 'policy' });
  assert.deepEqual(await which('beta'), { id: 'beta', key: 'policy@beta' });
  assert.deepEqual(await which('deleted-one'), { id: MAIN, key: 'policy' });
});

test('the audit log says which instance a change was made on', () => {
  inInstance(instanceById('beta')!, () => audit('george', 'decision.add', 'Ip:203.0.113.9'));
  audit('george', 'decision.add', 'Ip:203.0.113.10');
  const rows = db.prepare("SELECT target, instance FROM audit WHERE action = 'decision.add' ORDER BY id").all() as any[];
  assert.deepEqual(rows.map((r) => [r.target, r.instance]), [['Ip:203.0.113.9', 'BETA'], ['Ip:203.0.113.10', null]]);
});
