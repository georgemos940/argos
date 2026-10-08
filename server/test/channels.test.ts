import './setup.js';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { alertMessage, saveChannel, send, publicChannels, type Channel } from '../src/channels.js';
import type { Alert } from '../src/lapi.js';

const alert = (over: Partial<Alert> = {}): Alert => ({
  id: 1, scenario: 'crowdsecurity/http-probing', message: '', events_count: 12, start_at: '2026-10-08T10:00:00Z', stop_at: '2026-10-08T10:00:00Z',
  source: { scope: 'Ip', value: '203.0.113.7', cn: 'DE', as_name: 'Example <GmbH>' },
  decisions: [{ id: 1, type: 'ban', scope: 'Ip', value: '203.0.113.7', duration: '4h0m0s', origin: 'crowdsec' }],
  events: [{ timestamp: '', meta: [{ key: 'target_fqdn', value: 'shop.example.com' }] }], ...over,
});

function capture() {
  const calls: { url: string; init: RequestInit }[] = [];
  const real = globalThis.fetch;
  globalThis.fetch = (async (url: any, init: any) => { calls.push({ url: String(url), init }); return new Response('ok', { status: 200 }); }) as typeof fetch;
  return { calls, restore: () => { globalThis.fetch = real; } };
}

test('alert message reads like a human wrote it', () => {
  const m = alertMessage([alert()]);
  assert.equal(m.title, 'Attack from 203.0.113.7');
  assert.match(m.lines[0], /203\.0\.113\.7 · http-probing · 12 events from Example <GmbH> on shop\.example\.com · banned 4h/);
  assert.equal(m.severity, 'high');
  assert.equal(alertMessage(Array.from({ length: 12 }, (_, i) => alert({ id: i }))).lines.at(-1), '… and 2 more');
});

test('webhook body is signed with the shared secret', async () => {
  const ch: Channel = { id: 'w', type: 'webhook', name: 'w', enabled: true, alerts: true, digest: true, config: { url: 'https://example.com/hook', secret: 's3cret' } };
  const cap = capture();
  try { await send(ch, alertMessage([alert()]), { n: 1 }); } finally { cap.restore(); }
  const { init } = cap.calls[0];
  const sig = (init.headers as Record<string, string>)['X-Argos-Signature'];
  assert.equal(sig, `sha256=${createHmac('sha256', 's3cret').update(String(init.body)).digest('hex')}`);
});

test('telegram text is html-escaped', async () => {
  const ch: Channel = { id: 't', type: 'telegram', name: 't', enabled: true, alerts: true, digest: true, config: { token: '1:x', chatId: '42' } };
  const cap = capture();
  try { await send(ch, alertMessage([alert()]), {}); } finally { cap.restore(); }
  const body = JSON.parse(String(cap.calls[0].init.body));
  assert.equal(body.parse_mode, 'HTML');
  assert.match(body.text, /Example &lt;GmbH&gt;/);
  assert.doesNotMatch(body.text, /<GmbH>/);
});

test('channel secrets never go back to the browser', () => {
  saveChannel({ type: 'slack', name: 'team', config: { url: 'https://hooks.slack.com/services/T0/B0/xyz' } });
  const pub = publicChannels().find((c) => c.name === 'team')!;
  assert.equal(pub.config.url, '••••••');
  assert.throws(() => saveChannel({ type: 'slack', name: 'bad', config: { url: 'https://evil.example/hook' } }), /Slack/);
  assert.throws(() => saveChannel({ type: 'telegram', name: 'bad', config: { token: 'nope', chatId: '1' } }), /Telegram/);
});
