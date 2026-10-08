import './setup.js';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { findSuspects } from '../src/falsepos.js';
import type { Alert } from '../src/lapi.js';

let id = 1;
const alert = (ip: string, as: string, scenario: string, reqs: [string, string, string][]): Alert => ({
  id: id++, scenario, message: '', events_count: reqs.length, start_at: '2026-10-08T10:00:00Z', stop_at: '2026-10-08T10:00:00Z',
  source: { scope: 'Ip', value: ip, ip, cn: 'GR', as_name: as },
  events: reqs.map(([host, path, status]) => ({ timestamp: '', meta: [{ key: 'target_fqdn', value: host }, { key: 'http_path', value: path }, { key: 'http_status', value: status }] })),
});

test('scanners on hosting networks are not suspects', () => {
  const r = findSuspects([
    alert('34.1.1.1', 'GOOGLE-CLOUD-PLATFORM', 'crowdsecurity/http-sensitive-files', [['shop.example.com', '/.env', '404'], ['shop.example.com', '/.git/config', '404']]),
    alert('45.1.1.1', 'Bucklog SARL', 'crowdsecurity/http-probing', [['shop.example.com', '/wp-login.php', '404']]),
    alert('5.1.1.1', 'Vodafone Greece', 'crowdsecurity/CVE-2017-9841', [['shop.example.com', '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', '404']]),
  ]);
  assert.equal(r.suspects.length, 0);
});

test('a browser on a next.js app gets flagged with a ready ignore rule', () => {
  const r = findSuspects([alert('2607:fb92::1', 'T-MOBILE-AS21928', 'crowdsecurity/http-probing',
    [['panel.example.com', '/dashboard/events?_rsc=d5vq9', '404'], ['panel.example.com', '/dashboard/rules?_rsc=e3wom', '404']])]);
  const [s] = r.suspects;
  assert.equal(s.ip, '2607:fb92::1');
  assert.ok(s.score >= 5);
  assert.deepEqual(s.rule?.conditions, [{ field: 'host', op: 'equals', value: 'panel.example.com' }, { field: 'path', op: 'contains', value: '_rsc=' }]);
});

test('the same app path tripped by several home users is app noise', () => {
  const users = ['Cosmote', 'Vodafone Greece', 'Wind Hellas', 'Inalan'].map((as, i) =>
    alert(`79.1.1.${i}`, as, 'LePresidente/http-generic-403-bf', [['app.example.com', `/api/orders/${i}`, '403'], ['app.example.com', '/api/me', '403']]));
  const r = findSuspects(users, { unbanned: new Set(['79.1.1.0']), dismissed: new Set(['ip:79.1.1.3']) });
  assert.deepEqual(r.groups.map((g) => [g.host, g.prefix, g.ips]), [['app.example.com', '/api/', 4]]);
  assert.equal(r.suspects.length, 3, 'dismissed one left out');
  assert.equal(r.suspects[0].ip, '79.1.1.0', 'unbanned before ranks first');
  assert.deepEqual(r.suspects[1].rule?.conditions, [{ field: 'host', op: 'equals', value: 'app.example.com' }, { field: 'path', op: 'startsWith', value: '/api/' }]);
});

test('a probe path next to the app path keeps the spot out', () => {
  const r = findSuspects(['Cosmote', 'Vodafone Greece', 'Wind Hellas'].map((as, i) =>
    alert(`79.2.2.${i}`, as, 'crowdsecurity/http-probing', [['app.example.com', '/admin/', '404'], ['app.example.com', `/admin/x${i}`, '404']])));
  assert.equal(r.groups.length, 0);
});
