import type { Hono } from 'hono';
import { streamSSE } from 'hono/streaming';
import type { Alert } from './lapi.js';
import { slim, summarize } from './stats.js';
import { findSuspects } from './falsepos.js';
import { DEFAULT_POLICY, cleanPolicy, renderPolicy, renderRules, type IgnoreRule } from './policy.js';

// DEMO=1: the whole ui on generated data, no crowdsec, no docker, read-only

let seed = 7;
const rnd = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
const pick = <T>(a: T[]): T => a[Math.floor(rnd() * a.length)];

const SOURCES = [
  { cn: 'CN', as: 'CHINANET-BACKBONE', asn: '4134', lat: 31.2, lon: 121.5 }, { cn: 'US', as: 'DIGITALOCEAN-ASN', asn: '14061', lat: 40.7, lon: -74.0 },
  { cn: 'RU', as: 'Rostelecom', asn: '12389', lat: 55.7, lon: 37.6 }, { cn: 'NL', as: 'Hetzner Online GmbH', asn: '24940', lat: 52.4, lon: 4.9 },
  { cn: 'DE', as: 'Contabo GmbH', asn: '51167', lat: 48.1, lon: 11.6 }, { cn: 'BR', as: 'Claro NXT', asn: '28573', lat: -23.5, lon: -46.6 },
  { cn: 'IN', as: 'Reliance Jio', asn: '55836', lat: 19.1, lon: 72.9 }, { cn: 'VN', as: 'VNPT Corp', asn: '45899', lat: 21.0, lon: 105.8 },
  { cn: 'SG', as: 'Amazon.com, Inc.', asn: '16509', lat: 1.35, lon: 103.8 }, { cn: 'FR', as: 'OVH SAS', asn: '16276', lat: 50.7, lon: 3.2 },
  { cn: 'KR', as: 'Korea Telecom', asn: '4766', lat: 37.6, lon: 127.0 }, { cn: 'US', as: 'Google LLC', asn: '15169', lat: 37.4, lon: -122.1 },
  { cn: 'RO', as: 'M247 Europe SRL', asn: '9009', lat: 44.4, lon: 26.1 }, { cn: 'ZA', as: 'Afrihost', asn: '37611', lat: -26.2, lon: 28.0 },
];
const SCEN = ['crowdsecurity/http-probing', 'crowdsecurity/http-sensitive-files', 'crowdsecurity/http-wordpress-scan', 'crowdsecurity/ssh-bf',
  'crowdsecurity/http-bad-user-agent', 'crowdsecurity/CVE-2017-9841', 'crowdsecurity/http-path-traversal-probing', 'crowdsecurity/http-admin-interface-probing',
  'crowdsecurity/vpatch-env-access', 'crowdsecurity/vpatch-git-config'];
const SITES = ['shop.example.com', 'api.example.com', 'www.example.com', 'grafana.example.net', 'blog.example.org'];
const PATHS = ['/.env', '/wp-login.php', '/.git/config', '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', '/admin/', '/phpmyadmin/', '/xmlrpc.php',
  '/cgi-bin/luci', '/actuator/env', '/.aws/credentials', '/boaform/admin/formLogin', '/server-status'];
const ip = () => `${pick([45, 61, 79, 89, 103, 118, 141, 167, 185, 193, 196, 212])}.${Math.floor(rnd() * 255)}.${Math.floor(rnd() * 255)}.${1 + Math.floor(rnd() * 253)}`;

let nextId = 90000;
function fakeAlert(at: number): Alert {
  const s = pick(SOURCES);
  const v = ip();
  const iso = new Date(at).toISOString();
  const n = 3 + Math.floor(rnd() * 60);
  const site = pick(SITES);
  return {
    id: nextId++, scenario: pick(SCEN), message: '', events_count: n, start_at: iso, stop_at: iso, created_at: iso,
    source: { scope: 'Ip', value: v, ip: v, cn: s.cn, as_name: s.as, as_number: s.asn, range: v.replace(/\.\d+$/, '.0/24'),
      latitude: s.lat + (rnd() - 0.5) * 4, longitude: s.lon + (rnd() - 0.5) * 4 },
    decisions: rnd() < 0.72 ? [{ id: nextId, type: 'ban', scope: 'Ip', value: v, duration: `${1 + Math.floor(rnd() * 3)}h${Math.floor(rnd() * 59)}m12s`, origin: 'crowdsec' }] : [],
    events: Array.from({ length: Math.min(n, 6) }, () => ({ timestamp: iso, meta: [{ key: 'target_fqdn', value: site }, { key: 'http_path', value: pick(PATHS) },
      { key: 'http_status', value: pick(['404', '403', '200']) }, { key: 'http_user_agent', value: pick(['curl/8.4.0', 'Mozilla/5.0 zgrab/0.x', 'python-requests/2.31']) }, { key: 'http_verb', value: 'GET' }] })),
  };
}

const now = () => Date.now();
const alerts: Alert[] = Array.from({ length: 260 }, () => fakeAlert(now() - Math.pow(rnd(), 1.4) * 24 * 3600_000))
  .sort((a, b) => b.start_at.localeCompare(a.start_at));
const live: ((a: ReturnType<typeof slim>) => void)[] = [];
setInterval(() => {
  const a = fakeAlert(now());
  alerts.unshift(a);
  if (alerts.length > 400) alerts.pop();
  for (const l of live) l(slim(a));
}, 7000).unref();

const zones = ['example.com', 'example.net', 'example.org'];
const series = (base: number, amp: number) => Array.from({ length: 120 }, (_, i) => [Math.floor((now() - (120 - i) * 30_000) / 1000),
  Math.max(0, base + Math.sin(i / 9) * amp + (rnd() - 0.5) * amp + (i > 95 && i < 104 ? amp * 6 : 0))]);
const hubItem = (name: string, description: string) => ({ name, description, status: 'enabled', local_version: (rnd() * 2 + 0.1).toFixed(1) });
const embed = { username: 'Argos', avatarUrl: '', title: '{flag} {ip} · {scenario}', description: '**{events}** events from {network}\n{decision}',
  colorBan: '#ef4444', colorAlert: '#f59e0b', fields: ['country', 'site'], footer: 'Argos', linkBase: '', timestamp: true };

const demoPolicy = { ...DEFAULT_POLICY, escalate: true, captcha: true };
const demoRules: IgnoreRule[] = [
  { id: 'health', name: 'Uptime checks', enabled: true, conditions: [{ field: 'path', op: 'equals', value: '/healthz' }] },
  { id: 'next', name: 'App assets', enabled: true, conditions: [{ field: 'host', op: 'equals', value: 'shop.example.com' }, { field: 'path', op: 'startsWith', value: '/_next/' }] },
  { id: 'bots', name: 'Search engine crawlers on 404s', enabled: false, conditions: [{ field: 'user_agent', op: 'regex', value: '(?i)(googlebot|bingbot)' }, { field: 'status', op: 'equals', value: '404' }] },
];

// a few real visitors among the scanners, for the false positives page
const visitor = (ip: string, cn: string, as: string, scenario: string, reqs: [string, string, string][], hoursAgo: number): Alert => {
  const iso = new Date(now() - hoursAgo * 3600_000).toISOString();
  return { id: nextId++, scenario, message: '', events_count: reqs.length * 3, start_at: iso, stop_at: iso, created_at: iso,
    source: { scope: 'Ip', value: ip, ip, cn, as_name: as },
    decisions: [{ id: nextId, type: 'ban', scope: 'Ip', value: ip, duration: '3h12m4s', origin: 'crowdsec' }],
    events: reqs.map(([host, path, status]) => ({ timestamp: iso, meta: [{ key: 'target_fqdn', value: host }, { key: 'http_path', value: path }, { key: 'http_status', value: status }] })) };
};
const visitors = [
  visitor('2a02:587:4c1e::17', 'GR', 'Cosmote', 'crowdsecurity/http-probing', [['app.example.com', '/dashboard/orders?_rsc=1x9fk', '404'], ['app.example.com', '/dashboard/billing?_rsc=1x9fk', '404'], ['app.example.com', '/dashboard/team?_rsc=8ka2c', '404']], 2),
  visitor('94.66.21.140', 'GR', 'Vodafone-panafon Hellenic Telecommunications', 'LePresidente/http-generic-403-bf', [['shop.example.com', '/api/cart/items', '403'], ['shop.example.com', '/api/session', '403'], ['shop.example.com', '/api/cart', '200']], 5),
  visitor('85.74.112.9', 'GR', 'Wind Hellas Telecommunications', 'LePresidente/http-generic-403-bf', [['shop.example.com', '/api/cart', '403'], ['shop.example.com', '/api/wishlist', '403']], 9),
  visitor('62.38.201.77', 'GR', 'Hellas Online', 'crowdsecurity/http-probing', [['shop.example.com', '/api/products/9921', '404'], ['shop.example.com', '/api/products/9922', '404']], 20),
];

const routes: Record<string, (c: any) => unknown> = {
  '/api/auth/me': (c) => {
    const id = c.req.header('x-argos-instance') === 'edge-2' ? 'edge-2' : 'main';
    return { setup: false, user: { username: 'demo', role: 'admin', totp: true }, needsTotp: false, passkeys: true, home: [8.68, 50.11], demo: true,
      instance: id === 'main' ? 'demo' : 'edge-fra-2', instanceId: id, instances: [{ id: 'main', name: 'demo' }, { id: 'edge-2', name: 'edge-fra-2' }] };
  },
  '/api/instances': () => [
    { id: 'main', name: 'demo', lapiUrl: 'http://crowdsec:8080', lapiUser: 'argos', lapiPassword: '••••••', dockerProxyUrl: 'http://argos-docker-proxy:2375', dockerProxyToken: '••••••',
      container: 'crowdsec', promUrl: 'http://prometheus:9090', main: true, cscli: true, status: { lapi: 'ok', docker: 'ok' } },
    { id: 'edge-2', name: 'edge-fra-2', lapiUrl: 'http://100.64.0.12:8080', lapiUser: 'argos', lapiPassword: '••••••', dockerProxyUrl: 'http://100.64.0.12:2375', dockerProxyToken: '••••••',
      container: 'crowdsec', promUrl: '', main: false, cscli: true, status: { lapi: 'ok', docker: 'ok' } }],
  '/api/nav': () => ({ alerts: 12, bans: 3, lapiUp: true }),
  '/api/overview': (c) => {
    const window = (c.req.query('window') ?? '24h') as '24h' | '7d' | '30d';
    return { ...summarize(alerts, window), active: { crowdsec: 187, cscli: 4, CAPI: 21385, lists: 6345 }, lapiUp: true, latest: alerts.slice(0, 30).map(slim) };
  },
  '/api/alerts': () => alerts.map(slim),
  '/api/decisions': () => alerts.filter((a) => a.decisions?.length).slice(0, 40).map((a, i) => ({
    id: a.decisions![0].id, type: 'ban', scope: 'Ip', value: a.source.value, duration: a.decisions![0].duration, origin: i % 9 === 4 ? 'cscli' : 'crowdsec',
    reason: i % 9 === 4 ? 'manual ban from demo' : a.scenario, alertId: a.id, cn: a.source.cn, as_name: a.source.as_name, events: a.events_count, at: a.start_at })),
  '/api/blocklists': () => [
    { id: 'spamhaus-drop', name: 'Spamhaus DROP', url: 'https://www.spamhaus.org/drop/drop.txt', description: 'Netblocks run entirely by spammers and cyber-criminals. Very low risk of false positives.', enabled: true, refreshHours: 12, type: 'ban', lastRun: now() - 3 * 3600_000, lastCount: 1670, lastSkipped: 0, lastError: null },
    { id: 'firehol-level1', name: 'FireHOL level 1', url: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', description: 'Combined list of the worst attackers (Spamhaus, DShield, Feodo, abuse.ch). Safe for most sites.', enabled: true, refreshHours: 6, type: 'ban', lastRun: now() - 40 * 60_000, lastCount: 4599, lastSkipped: 10, lastError: null },
    { id: 'tor-exits', name: 'Tor exit nodes', url: 'https://check.torproject.org/torbulkexitlist', description: 'Every Tor exit node. Blocks anonymous traffic, including some legitimate privacy-minded users.', enabled: false, refreshHours: 3, type: 'captcha', lastRun: null, lastCount: null, lastSkipped: null, lastError: null },
    { id: 'abuseipdb', name: 'AbuseIPDB top offenders', url: 'abuseipdb', description: 'IPs with an abuse confidence of 100%. Uses the AbuseIPDB key from Settings (free tier: 5 downloads a day).', enabled: true, refreshHours: 12, type: 'ban', lastRun: now() - 5 * 3600_000, lastCount: 9871, lastSkipped: 2, lastError: null },
  ],
  '/api/waf': () => ({ metrics: { 'appsec-engine': { appsec: { processed: 81493, blocked: 37 } }, 'appsec-rule': { appsec: {
    'crowdsecurity/vpatch-env-access': { triggered: 19 }, 'crowdsecurity/vpatch-git-config': { triggered: 9 }, 'crowdsecurity/vpatch-CVE-2017-9841': { triggered: 5 },
    'crowdsecurity/vpatch-CVE-2023-22515': { triggered: 3 } } } }, alerts: alerts.filter((a) => a.scenario.includes('vpatch')).map(slim) }),
  '/api/simulation': () => ({ global: false, scenarios: ['crowdsecurity/http-bad-user-agent'] }),
  '/api/cloudflare': () => ({ configured: true, zones: zones.map((z, i) => ({ id: `z${i}`, name: z, level: i === 1 ? 'under_attack' : 'medium', rps: [4, 212, 1][i], guardHolds: false })) }),
  '/api/traffic': () => ({ perZone: zones.map((z, i) => ({ metric: { zone: z }, values: series([6, 14, 2][i], [3, 9, 1][i]) })), codes: [], cpu: 18 }),
  '/api/infra': () => ({
    bouncers: [{ name: 'firewall-bouncer', type: 'crowdsec-firewall-bouncer', ip_address: '127.0.0.1', last_pull: new Date(now() - 8000).toISOString() },
      { name: 'traefik-plugin', type: 'Crowdsec-Bouncer-Traefik-Plugin', ip_address: '172.19.0.3', last_pull: new Date(now() - 41000).toISOString() }],
    machines: [{ machineId: 'localhost', version: 'v1.7.7', ipAddress: '127.0.0.1', last_heartbeat: new Date(now() - 12000).toISOString() },
      { machineId: 'argos', version: 'v1.7.7', ipAddress: '172.21.0.9', last_heartbeat: new Date(now() - 20000).toISOString() }],
    metrics: { acquisition: { 'file:/var/log/traefik/access.log': { reads: 1849213, parsed: 1846021, unparsed: 3192, pour: 52310 }, 'appsec:appsec': { reads: 81493, parsed: 81493, unparsed: 0, pour: 37 } } },
  }),
  '/api/hub': () => ({
    collections: ['crowdsecurity/traefik', 'crowdsecurity/base-http-scenarios', 'crowdsecurity/http-cve', 'crowdsecurity/linux', 'crowdsecurity/sshd', 'crowdsecurity/appsec-virtual-patching']
      .map((n) => hubItem(n, 'Bundles the parsers and scenarios for ' + n.split('/')[1].replace(/-/g, ' '))),
    scenarios: SCEN.filter((s) => !s.includes('vpatch')).map((n) => hubItem(n, 'Detects ' + n.split('/')[1].replace(/-/g, ' '))),
    parsers: ['crowdsecurity/traefik-logs', 'crowdsecurity/sshd-logs', 'crowdsecurity/geoip-enrich', 'crowdsecurity/whitelists'].map((n) => hubItem(n, 'Parser ' + n.split('/')[1])),
  }),
  '/api/hub/store': () => ({
    collections: [['crowdsecurity/appsec-generic-rules', 'Generic AppSec rules: SQLi, XSS, RCE patterns'], ['crowdsecurity/nextcloud', 'Nextcloud brute force and enumeration'],
      ['crowdsecurity/wordpress', 'WordPress scanners, xmlrpc and login brute force'], ['crowdsecurity/http-dos', 'Layer 7 DoS detection for HTTP services'],
      ['crowdsecurity/grafana', 'Grafana login brute force'], ['crowdsecurity/mysql', 'MySQL authentication brute force'], ['crowdsecurity/vaultwarden', 'Vaultwarden login brute force']]
      .map(([name, description]) => ({ name, description, installed: false, status: 'disabled' })),
    scenarios: [], parsers: [], 'appsec-rules': [], 'appsec-configs': [], postoverflows: [],
  }),
  '/api/notifications': () => ({ enabled: true, webhook: 'https://discord.com/api/webhooks/0000/demo…', hasWebhook: true, minEvents: 3, scenarioInclude: '',
    scenarioExclude: 'http-probing', cooldownMinutes: 60, maxPerHour: 20, mention: '', embed, embedDefaults: embed }),
  '/api/notifications/sample': () => ({ vars: { ip: '185.220.101.47', flag: '🇩🇪', country: 'Germany', cc: 'DE', scenario: 'http-sensitive-files',
    scenario_full: 'crowdsecurity/http-sensitive-files', events: '42', network: 'Contabo GmbH', asn: 'AS51167', range: '185.220.101.0/24',
    site: 'shop.example.com', duration: '4h', decision: 'Banned for **4h**' }, banned: true, at: new Date(now() - 120000).toISOString() }),
  '/api/grafana-relay': () => ({ webhookSet: true, lastAt: now() - 3600_000, lastStatus: 'resolved', sent: 27, token: 'demo-token', port: 3000 }),
  '/api/channels': () => [
    { id: 't1', type: 'telegram', name: 'Ops Telegram', enabled: true, alerts: true, digest: true, config: { token: '••••••', chatId: '-1001234567890' } },
    { id: 'n1', type: 'ntfy', name: 'Phone (ntfy)', enabled: true, alerts: true, digest: false, config: { topic: 'argos-alerts', server: 'https://ntfy.sh', token: '' } },
    { id: 'e1', type: 'email', name: 'Weekly email', enabled: true, alerts: false, digest: true,
      config: { host: 'smtp.example.com', port: '587', user: 'argos', pass: '••••••', from: 'argos@example.com', to: 'team@example.com' } },
  ],
  '/api/digest': () => {
    const s = summarize(alerts, '7d');
    return { settings: { daily: false, weekly: true, hour: 9, weekday: 1, discord: true }, preview: { title: 'Argos weekly summary', severity: 'default', lines: [
      `${s.totals.alerts} attacks from ${s.totals.uniqueIps} IPs, ${alerts.filter((a) => a.decisions?.length).length} led to a ban`,
      `Top attacks: ${s.scenarios.slice(0, 3).map((x) => `${x.key.replace(/^crowdsecurity\//, '')} (${x.count})`).join(', ')}`,
      `Sites hit most: ${s.sites.slice(0, 3).map((x) => `${x.key} (${x.count})`).join(', ')}`,
    ] } };
  },
  '/api/console': () => ({ console_management: false, context: true, custom: true, manual: true, tainted: true }),
  '/api/settings': () => ({ ctiKeySet: true, abuseKeySet: true, repMode: 'auto', require2fa: true }),
  '/api/users': () => [{ id: 1, username: 'demo', role: 'admin', totp: 1, created_at: now() - 30 * 86400_000 },
    { id: 2, username: 'oncall', role: 'operator', totp: 1, created_at: now() - 9 * 86400_000 }, { id: 3, username: 'intern', role: 'viewer', totp: 0, created_at: now() - 2 * 86400_000 }],
  '/api/audit': () => [['demo', 'decision.add', 'Ip:203.0.113.77'], ['oncall', 'cloudflare.level', 'example.net'], ['demo', 'blocklist.update', 'firehol-level1'],
    ['demo', 'hub.upgrade', '4 items'], ['oncall', 'login', '198.51.100.12'], ['intern', 'login.failed', '198.51.100.40']]
    .map(([u, a, t], i) => ({ id: 100 - i, ts: now() - i * 2400_000, username: u, action: a, target: t, detail: null })),
  '/api/policy': () => ({ live: renderPolicy(demoPolicy), managed: true, policy: demoPolicy, generated: renderPolicy(demoPolicy), backup: { at: now() - 6 * 86400_000 } }),
  '/api/ignore-rules': () => ({ rules: demoRules, live: renderRules(demoRules), inSync: true, backup: null }),
  '/api/bouncer-metrics': () => ({ bouncers: [{ name: 'firewall-bouncer', processed: { bytes: 4662246370189, packets: 1483259338 }, dropped: 9172, origins: [
    { origin: 'crowdsec', label: 'CrowdSec detections', bytes: 229808, packets: 4048, active: 187 },
    { origin: 'lists:firehol_greensnow', label: 'firehol_greensnow', bytes: 108212, packets: 2311, active: 3982 },
    { origin: 'CAPI', label: 'Community blocklist', bytes: 91790, packets: 1930, active: 22719 },
    { origin: 'cscli', label: 'Manual and Argos', bytes: 40120, packets: 883, active: 6349 },
  ] }] }),
  '/api/false-positives': () => findSuspects([...visitors, ...alerts], { active: new Map(visitors.map((v) => [v.source.value, { id: v.decisions![0].id, type: 'ban', duration: '3h12m4s' }])) }),
  '/api/auth/passkeys': () => [{ id: 'demo', name: 'Mac · Safari', created_at: now() - 12 * 86400_000, last_used_at: now() - 3600_000 }],
  '/api/sso': () => ({ enabled: true, issuer: 'https://auth.example.com/application/o/argos/', clientId: 'argos', clientSecret: '••••••', label: 'Authentik',
    allowedDomains: 'example.com', autoCreate: true, defaultRole: 'viewer', groupsClaim: 'groups', adminGroup: 'argos-admins', operatorGroup: 'soc', viewerGroup: '',
    redirectUri: 'https://argos.example.com/api/auth/sso/callback' }),
  '/api/tokens': () => [
    { id: 2, name: 'home-assistant', prefix: 'argos_Qm3xT', role: 'viewer', created_by: 'demo', created_at: now() - 20 * 86400_000, expires_at: now() + 70 * 86400_000, last_used_at: now() - 90_000, last_ip: '192.168.1.20' },
    { id: 1, name: 'fail2ban-bridge', prefix: 'argos_9Kd2w', role: 'operator', created_by: 'demo', created_at: now() - 60 * 86400_000, expires_at: null, last_used_at: now() - 3 * 3600_000, last_ip: '10.0.0.4' }],
  '/api/allowlists': () => [
    { name: 'trusted', description: 'Office and monitoring', created_at: '', updated_at: '', items: [{ value: '198.51.100.10', comment: 'office' }, { value: '203.0.113.0/28', comment: 'uptime monitor' }] },
    { name: 'partners', description: 'Payment and API partners', created_at: '', updated_at: '', items: [{ value: '192.0.2.44', comment: 'payment gateway webhooks' }] }],
};

function ipProfile(c: any) {
  const ipAddr = decodeURIComponent(c.req.param('ip'));
  const found = alerts.filter((a) => a.source.value === ipAddr);
  const list = found.length ? found : alerts.filter((a) => a.source.cn === 'DE').slice(0, 6);
  return { ip: ipAddr, alerts: list, reputation: { source: 'abuseipdb', score: 100, verdict: 'malicious', tags: ['Data Center/Web Hosting/Transit'], quotaLeft: 974,
    details: { Reports: 1614, 'Distinct reporters': 312, 'Last reported': new Date().toISOString().slice(0, 10), ISP: list[0]?.source.as_name ?? '', Usage: 'Data Center/Web Hosting/Transit', Tor: false } },
    reputationError: null };
}

export function mountDemo(app: Hono<any>): void {
  console.log('[demo] DEMO=1: generated data, read-only, no crowdsec needed');
  app.get('/api/stream', (c) => streamSSE(c, async (stream) => {
    const send = (a: unknown) => { stream.writeSSE({ event: 'alert', data: JSON.stringify(a) }); };
    live.push(send);
    stream.onAbort(() => { live.splice(live.indexOf(send), 1); });
    while (!stream.aborted) { await stream.writeSSE({ event: 'ping', data: String(Date.now()) }); await stream.sleep(25_000); }
  }));
  app.get('/api/ip/:ip', (c) => c.json(ipProfile(c)));
  app.get('/api/alerts/:id', (c) => c.json(alerts.find((a) => a.id === Number(c.req.param('id'))) ?? alerts[0]));
  for (const [path, fn] of Object.entries(routes)) app.get(path, (c) => c.json(fn(c) as any));
  app.post('/api/policy/preview', async (c) => c.json({ generated: renderPolicy(cleanPolicy(await c.req.json())) }));
  app.all('/api/*', (c) => (c.req.method === 'GET'
    ? c.json({ error: 'not available in the demo' }, 404)
    : c.json({ error: 'This is a read-only demo. Run Argos with your own CrowdSec to change things.' }, 403)));
}
