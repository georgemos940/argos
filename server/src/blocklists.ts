import { getSetting, setSetting, audit } from './db.js';
import { deleteDecisionsByScenario, pushListDecisions } from './lapi.js';
import { config } from './config.js';

export interface Blocklist {
  id: string;
  name: string;
  url: string;                 // or "abuseipdb"
  description: string;
  enabled: boolean;
  refreshHours: number;
  type: 'ban' | 'captcha';
  lastRun: number | null;
  lastCount: number | null;
  lastSkipped: number | null;
  lastError: string | null;
}

export const PRESETS: Omit<Blocklist, 'enabled' | 'lastRun' | 'lastCount' | 'lastSkipped' | 'lastError'>[] = [
  { id: 'spamhaus-drop', name: 'Spamhaus DROP', url: 'https://www.spamhaus.org/drop/drop.txt', refreshHours: 12, type: 'ban',
    description: 'Netblocks run entirely by spammers and cyber-criminals. Very low risk of false positives.' },
  { id: 'firehol-level1', name: 'FireHOL level 1', url: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', refreshHours: 6, type: 'ban',
    description: 'Combined list of the worst attackers (Spamhaus, DShield, Feodo, abuse.ch). Safe for most sites.' },
  { id: 'tor-exits', name: 'Tor exit nodes', url: 'https://check.torproject.org/torbulkexitlist', refreshHours: 3, type: 'ban',
    description: 'Every Tor exit node. Blocks anonymous traffic, including some legitimate privacy-minded users.' },
  { id: 'abuseipdb', name: 'AbuseIPDB top offenders', url: 'abuseipdb', refreshHours: 12, type: 'ban',
    description: 'IPs with an abuse confidence of 100%. Uses the AbuseIPDB key from Settings (free tier: 5 downloads a day).' },
];

export const PREFIX = 'argos-list/';

export function listAll(): Blocklist[] {
  const saved = getSetting<Blocklist[]>('blocklists', []);
  const byId = new Map(saved.map((b) => [b.id, b]));
  const presets = PRESETS.map((p) => ({ enabled: false, lastRun: null, lastCount: null, lastSkipped: null, lastError: null, ...p, ...byId.get(p.id) }));
  return [...presets, ...saved.filter((b) => !PRESETS.some((p) => p.id === b.id))];
}

const save = (all: Blocklist[]) => setSetting('blocklists', all);

export function upsert(b: Partial<Blocklist> & { id: string }): Blocklist {
  const all = listAll();
  const i = all.findIndex((x) => x.id === b.id);
  const cur = i >= 0 ? all[i] : { enabled: false, lastRun: null, lastCount: null, lastSkipped: null, lastError: null, description: '', name: b.id, url: '', refreshHours: 12, type: 'ban' as const, id: b.id };
  const next: Blocklist = {
    ...cur,
    ...b,
    refreshHours: Math.min(168, Math.max(1, Number(b.refreshHours ?? cur.refreshHours))),
    type: b.type === 'captcha' ? 'captcha' : (b.type ?? cur.type),
  };
  if (next.url !== 'abuseipdb' && !/^https?:\/\/\S+$/.test(next.url)) throw new Error('URL must start with http:// or https://');
  if (i >= 0) all[i] = next; else all.push(next);
  save(all);
  return next;
}

export function remove(id: string): void {
  save(listAll().filter((b) => b.id !== id));
}

// ---------------------------------------------------------------- parsing

const v4 = (s: string) => {
  const p = s.split('.').map(Number);
  return p.length === 4 && p.every((n) => Number.isInteger(n) && n >= 0 && n <= 255) ? ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3] : null;
};

function v4Range(entry: string, minBits = 8): [number, number] | null {
  const [ip, bits = '32'] = entry.split('/');
  const n = v4(ip);
  const b = Number(bits);
  if (n === null || !Number.isInteger(b) || b < minBits || b > 32) return null;
  const size = 2 ** (32 - b);
  const start = n - (n % size);
  return [start, start + size - 1];
}

// never ban private/reserved space or our own ips
const RESERVED_V4 = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
  '192.0.0.0/24', '192.168.0.0/16', '198.18.0.0/15', '224.0.0.0/3', ...config.selfIps.filter((ip) => !ip.includes(':'))]
  .map((r) => v4Range(r, 0)).filter(Boolean) as [number, number][];

let cfRanges: { at: number; v4: [number, number][]; v6: string[] } | null = null;

// banning a cloudflare range takes every proxied site down
async function cloudflare(): Promise<{ v4: [number, number][]; v6: string[] }> {
  if (cfRanges && Date.now() - cfRanges.at < 24 * 3600_000) return cfRanges;
  const [a, b] = await Promise.all(['ips-v4', 'ips-v6'].map((f) => fetch(`https://www.cloudflare.com/${f}`).then((r) => r.text())));
  const list4 = a.split(/\s+/).filter(Boolean).map(v4Range).filter(Boolean) as [number, number][];
  if (list4.length < 5) throw new Error('could not load the Cloudflare ranges');
  cfRanges = { at: Date.now(), v4: list4, v6: b.split(/\s+/).filter(Boolean) };
  return cfRanges;
}

const overlaps = (r: [number, number], list: [number, number][]) => list.some(([s, e]) => r[0] <= e && s <= r[1]);
const V6 = /^[0-9a-f:]+(\/\d{1,3})?$/i;

export function parse(text: string, cf: { v4: [number, number][]; v6: string[] }): { values: string[]; skipped: number } {
  const out = new Set<string>();
  let skipped = 0;
  for (const raw of text.split('\n')) {
    const entry = raw.replace(/[#;].*$/, '').trim().split(/\s+/)[0];
    if (!entry) continue;
    if (entry.includes(':')) {
      const low = entry.toLowerCase();
      // skip link-local, ula, loopback and cloudflare
      if (!V6.test(entry) || /^(fe8|fe9|fea|feb|fc|fd|::1$|::\/|::$)/.test(low) || cf.v6.some((p) => low.startsWith(p.split('::')[0].toLowerCase()))) { skipped++; continue; }
      out.add(entry);
      continue;
    }
    const r = v4Range(entry);
    if (!r || overlaps(r, RESERVED_V4) || overlaps(r, cf.v4)) { skipped++; continue; }
    out.add(entry.endsWith('/32') ? entry.slice(0, -3) : entry);
  }
  return { values: [...out], skipped };
}

async function download(b: Blocklist): Promise<string> {
  if (b.url === 'abuseipdb') {
    const key = getSetting<string>('abuse.key', '');
    if (!key) throw new Error('no AbuseIPDB key in Settings');
    const res = await fetch('https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=100&limit=10000', { headers: { Key: key, Accept: 'text/plain' } });
    if (!res.ok) throw new Error(`AbuseIPDB ${res.status}${res.status === 429 ? ' (daily download limit)' : ''}`);
    return res.text();
  }
  const res = await fetch(b.url, { headers: { 'User-Agent': 'argos/1.0' }, signal: AbortSignal.timeout(60_000) });
  if (!res.ok) throw new Error(`download ${res.status}`);
  const text = await res.text();
  if (text.length > 20_000_000) throw new Error('list is larger than 20 MB');
  return text;
}

// ---------------------------------------------------------------- refresh

const running = new Set<string>();

export async function refresh(id: string, by = 'scheduler'): Promise<Blocklist> {
  const b = listAll().find((x) => x.id === id);
  if (!b) throw new Error('unknown list');
  if (running.has(id)) throw new Error('already refreshing');
  running.add(id);
  try {
    const { values, skipped } = parse(await download(b), await cloudflare());
    if (values.length > 100_000) throw new Error(`${values.length} entries, the limit is 100000`);
    // drop the old set first, duration covers one missed refresh
    await deleteDecisionsByScenario(PREFIX + b.id);
    if (values.length) await pushListDecisions(PREFIX + b.id, b.name, values, `${b.refreshHours * 2 + 1}h`, b.type);
    const next = upsert({ id, lastRun: Date.now(), lastCount: values.length, lastSkipped: skipped, lastError: null });
    if (by !== 'scheduler') audit(by, 'blocklist.refresh', id, { count: values.length, skipped });
    return next;
  } catch (e: any) {
    upsert({ id, lastRun: Date.now(), lastError: e.message });
    throw e;
  } finally {
    running.delete(id);
  }
}

export async function disable(id: string): Promise<void> {
  await deleteDecisionsByScenario(PREFIX + id);
  upsert({ id, enabled: false, lastCount: 0 });
}

export function startBlocklists(): void {
  const tick = async () => {
    for (const b of listAll()) {
      if (!b.enabled || running.has(b.id)) continue;
      // retry failures after 30m
      const wait = b.lastError ? 30 * 60_000 : b.refreshHours * 3600_000;
      if (b.lastRun && Date.now() - b.lastRun < wait) continue;
      await refresh(b.id).catch((e) => console.error('[blocklists]', b.id, e.message));
    }
  };
  setTimeout(tick, 30_000);
  setInterval(tick, 5 * 60_000);
}
