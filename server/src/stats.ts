import { getAlerts, meta, type Alert } from './lapi.js';
import { current } from './instances.js';

const cache = new Map<string, { at: number; alerts: Alert[] }>();

export async function recentAlerts(window: '24h' | '7d' | '30d'): Promise<Alert[]> {
  const key = `${current().id}:${window}`;
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < 15_000) return hit.alerts;
  const alerts = await getAlerts({ since: window === '24h' ? '24h' : window === '7d' ? '168h' : '720h', limit: 5000 });
  cache.set(key, { at: Date.now(), alerts });
  return alerts;
}

const top = (m: Map<string, number>, n = 10) =>
  [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n).map(([key, count]) => ({ key, count }));

const bump = (m: Map<string, number>, k: string | undefined, by = 1) => {
  if (k) m.set(k, (m.get(k) ?? 0) + by);
};

export function summarize(alerts: Alert[], window: '24h' | '7d' | '30d') {
  const countries = new Map<string, number>();
  const asns = new Map<string, number>();
  const scenarios = new Map<string, number>();
  const sites = new Map<string, number>();
  const paths = new Map<string, number>();
  const ips = new Set<string>();
  const points = new Map<string, { lat: number; lon: number; cn: string; count: number; ips: Set<string> }>();

  const bucketMs = window === '24h' ? 3600_000 : window === '7d' ? 6 * 3600_000 : 24 * 3600_000;
  const span = window === '24h' ? 24 : window === '7d' ? 28 : 30;
  const now = Date.now();
  const firstBucket = Math.floor((now - span * bucketMs) / bucketMs) * bucketMs;
  const timeline = new Map<number, { t: number; alerts: number; bans: number }>();
  for (let i = 0; i <= span; i++) timeline.set(firstBucket + i * bucketMs, { t: firstBucket + i * bucketMs, alerts: 0, bans: 0 });

  for (const a of alerts) {
    if (a.scenario.startsWith('manual ')) continue;
    const s = a.source;
    if (s.ip) ips.add(s.ip);
    bump(countries, s.cn);
    bump(asns, s.as_name ? `${s.as_name} (AS${s.as_number})` : undefined);
    bump(scenarios, a.scenario);
    for (let i = 0; i < (a.events?.length ?? 0); i++) {
      bump(sites, meta(a, i, 'target_fqdn'));
      bump(paths, meta(a, i, 'http_path'));
    }
    if (s.latitude !== undefined && s.longitude !== undefined && (s.latitude || s.longitude)) {
      const key = `${s.latitude.toFixed(1)},${s.longitude.toFixed(1)}`;
      const p = points.get(key) ?? { lat: s.latitude, lon: s.longitude, cn: s.cn ?? '', count: 0, ips: new Set() };
      p.count++;
      if (s.ip) p.ips.add(s.ip);
      points.set(key, p);
    }
    const b = timeline.get(Math.floor(new Date(a.start_at).getTime() / bucketMs) * bucketMs);
    if (b) {
      b.alerts++;
      if (a.decisions?.length) b.bans++;
    }
  }

  return {
    totals: { alerts: alerts.filter((a) => !a.scenario.startsWith('manual ')).length, uniqueIps: ips.size },
    timeline: [...timeline.values()],
    countries: top(countries, 15),
    asns: top(asns),
    scenarios: top(scenarios),
    sites: top(sites),
    paths: top(paths, 15),
    points: [...points.values()].map((p) => ({ lat: p.lat, lon: p.lon, cn: p.cn, count: p.count, ips: [...p.ips].slice(0, 5) })),
  };
}

// no event payloads
export function slim(a: Alert) {
  return {
    id: a.id, scenario: a.scenario, message: a.message, events_count: a.events_count,
    start_at: a.start_at, stop_at: a.stop_at, source: a.source,
    target: meta(a, 0, 'target_fqdn'),
    decisions: (a.decisions ?? []).map((d) => ({ id: d.id, type: d.type, value: d.value, duration: d.duration, origin: d.origin })),
  };
}
