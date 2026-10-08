import { getSetting } from './db.js';

export type RepMode = 'auto' | 'cti' | 'abuseipdb';

export interface Reputation {
  source: 'crowdsec-cti' | 'abuseipdb';
  score: number | null;          // 0-100
  verdict: string;
  details: Record<string, string | number | boolean | null>;
  tags: string[];
  quotaLeft?: number | null;
  raw?: unknown;
}

const cache = new Map<string, { at: number; rep: Reputation }>();
const TTL = 24 * 3600_000;

class LimitError extends Error {}

async function cti(ip: string, key: string): Promise<Reputation> {
  const res = await fetch(`https://cti.api.crowdsec.net/v2/smoke/${encodeURIComponent(ip)}`, { headers: { 'x-api-key': key } });
  if (res.status === 429 || res.status === 403) throw new LimitError(`CTI ${res.status}`);
  if (res.status === 404) {
    return { source: 'crowdsec-cti', score: 0, verdict: 'unknown to the CrowdSec network', details: {}, tags: [] };
  }
  if (!res.ok) throw new Error(`CTI ${res.status}`);
  const d = (await res.json()) as any;
  const score = d.scores?.overall?.total != null ? Math.round((d.scores.overall.total / 5) * 100) : null;
  return {
    source: 'crowdsec-cti',
    score,
    verdict: d.reputation ?? 'unknown',
    details: {
      'Background noise': d.background_noise ?? d.background_noise_score ?? null,
      'First seen': d.history?.first_seen?.slice(0, 10) ?? null,
      'Last seen': d.history?.last_seen?.slice(0, 10) ?? null,
      Network: d.as_name ?? null,
      'IP range': d.ip_range ?? null,
    },
    tags: [
      ...(d.behaviors ?? []).map((b: any) => b.label),
      ...(d.classifications?.classifications ?? []).map((c: any) => c.label),
    ].slice(0, 10),
    raw: d,
  };
}

async function abuseipdb(ip: string, key: string): Promise<Reputation> {
  const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
    headers: { Key: key, Accept: 'application/json' },
  });
  const left = res.headers.get('x-ratelimit-remaining');
  if (res.status === 429) throw new LimitError('AbuseIPDB daily limit reached');
  if (!res.ok) throw new Error(`AbuseIPDB ${res.status}`);
  const d = ((await res.json()) as any).data;
  const score = d.abuseConfidenceScore as number;
  return {
    source: 'abuseipdb',
    score,
    verdict: score >= 75 ? 'malicious' : score >= 25 ? 'suspicious' : d.totalReports ? 'low risk' : 'clean',
    details: {
      Reports: d.totalReports,
      'Distinct reporters': d.numDistinctUsers,
      'Last reported': d.lastReportedAt?.slice(0, 10) ?? null,
      ISP: d.isp ?? null,
      Usage: d.usageType ?? null,
      Domain: d.domain ?? null,
      Tor: d.isTor ?? null,
    },
    tags: [d.usageType, d.isTor ? 'Tor exit' : null, d.isWhitelisted ? 'whitelisted' : null].filter(Boolean),
    quotaLeft: left === null ? null : Number(left),
  };
}

export async function reputation(ip: string): Promise<{ rep: Reputation | null; error?: string }> {
  const hit = cache.get(ip);
  if (hit && Date.now() - hit.at < TTL) return { rep: hit.rep };

  const mode = getSetting<RepMode>('rep.mode', 'auto');
  const ctiKey = getSetting<string>('cti.key', '');
  const abuseKey = getSetting<string>('abuse.key', '');
  const order: ('cti' | 'abuseipdb')[] =
    mode === 'cti' ? ['cti'] : mode === 'abuseipdb' ? ['abuseipdb'] : ['cti', 'abuseipdb'];

  const errors: string[] = [];
  for (const p of order) {
    const key = p === 'cti' ? ctiKey : abuseKey;
    if (!key) continue;
    try {
      const rep = p === 'cti' ? await cti(ip, key) : await abuseipdb(ip, key);
      cache.set(ip, { at: Date.now(), rep });
      return { rep };
    } catch (e: any) {
      errors.push(e.message);
      if (!(e instanceof LimitError) && mode !== 'auto') break;
    }
  }
  return { rep: null, error: errors.join(' · ') || 'no reputation key configured' };
}
