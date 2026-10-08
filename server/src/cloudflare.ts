import { existsSync, readFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { config } from './config.js';

function readEnv(): { token: string; zones: string[] } | null {
  if (config.cfToken) return config.cfZones.length ? { token: config.cfToken, zones: config.cfZones } : null;
  if (!config.cfEnvFile || !existsSync(config.cfEnvFile)) return null;
  const s = readFileSync(config.cfEnvFile, 'utf8');
  const token = s.match(/^CF_API_TOKEN="?([^"\n]+)"?/m)?.[1];
  const block = s.match(/^CF_ZONE_IDS=\(([\s\S]*?)\)/m)?.[1] ?? '';
  const zones = [...block.matchAll(/"([0-9a-f]{32})"/g)].map((m) => m[1]);
  return token ? { token, zones } : null;
}

async function cf<T>(path: string, token: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
    ...init,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
  });
  const body = (await res.json()) as any;
  if (!body.success) throw new Error(body.errors?.[0]?.message ?? `cloudflare ${res.status}`);
  return body.result as T;
}

const names = new Map<string, string>();

export interface ZoneState { id: string; name: string; level: string; guardHolds: boolean }

export function cloudflareConfigured(): boolean {
  return readEnv() !== null;
}

export async function zones(): Promise<ZoneState[]> {
  const env = readEnv();
  if (!env) return [];
  return Promise.all(env.zones.map(async (id) => {
    if (!names.has(id)) names.set(id, (await cf<{ name: string }>(`/zones/${id}`, env.token)).name);
    const level = (await cf<{ value: string }>(`/zones/${id}/settings/security_level`, env.token)).value;
    return { id, name: names.get(id)!, level, guardHolds: !!config.cfStateDir && existsSync(join(config.cfStateDir, 'rps', `uam_${id}`)) };
  }));
}

export async function setLevel(id: string, level: 'under_attack' | 'medium' | 'high'): Promise<void> {
  const env = readEnv();
  if (!env || !env.zones.includes(id)) throw new Error('unknown zone');
  await cf(`/zones/${id}/settings/security_level`, env.token, { method: 'PATCH', body: JSON.stringify({ value: level }) });
  // release the guard's hold so it can re-enable it
  if (!config.cfStateDir) return;
  const hold = join(config.cfStateDir, 'rps', `uam_${id}`);
  if (level !== 'under_attack' && existsSync(hold)) unlinkSync(hold);
}
