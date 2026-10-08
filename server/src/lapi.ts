import { config } from './config.js';

export interface Decision {
  id: number; type: string; scope: string; value: string; duration: string;
  origin: string; scenario?: string; until?: string; simulated?: boolean;
}
export interface Source {
  scope: string; value: string; ip?: string; range?: string; cn?: string;
  as_name?: string; as_number?: string; latitude?: number; longitude?: number;
}
export interface EventMeta { key: string; value: string }
export interface Alert {
  id: number; scenario: string; message: string; events_count: number;
  start_at: string; stop_at: string; created_at?: string; machine_id?: string;
  source: Source; decisions?: Decision[]; events?: { timestamp: string; meta: EventMeta[] }[];
  remediation?: boolean; simulated?: boolean;
}

let token: { value: string; expires: number } | null = null;

// lapi wants a "name/version" user agent, otherwise reports a wrong password
const UA = { 'User-Agent': 'argos/1.0.0' };

async function login(): Promise<string> {
  const res = await fetch(`${config.lapiUrl}/v1/watchers/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...UA },
    body: JSON.stringify({ machine_id: config.lapiUser, password: config.lapiPassword, scenarios: [] }),
  });
  if (!res.ok) throw new Error(`LAPI login ${res.status}`);
  const body = (await res.json()) as { token: string; expire: string };
  token = { value: body.token, expires: new Date(body.expire).getTime() - 60_000 };
  return token.value;
}

async function lapi<T>(path: string, init: RequestInit = {}, retry = true): Promise<T> {
  const t = token && token.expires > Date.now() ? token.value : await login();
  const res = await fetch(`${config.lapiUrl}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...UA, Authorization: `Bearer ${t}`, ...(init.headers ?? {}) },
  });
  if (res.status === 401 && retry) {
    token = null;
    return lapi<T>(path, init, false);
  }
  if (!res.ok) throw new Error(`LAPI ${init.method ?? 'GET'} ${path} -> ${res.status} ${await res.text()}`);
  const text = await res.text();
  return (text ? JSON.parse(text) : null) as T;
}

export interface AlertQuery {
  since?: string; until?: string; ip?: string; range?: string; scenario?: string;
  origin?: string; has_active_decision?: boolean; include_capi?: boolean; limit?: number;
}

export function getAlerts(q: AlertQuery = {}): Promise<Alert[]> {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) if (v !== undefined && v !== '') p.set(k, String(v));
  if (!p.has('include_capi')) p.set('include_capi', 'false');
  if (!p.has('limit')) p.set('limit', '1000');
  return lapi<Alert[] | null>(`/v1/alerts?${p}`).then((a) => a ?? []);
}

export function getAlert(id: number): Promise<Alert> {
  return lapi<Alert>(`/v1/alerts/${id}`);
}

export function deleteDecision(id: number): Promise<{ nbDeleted: string }> {
  return lapi(`/v1/decisions/${id}`, { method: 'DELETE' });
}

export function deleteDecisionsFor(scope: 'ip' | 'range', value: string): Promise<{ nbDeleted: string }> {
  return lapi(`/v1/decisions?${scope}=${encodeURIComponent(value)}`, { method: 'DELETE' });
}

// same payload as `cscli decisions add`
export function addDecision(opts: {
  scope: 'Ip' | 'Range' | 'Country' | 'As'; value: string; duration: string; reason: string; type?: string; by: string;
}): Promise<unknown> {
  const now = new Date().toISOString();
  const scenario = `manual '${opts.type ?? 'ban'}' from '${opts.by}' via Argos: ${opts.reason}`;
  const alert = {
    scenario, scenario_hash: '', scenario_version: '', message: scenario,
    events_count: 1, start_at: now, stop_at: now, capacity: 0, leakspeed: '0',
    simulated: false, remediation: true, events: [],
    source: { scope: opts.scope, value: opts.value, ...(opts.scope === 'Ip' ? { ip: opts.value } : {}),
              ...(opts.scope === 'Range' ? { range: opts.value } : {}) },
    decisions: [{ duration: opts.duration, type: opts.type ?? 'ban', scope: opts.scope, value: opts.value,
                  origin: 'cscli', scenario: opts.reason }],
  };
  return lapi('/v1/alerts', { method: 'POST', body: JSON.stringify([alert]) });
}

export function deleteDecisionsByScenario(scenario: string): Promise<{ nbDeleted: string }> {
  return lapi(`/v1/decisions?scenario=${encodeURIComponent(scenario)}`, { method: 'DELETE' });
}

// one alert per list, origin "lists" keeps it out of include_capi=false queries
export function pushListDecisions(scenario: string, name: string, values: string[], duration: string, type: 'ban' | 'captcha'): Promise<unknown> {
  const now = new Date().toISOString();
  const alert = {
    scenario, scenario_hash: '', scenario_version: '', message: `blocklist ${name}: ${values.length} entries`,
    events_count: values.length, start_at: now, stop_at: now, capacity: 0, leakspeed: '0',
    simulated: false, remediation: true, events: [],
    source: { scope: 'argos-list', value: name },
    decisions: values.map((v) => ({ duration, type, scope: v.includes('/') ? 'Range' : 'Ip', value: v, origin: 'lists', scenario })),
  };
  return lapi('/v1/alerts', { method: 'POST', body: JSON.stringify([alert]) });
}

export async function lapiHealth(): Promise<boolean> {
  try { await lapi('/v1/alerts?limit=1&include_capi=false'); return true; } catch { return false; }
}

export const meta = (a: Alert, i: number, key: string): string | undefined =>
  a.events?.[i]?.meta?.find((m) => m.key === key)?.value;
