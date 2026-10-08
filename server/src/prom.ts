import { current } from './instances.js';

const base = () => {
  const u = current().promUrl;
  if (!u) throw new Error('no prometheus for this instance');
  return u;
};

export interface Sample { metric: Record<string, string>; value: number }

export async function query(q: string): Promise<Sample[]> {
  const res = await fetch(`${base()}/api/v1/query?query=${encodeURIComponent(q)}`);
  if (!res.ok) throw new Error(`prometheus ${res.status}`);
  const body = (await res.json()) as any;
  return (body.data?.result ?? []).map((r: any) => ({ metric: r.metric, value: Number(r.value[1]) }));
}

export async function scalar(q: string): Promise<number | null> {
  const r = await query(q).catch(() => []);
  return r.length ? r[0].value : null;
}

export async function range(q: string, seconds: number, step: number): Promise<{ metric: Record<string, string>; values: [number, number][] }[]> {
  const end = Math.floor(Date.now() / 1000);
  const p = new URLSearchParams({ query: q, start: String(end - seconds), end: String(end), step: String(step) });
  const res = await fetch(`${base()}/api/v1/query_range?${p}`);
  if (!res.ok) throw new Error(`prometheus ${res.status}`);
  const body = (await res.json()) as any;
  return (body.data?.result ?? []).map((r: any) => ({
    metric: r.metric,
    values: r.values.map((v: [number, string]) => [v[0], Number(v[1])]),
  }));
}
