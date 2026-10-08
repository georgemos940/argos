import { useEffect, useState } from 'react';
import { api } from '../api';
import { Badge, ErrorBox, IpLink, Modal, Skeleton, SkeletonList, countryName, flag, shortScenario } from '../ui';

interface FullAlert {
  id: number; scenario: string; message: string; events_count: number; start_at: string; stop_at: string;
  source: { value: string; cn?: string; as_name?: string; as_number?: string; range?: string };
  decisions?: { id: number; type: string; duration: string; origin: string }[];
  events?: { timestamp: string; meta: { key: string; value: string }[] }[];
}

export function AlertDetail({ id, onClose }: { id: number | null; onClose: () => void }) {
  const [a, setA] = useState<FullAlert | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setA(null);
    if (id) api<FullAlert>(`/alerts/${id}`).then(setA).catch((e) => setError(e.message));
  }, [id]);
  const m = (e: NonNullable<FullAlert['events']>[number], k: string) => e.meta.find((x) => x.key === k)?.value;

  return (
    <Modal open={id !== null} onClose={onClose} title={a ? shortScenario(a.scenario) : 'Alert'} wide>
      <ErrorBox error={error} />
      {!a && !error && (
        <div className="space-y-5">
          <div className="grid gap-3 sm:grid-cols-4">{Array.from({ length: 4 }, (_, i) => <Skeleton key={i} className="h-16 rounded-xl" />)}</div>
          <SkeletonList rows={6} />
        </div>
      )}
      {a && (
        <div className="space-y-5">
          <div className="grid gap-3 sm:grid-cols-4">
            <Info label="Source"><IpLink ip={a.source.value} cn={a.source.cn} /></Info>
            <Info label="Country">{flag(a.source.cn)} {countryName(a.source.cn)}</Info>
            <Info label="Network">{a.source.as_name ?? '—'}{a.source.as_number && <span className="text-slate-500"> · AS{a.source.as_number}</span>}</Info>
            <Info label="Decision">{a.decisions?.length ? <Badge tone="rose">{a.decisions[0].type} {a.decisions[0].duration}</Badge> : <Badge>none</Badge>}</Info>
          </div>
          <p className="rounded-xl bg-ink-950/60 p-3 font-mono text-xs text-slate-400 ring-1 ring-white/5">{a.message}</p>
          <div>
            <h4 className="mb-2 text-xs font-semibold tracking-wide text-slate-400 uppercase">Requests that triggered it ({a.events?.length ?? 0})</h4>
            <div className="scroll-thin max-h-[420px] overflow-auto rounded-xl ring-1 ring-white/5">
              <table className="data w-full text-xs">
                <thead className="sticky top-0 bg-ink-850 text-left text-slate-500">
                  <tr><th className="px-3 py-2">Time</th><th className="px-3">Method</th><th className="px-3">Site</th><th className="px-3">Path</th><th className="px-3">Status</th></tr>
                </thead>
                <tbody className="font-mono">
                  {(a.events ?? []).map((e, i) => (
                    <tr key={i} className="border-t border-white/[0.03]">
                      <td className="px-3 py-1.5 whitespace-nowrap text-slate-500">{new Date(m(e, 'timestamp') ?? e.timestamp).toLocaleTimeString()}</td>
                      <td className="px-3 text-slate-300">{m(e, 'http_verb')}</td>
                      <td className="px-3 text-violet-300">{m(e, 'target_fqdn')}</td>
                      <td className="max-w-[420px] truncate px-3 text-slate-200" title={m(e, 'http_path')}>{m(e, 'http_path')}</td>
                      <td className="px-3"><Badge tone={(m(e, 'http_status') ?? '').startsWith('2') ? 'emerald' : 'amber'}>{m(e, 'http_status')}</Badge></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </Modal>
  );
}

function Info({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl bg-ink-950/50 p-3 ring-1 ring-white/5">
      <div className="text-[11px] tracking-wide text-slate-500 uppercase">{label}</div>
      <div className="mt-1 text-sm text-slate-200">{children}</div>
    </div>
  );
}
