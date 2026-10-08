import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { Ban, Fingerprint, Globe2, ListPlus, Route, ShieldOff, Target } from 'lucide-react';
import { api } from '../api';
import { can, type Role } from '../App';
import { BanModal } from './Decisions';
import { AlertDetail } from './AlertDetail';
import { Badge, Button, Card, Empty, ErrorBox, Field, Modal, Skeleton, SkeletonList, Stat, ago, countryName, cx, flag, inputCls, shortScenario, toast, useAsync } from '../ui';

interface Reputation {
  source: 'crowdsec-cti' | 'abuseipdb';
  score: number | null;
  verdict: string;
  details: Record<string, string | number | boolean | null>;
  tags: string[];
  quotaLeft?: number | null;
}

interface Profile {
  ip: string;
  alerts: { id: number; scenario: string; events_count: number; start_at: string;
    source: { cn?: string; as_name?: string; as_number?: string; range?: string };
    decisions?: { id: number; type: string; duration: string; origin: string }[];
    events?: { meta: { key: string; value: string }[] }[] }[];
  reputation: Reputation | null;
  reputationError: string | null;
}

const SOURCE = { 'crowdsec-cti': 'CrowdSec CTI', abuseipdb: 'AbuseIPDB' };

function ScoreRing({ score }: { score: number | null }) {
  const s = score ?? 0;
  const color = s >= 75 ? '#fb7185' : s >= 25 ? '#fbbf24' : '#34d399';
  const c = 2 * Math.PI * 42;
  return (
    <div className="relative h-32 w-32 shrink-0">
      <svg viewBox="0 0 100 100" className="-rotate-90">
        <circle cx="50" cy="50" r="42" fill="none" stroke="rgba(148,163,184,.12)" strokeWidth="9" />
        <circle cx="50" cy="50" r="42" fill="none" stroke={color} strokeWidth="9" strokeLinecap="round"
          strokeDasharray={`${(s / 100) * c} ${c}`} style={{ transition: 'stroke-dasharray 1.2s cubic-bezier(.2,.8,.2,1)', filter: `drop-shadow(0 0 8px ${color})` }} />
      </svg>
      <div className="absolute inset-0 grid place-items-center text-center">
        <div>
          <div className="font-display text-3xl font-semibold text-white tabular">{score ?? '—'}</div>
          <div className="text-[10px] tracking-widest text-slate-500 uppercase">risk</div>
        </div>
      </div>
    </div>
  );
}

export default function IpProfile({ role }: { role: Role }) {
  const ip = decodeURIComponent(useParams().ip ?? '');
  const { data, error, reload } = useAsync(() => api<Profile>(`/ip/${encodeURIComponent(ip)}`), [ip]);
  const [banOpen, setBanOpen] = useState(false);
  const [allowOpen, setAllowOpen] = useState(false);
  const [open, setOpen] = useState<number | null>(null);
  const op = can(role, 'operator');

  const first = data?.alerts[0];
  const rep = data?.reputation ?? null;
  const active = (data?.alerts ?? []).flatMap((a) => a.decisions ?? []);
  const sites = new Map<string, number>();
  const paths = new Map<string, number>();
  for (const a of data?.alerts ?? []) for (const e of a.events ?? []) {
    const s = e.meta.find((m) => m.key === 'target_fqdn')?.value;
    const p = e.meta.find((m) => m.key === 'http_path')?.value;
    if (s) sites.set(s, (sites.get(s) ?? 0) + 1);
    if (p) paths.set(p, (paths.get(p) ?? 0) + 1);
  }
  const network = first?.source.as_name ?? (rep?.details.Network as string) ?? (rep?.details.ISP as string) ?? 'unknown network';

  const unban = async () => {
    const r = await api<{ deleted: number }>('/decisions/unban', { method: 'POST', json: { values: [ip] } });
    toast(`Removed ${r.deleted} decision(s)`);
    reload();
  };

  return (
    <div className="space-y-7">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <div className="mb-2 text-[11px] font-semibold tracking-[0.18em] text-cyan-300/80 uppercase">IP profile</div>
          <h1 className="flex items-center gap-3 font-mono text-3xl font-semibold text-white sm:text-[34px]">
            <span className="font-sans">{flag(first?.source.cn)}</span>{ip}
          </h1>
          <p className="mt-2 max-w-2xl text-sm text-slate-400">
            {countryName(first?.source.cn)} · {network}
            {first?.source.as_number && <> · AS{first.source.as_number}</>}
            {first?.source.range && <> · {first.source.range}</>}
          </p>
          <div className="hairline mt-4 w-40" />
        </div>
        {op && (
          <div className="flex gap-2">
            <Button onClick={() => setAllowOpen(true)}><ListPlus size={16} /> Allowlist</Button>
            {active.length ? <Button tone="primary" onClick={unban}><ShieldOff size={16} /> Unban</Button>
              : <Button tone="danger" onClick={() => setBanOpen(true)}><Ban size={16} /> Ban</Button>}
          </div>
        )}
      </div>
      <ErrorBox error={error} />

      {!data && !error ? <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">{Array.from({ length: 4 }, (_, i) => <Skeleton key={i} className="h-36 rounded-[1.25rem]" />)}</div> : <div className="stagger grid grid-cols-2 gap-4 xl:grid-cols-4">
        <Stat label="Alerts (90 days)" value={data?.alerts.length ?? 0} accent="rose" icon={<Target size={16} />} />
        <Stat label="Requests seen" value={(data?.alerts ?? []).reduce((n, a) => n + a.events_count, 0)} accent="amber" icon={<Route size={16} />} />
        <Stat label="Status" value={active.length ? <Badge tone="rose">banned</Badge> : <Badge tone="emerald">not banned</Badge>}
          hint={active[0] ? `${active[0].duration.replace(/\.\d+s$/, 's')} left` : 'no active decision'} accent="cyan" icon={<Ban size={16} />} />
        <Stat label="Sites hit" value={sites.size} accent="violet" icon={<Globe2 size={16} />} />
      </div>}

      <Card title="Reputation" icon={<Fingerprint size={15} />} hover={false}
        subtitle={rep ? `from ${SOURCE[rep.source]}${rep.quotaLeft != null ? ` · ${rep.quotaLeft} checks left today` : ''} · cached 24h` : undefined}>
        {rep ? (
          <div className="flex flex-col gap-6 sm:flex-row sm:items-center">
            <ScoreRing score={rep.score} />
            <div className="min-w-0 flex-1 space-y-4">
              <div className="flex flex-wrap items-center gap-2">
                <span className={cx('font-display text-xl font-semibold capitalize',
                  (rep.score ?? 0) >= 75 ? 'text-rose-300' : (rep.score ?? 0) >= 25 ? 'text-amber-300' : 'text-emerald-300')}>{rep.verdict}</span>
                {rep.tags.map((t) => <Badge key={t} tone="violet">{t}</Badge>)}
              </div>
              <dl className="grid gap-x-8 gap-y-2 text-sm sm:grid-cols-2">
                {Object.entries(rep.details).filter(([, v]) => v !== null && v !== '').map(([k, v]) => (
                  <div key={k} className="flex justify-between gap-3 border-b border-white/[0.04] pb-1.5">
                    <dt className="text-slate-500">{k}</dt><dd className="text-right text-slate-200">{String(v)}</dd>
                  </div>
                ))}
              </dl>
            </div>
          </div>
        ) : !data ? (
          <div className="flex flex-col gap-6 sm:flex-row sm:items-center"><Skeleton className="h-32 w-32 shrink-0 rounded-full" /><div className="flex-1"><SkeletonList rows={4} /></div></div>
        ) : (
          <div className="text-sm text-slate-500">
            {data?.reputationError ?? 'Loading…'}
            {data?.reputationError?.includes('no reputation key') && <> Add a CrowdSec CTI or AbuseIPDB key in <b className="text-slate-300">Settings</b>.</>}
          </div>
        )}
      </Card>

      <div className="grid gap-6 xl:grid-cols-3">
        <Card title="Alert history" className="xl:col-span-2" hover={false}>
          {!data && <SkeletonList rows={6} />}
          <ul className="divide-y divide-white/5">
            {(data?.alerts ?? []).map((a) => (
              <li key={a.id} onClick={() => setOpen(a.id)} className="flex cursor-pointer items-center justify-between gap-3 rounded-lg px-2 py-2.5 transition hover:bg-white/[0.03]">
                <span className="text-slate-200">{shortScenario(a.scenario)}</span>
                <span className="flex items-center gap-3 text-xs">
                  <span className="font-mono text-slate-400">{a.events_count} events</span>
                  {a.decisions?.length ? <Badge tone="rose">{a.decisions[0].duration.replace(/\.\d+s$/, 's')}</Badge> : null}
                  <span className="text-slate-500">{ago(a.start_at)}</span>
                </span>
              </li>
            ))}
          </ul>
          {data && !data.alerts.length && <Empty>No alerts from this IP in the last 90 days.</Empty>}
        </Card>
        <div className="space-y-6">
          <Card title="Sites it hit">
            {[...sites.entries()].sort((a, b) => b[1] - a[1]).map(([s, n]) => (
              <div key={s} className="flex justify-between py-1 text-sm"><Badge tone="violet">{s}</Badge><span className="font-mono text-slate-400">{n}</span></div>
            ))}
            {!sites.size && <div className="text-sm text-slate-500">—</div>}
          </Card>
          <Card title="Paths it requested">
            <div className="scroll-thin max-h-72 space-y-1 overflow-y-auto">
              {[...paths.entries()].sort((a, b) => b[1] - a[1]).slice(0, 40).map(([p, n]) => (
                <div key={p} className="flex justify-between gap-3 font-mono text-xs"><span className="truncate text-slate-300">{p}</span><span className="text-slate-500">{n}</span></div>
              ))}
              {!paths.size && <div className="text-sm text-slate-500">—</div>}
            </div>
          </Card>
        </div>
      </div>

      <BanModal open={banOpen} onClose={() => setBanOpen(false)} onDone={reload} initial={ip} />
      <AllowModal open={allowOpen} onClose={() => setAllowOpen(false)} ip={ip} />
      <AlertDetail id={open} onClose={() => setOpen(null)} />
    </div>
  );
}

function AllowModal({ open, onClose, ip }: { open: boolean; onClose: () => void; ip: string }) {
  const { data } = useAsync(() => (open ? api<{ name: string }[]>('/allowlists') : Promise.resolve([])), [open]);
  const [name, setName] = useState('');
  const [comment, setComment] = useState('');
  const add = async () => {
    await api(`/allowlists/${encodeURIComponent(name || data?.[0]?.name || '')}/add`, { method: 'POST', json: { values: [ip], comment } });
    toast(`${ip} added to allowlist`);
    onClose();
  };
  return (
    <Modal open={open} onClose={onClose} title={`Allowlist ${ip}`}>
      <div className="space-y-4">
        <Field label="Allowlist">
          <select className={inputCls} value={name} onChange={(e) => setName(e.target.value)}>
            {(data ?? []).map((l) => <option key={l.name} value={l.name}>{l.name}</option>)}
          </select>
        </Field>
        <Field label="Comment"><input className={inputCls} value={comment} onChange={(e) => setComment(e.target.value)} /></Field>
        <p className="text-xs text-slate-500">CrowdSec will never ban an allowlisted IP. Existing bans are not removed automatically.</p>
        <div className="flex justify-end"><Button tone="primary" onClick={add}>Add</Button></div>
      </div>
    </Modal>
  );
}
