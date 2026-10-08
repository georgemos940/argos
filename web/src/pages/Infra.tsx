import { useEffect, useMemo, useState } from 'react';
import { Line, LineChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis, Legend } from 'recharts';
import {
  AlertTriangle, ArrowRight, Boxes, CheckCircle2, CloudLightning, Cpu, Download, Loader2, PackageCheck, RefreshCw, RotateCw, Server, ShieldHalf, Sparkles, Store,
} from 'lucide-react';
import { api } from '../api';
import { can, type Role } from '../App';
import { Badge, Button, Card, Confirm, ErrorBox, Modal, Skeleton, SkeletonList, SkeletonRows, Switch, ago, ask, cx, inputBase, inputCls, toast, useAsync } from '../ui';

const COLORS = ['#22d3ee', '#a855f7', '#f43f5e', '#f59e0b', '#10b981', '#60a5fa', '#e879f9'];

export default function Infra({ role }: { role: Role }) {
  return (
    <div className="space-y-7">
      <div>
        <h1 className="font-display text-3xl font-semibold text-white sm:text-[34px]">Infrastructure</h1>
        <p className="mt-2 max-w-2xl text-sm text-slate-400">Cloudflare protection, the CrowdSec engine, its bouncers and the detection rules.</p>
          <div className="hairline mt-4 w-40" />
      </div>
      <CloudflarePanel role={role} />
      <Engine />
      <Hub role={role} />
    </div>
  );
}

function CloudflarePanel({ role }: { role: Role }) {
  const cf = useAsync(() => api<{ configured: boolean; zones: { id: string; name: string; level: string; rps: number | null; guardHolds: boolean }[] }>('/cloudflare'), [], 30_000);
  const traffic = useAsync(() => api<{ perZone: { metric: { zone: string }; values: [number, number][] }[] }>('/traffic'), [], 30_000);
  const series = useMemo(() => {
    const byT = new Map<number, Record<string, number>>();
    for (const s of traffic.data?.perZone ?? []) for (const [t, v] of s.values) {
      const row = byT.get(t) ?? { t: t * 1000 };
      row[s.metric.zone] = v;
      byT.set(t, row);
    }
    return [...byT.values()].sort((a, b) => a.t - b.t);
  }, [traffic.data]);
  const zonesNames = (traffic.data?.perZone ?? []).map((s) => s.metric.zone);

  const set = async (id: string, name: string, level: string) => {
    const on = level === 'under_attack';
    if (!await ask({
      title: `${on ? 'Turn on' : 'Turn off'} Under Attack for ${name}?`, tone: on ? 'danger' : 'primary', confirmLabel: on ? 'Turn on' : 'Turn off',
      body: on ? 'Every visitor gets a Cloudflare challenge page for a few seconds before the site loads.'
        : 'Visitors reach the site directly again, without the challenge page.',
    })) return;
    await api(`/cloudflare/${id}`, { method: 'POST', json: { level } });
    toast(`${name}: ${level}`);
    cf.reload();
  };

  return (
    <Card title="Cloudflare · Under Attack per domain" icon={<CloudLightning size={16} />}>
      <ErrorBox error={cf.error} />
      <div className="grid gap-6 xl:grid-cols-5">
        <ul className="divide-y divide-white/5 xl:col-span-2">
          {!cf.data && !cf.error && <li><SkeletonList rows={6} /></li>}
          {(cf.data?.zones ?? []).map((z) => (
            <li key={z.id} className="flex items-center justify-between gap-3 py-3">
              <div>
                <div className="text-sm font-medium text-white">{z.name}</div>
                <div className="text-xs text-slate-500">{z.rps ?? 0} req/s{z.guardHolds && ' · held by the rate guard'}</div>
              </div>
              <div className="flex items-center gap-2">
                <Badge tone={z.level === 'under_attack' ? 'rose' : 'emerald'}>{z.level === 'under_attack' ? 'UNDER ATTACK' : z.level}</Badge>
                {can(role, 'operator') && (z.level === 'under_attack'
                  ? <Button tone="ghost" onClick={() => set(z.id, z.name, 'medium')}>Turn off</Button>
                  : <Button tone="danger" onClick={() => set(z.id, z.name, 'under_attack')}>Turn on</Button>)}
              </div>
            </li>
          ))}
        </ul>
        <div className="h-72 xl:col-span-3">
          {!traffic.data ? <Skeleton className="h-[calc(100%-1.25rem)] w-full rounded-xl" /> : <ResponsiveContainer>
            <LineChart data={series} margin={{ left: -20, right: 8 }}>
              <CartesianGrid stroke="#1c2540" vertical={false} />
              <XAxis dataKey="t" tickFormatter={(t) => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} stroke="#64748b" fontSize={11} minTickGap={40} />
              <YAxis stroke="#64748b" fontSize={11} />
              <Tooltip contentStyle={{ background: '#0e1324', border: '1px solid #2a355a', borderRadius: 12 }} labelFormatter={(t) => new Date(t).toLocaleTimeString()} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              {zonesNames.map((z, i) => <Line key={z} dataKey={z} stroke={COLORS[i % COLORS.length]} dot={false} strokeWidth={2} />)}
            </LineChart>
          </ResponsiveContainer>}
          <div className="text-center text-xs text-slate-500">Requests per second reaching the VPS, last hour</div>
        </div>
      </div>
    </Card>
  );
}

function Engine() {
  const { data, error, loading } = useAsync(() => api<{ bouncers: any[]; machines: any[]; metrics: any }>('/infra'), [], 60_000);
  const acq = data?.metrics?.acquisition ?? {};
  return (
    <div className="grid gap-6 xl:grid-cols-2">
      <Card title="Bouncers" icon={<ShieldHalf size={16} />}>
        <ErrorBox error={error} />
        <Table loading={loading} head={['Name', 'Type', 'IP', 'Last pull']}
          rows={(data?.bouncers ?? []).map((b) => [
            b.name, b.type, <span className="font-mono">{b.ip_address}</span>,
            <span className={cx(stale(b.last_pull) ? 'text-amber-300' : 'text-slate-400')}>{b.last_pull ? ago(b.last_pull) : '—'}</span>,
          ])} />
      </Card>
      <Card title="Machines" icon={<Server size={16} />}>
        <Table loading={loading} head={['Name', 'Version', 'IP', 'Heartbeat']}
          rows={(data?.machines ?? []).map((m) => [
            m.machineId, <span className="font-mono text-xs">{m.version}</span>, <span className="font-mono">{m.ipAddress}</span>,
            m.last_heartbeat ? ago(m.last_heartbeat) : '—',
          ])} />
      </Card>
      <Card title="Log sources read by CrowdSec" icon={<Cpu size={16} />} className="xl:col-span-2">
        <Table loading={loading} head={['Source', 'Lines read', 'Parsed', 'Unparsed', 'Poured to buckets']}
          rows={Object.entries(acq).map(([src, v]: [string, any]) => [
            <span className="font-mono text-xs">{src}</span>, num(v.reads), num(v.parsed), num(v.unparsed), num(v.pour),
          ])} />
      </Card>
    </div>
  );
}

const num = (n?: number) => <span className="font-mono">{n === undefined ? '—' : n.toLocaleString()}</span>;
const stale = (t?: string) => !t || Date.now() - new Date(t).getTime() > 3600_000 * 24;

function Table({ head, rows, loading }: { head: string[]; rows: React.ReactNode[][]; loading?: boolean }) {
  return (
    <div className="scroll-thin overflow-x-auto">
      <table className="data w-full text-sm">
        <thead className="text-left text-xs tracking-wide text-slate-500 uppercase"><tr className="border-b border-white/5">{head.map((h) => <th key={h} className="py-2 pr-4">{h}</th>)}</tr></thead>
        <tbody>{loading && !rows.length && <SkeletonRows rows={4} cols={head.length} />}{rows.map((r, i) => <tr key={i} className="border-b border-white/[0.03]">{r.map((c, j) => <td key={j} className="py-2 pr-4 text-slate-300">{c}</td>)}</tr>)}</tbody>
      </table>
      {!loading && !rows.length && <div className="py-6 text-center text-sm text-slate-500">Nothing here</div>}
    </div>
  );
}

interface PlanItem { type: string; name: string; from?: string; to?: string }
interface Plan { steps: { action: string; items: PlanItem[] }[]; dataFiles: boolean }

function UpgradeModal({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: () => void }) {
  const [plan, setPlan] = useState<Plan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [phase, setPhase] = useState<'idle' | 'upgrading' | 'done'>('idle');
  const [result, setResult] = useState<{ count: number; back: boolean; seconds: number } | null>(null);
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    if (!open) return;
    setPlan(null); setError(null); setPhase('idle'); setResult(null);
    api<Plan>('/hub/plan').then(setPlan).catch((e) => setError(e.message));
  }, [open]);
  useEffect(() => {
    if (phase !== 'upgrading') return;
    const t0 = Date.now();
    const t = setInterval(() => setElapsed(Math.round((Date.now() - t0) / 1000)), 500);
    return () => clearInterval(t);
  }, [phase]);

  const total = plan?.steps.reduce((n, s) => n + s.items.length, 0) ?? 0;
  const go = async () => {
    setPhase('upgrading'); setElapsed(0);
    try {
      const r = await api<{ count: number; back: boolean; seconds: number }>('/hub/upgrade', { method: 'POST' });
      setResult(r); setPhase('done'); onDone();
    } catch (e: any) { setError(e.message); setPhase('idle'); }
  };

  return (
    <Modal open={open} onClose={phase === 'upgrading' ? () => {} : onClose} wide title={
      <span className="flex items-center gap-3">
        <span className="grid h-9 w-9 place-items-center rounded-xl bg-cyan-400/15 text-cyan-200 ring-1 ring-cyan-400/30"><Download size={18} /></span>
        Upgrade detection rules
      </span>
    }>
      <ErrorBox error={error} />
      {!plan && !error && (
        <div className="flex items-center gap-3 py-8 text-sm text-slate-400"><Loader2 size={16} className="animate-spin text-cyan-300" /> Downloading the latest hub index and checking what changed…</div>
      )}

      {plan && phase !== 'done' && (
        <div className="space-y-5">
          <div className="flex gap-3 rounded-xl bg-amber-400/[0.07] p-4 text-sm text-amber-100/90 ring-1 ring-amber-400/25">
            <AlertTriangle size={18} className="mt-0.5 shrink-0 text-amber-300" />
            <div>
              <b className="text-amber-200">CrowdSec restarts automatically</b> after the upgrade so the new rules load. It takes about 10–30 seconds.
              Existing bans stay in force through the bouncers; new attacks are not detected while it starts.
            </div>
          </div>
          {total ? (
            <>
              <p className="text-sm text-slate-300"><b className="font-display text-2xl text-white">{total}</b> &nbsp;detection rule{total === 1 ? '' : 's'} will be updated:</p>
              <div className="scroll-thin max-h-[32vh] space-y-4 overflow-y-auto pr-1">
                {plan.steps.map((s) => (
                  <div key={s.action}>
                    <div className="mb-2 text-[11px] font-semibold tracking-[0.14em] text-slate-500 uppercase">{s.action}</div>
                    <div className="grid gap-1.5 sm:grid-cols-2">
                      {s.items.map((i) => (
                        <div key={i.type + i.name} className="flex items-center justify-between gap-3 rounded-lg bg-ink-950/60 px-3 py-2 ring-1 ring-white/5">
                          <span className="min-w-0"><span className="block truncate font-mono text-xs text-slate-100">{i.name}</span><span className="text-[10.5px] text-slate-500">{i.type}</span></span>
                          {i.to && <span className="shrink-0 font-mono text-[11px] text-slate-400">{i.from || 'new'} <ArrowRight size={10} className="inline text-cyan-300" /> <span className="text-emerald-300">{i.to}</span></span>}
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="flex items-center gap-3 rounded-xl bg-emerald-500/[0.07] p-4 text-sm text-emerald-200 ring-1 ring-emerald-400/20">
              <CheckCircle2 size={18} /> Every rule is already on the latest version.{plan.dataFiles && ' Only the data files (IP lists, user agents) will be refreshed.'}
            </div>
          )}
          {phase === 'upgrading' && (
            <div className="space-y-2">
              <div className="flex justify-between text-xs text-slate-400"><span>{elapsed < 8 ? 'Upgrading rules…' : 'Restarting CrowdSec and waiting for it to come back…'}</span><span className="font-mono">{elapsed}s</span></div>
              <div className="h-1.5 overflow-hidden rounded-full bg-white/5"><div className="h-full w-1/3 rounded-full bg-gradient-to-r from-cyan-400 to-violet-500" style={{ animation: 'indeterminate 1.3s ease-in-out infinite' }} /></div>
            </div>
          )}
          <div className="flex justify-end gap-2">
            <Button tone="ghost" disabled={phase === 'upgrading'} onClick={onClose}>Cancel</Button>
            <Button tone="primary" disabled={phase === 'upgrading'} onClick={go}>
              {phase === 'upgrading' ? <Loader2 size={14} className="animate-spin" /> : <RotateCw size={14} />}
              {total ? `Upgrade ${total} & restart` : 'Refresh & restart'}
            </Button>
          </div>
        </div>
      )}

      {phase === 'done' && result && (
        <div className="space-y-5">
          <div className={cx('flex items-center gap-4 rounded-xl p-5 ring-1', result.back ? 'bg-emerald-500/[0.08] ring-emerald-400/25' : 'bg-rose-500/[0.08] ring-rose-400/25')}>
            {result.back ? <CheckCircle2 size={28} className="text-emerald-300" /> : <AlertTriangle size={28} className="text-rose-300" />}
            <div>
              <div className="font-display text-lg text-white">{result.back ? 'Upgraded and back online' : 'Upgraded, but CrowdSec did not come back yet'}</div>
              <div className="text-sm text-slate-400">
                {result.count} rule{result.count === 1 ? '' : 's'} updated · {result.back ? `restart took ${result.seconds}s` : 'check `docker logs crowdsec` on the VPS'}
              </div>
            </div>
          </div>
          <div className="flex justify-end"><Button tone="primary" onClick={onClose}>Close</Button></div>
        </div>
      )}
    </Modal>
  );
}

function Hub({ role }: { role: Role }) {
  const { data, error, reload } = useAsync(() => api<Record<string, any[]>>('/hub'), []);
  const [type, setType] = useState('scenarios');
  const [q, setQ] = useState('');
  const [busy, setBusy] = useState(false);
  const [upgradeOpen, setUpgradeOpen] = useState(false);
  const [restartOpen, setRestartOpen] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);
  const admin = can(role, 'admin');
  const [mode, setMode] = useState<'installed' | 'store'>('installed');
  const sim = useAsync(() => api<{ global: boolean; scenarios: string[] }>('/simulation'), []);
  const items = (data?.[type] ?? []).filter((i) => !q || i.name.toLowerCase().includes(q.toLowerCase()));

  const run = async (path: string, body?: unknown, msg?: string) => {
    setBusy(true);
    try { await api(path, { method: 'POST', json: body ?? {} }); toast(msg ?? 'Done'); reload(); }
    catch (e: any) { toast(e.message, 'err'); }
    finally { setBusy(false); }
  };
  const restart = async () => {
    const r = await api<{ back: boolean; seconds: number }>('/crowdsec/restart', { method: 'POST' });
    toast(r.back ? `CrowdSec back online in ${r.seconds}s` : 'CrowdSec did not come back within 90s', r.back ? 'ok' : 'err');
  };
  const simulate = async (name: string, enabled: boolean) => {
    if (!await ask({
      title: `${enabled ? 'Simulate' : 'Stop simulating'} ${name}?`, confirmLabel: enabled ? 'Simulate & restart' : 'Enforce & restart',
      body: enabled ? 'It keeps raising alerts but stops banning. CrowdSec restarts to apply it (10–30 s).'
        : 'It starts banning again. CrowdSec restarts to apply it (10–30 s).',
    })) return;
    setBusy(true);
    try { await api('/simulation', { method: 'POST', json: { scenario: name, enabled } }); toast(`${name}: ${enabled ? 'simulation' : 'enforced'}`); sim.reload(); }
    catch (e: any) { toast(e.message, 'err'); }
    finally { setBusy(false); }
  };
  const remove = async () => {
    await api(`/hub/${type}/remove`, { method: 'POST', json: { name: removing } });
    await restart();
    setRemoving(null);
    reload();
  };

  return (
    <Card title="Detection rules (hub)" icon={<Boxes size={16} />} hover={false}
      actions={admin && (
        <div className="flex gap-2">
          <Button disabled={busy} onClick={() => setRestartOpen(true)}><RotateCw size={14} /> Restart</Button>
          <Button disabled={busy} onClick={() => run('/hub/update', undefined, 'Hub index updated')}><RefreshCw size={14} /> Update index</Button>
          <Button tone="primary" disabled={busy} onClick={() => setUpgradeOpen(true)}><Download size={14} /> Upgrade all</Button>
        </div>
      )}>
      <UpgradeModal open={upgradeOpen} onClose={() => setUpgradeOpen(false)} onDone={reload} />
      <Confirm open={restartOpen} onClose={() => setRestartOpen(false)} title="Restart CrowdSec?" confirmLabel="Restart" icon={<RotateCw size={18} />}
        onConfirm={async () => { await restart(); setRestartOpen(false); }}>
        Detection pauses for 10–30 seconds while it starts. Existing bans stay in force.
      </Confirm>
      <Confirm open={!!removing} onClose={() => setRemoving(null)} onConfirm={remove} tone="danger" title={`Remove ${removing}?`} confirmLabel="Remove & restart">
        CrowdSec stops using this {type.replace(/s$/, '')} and restarts to apply it (10–30 seconds). You can install it again from the hub.
      </Confirm>
      <div className="mb-5 flex rounded-xl bg-ink-950/60 p-1 ring-1 ring-white/10 sm:w-fit">
        {(['installed', 'store'] as const).map((m) => (
          <button key={m} onClick={() => setMode(m)}
            className={cx('flex-1 rounded-lg px-4 py-2 text-sm font-medium transition-all sm:flex-none',
              mode === m ? 'bg-gradient-to-r from-cyan-500/25 to-violet-500/25 text-white ring-1 ring-white/10 shadow-[0_0_16px_-6px_rgba(34,211,238,.8)]' : 'text-slate-400 hover:text-white')}>
            {m === 'installed' ? <><PackageCheck size={14} className="mr-1.5 inline" />Installed</> : <><Store size={14} className="mr-1.5 inline" />Hub store</>}
          </button>
        ))}
      </div>
      {mode === 'store' ? <HubStore admin={admin} onInstalled={reload} restart={restart} /> : <>
      {type === 'scenarios' && sim.data && (
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-xl bg-violet-500/[0.06] px-4 py-3 ring-1 ring-violet-400/20">
          <div className="text-sm text-slate-300">
            <b className="text-violet-200">Simulation mode</b> · a scenario in simulation still raises alerts but never bans. Use it to try a new rule safely.
            {sim.data.scenarios.length > 0 && <span className="text-slate-500"> {sim.data.scenarios.length} in simulation now.</span>}
          </div>
          {sim.data.global && <Badge tone="amber">global simulation is ON: nothing gets banned</Badge>}
        </div>
      )}
      <ErrorBox error={error} />
      <div className="mb-4 flex flex-wrap gap-2">
        {Object.keys(data ?? {}).filter((k) => (data?.[k]?.length ?? 0) > 0).map((k) => (
          <button key={k} onClick={() => setType(k)}
            className={cx('rounded-lg px-3 py-1.5 text-xs font-medium ring-1', type === k ? 'bg-cyan-500/20 text-cyan-200 ring-cyan-400/40' : 'text-slate-400 ring-white/10 hover:text-white')}>
            {k} <span className="text-slate-500">{data?.[k]?.length}</span>
          </button>
        ))}
        <input className={cx(inputBase, 'ml-auto w-56')} placeholder="Filter…" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      <div className="grid gap-2 md:grid-cols-2 2xl:grid-cols-3">
        {!data && !error && Array.from({ length: 9 }, (_, i) => <Skeleton key={i} className="skeleton-row h-[92px] rounded-xl" style={{ animationDelay: `${i * 40}ms` }} />)}
        {items.map((i) => (
          <div key={i.name} className="flex items-start justify-between gap-3 rounded-xl bg-ink-950/50 p-3 ring-1 ring-white/5">
            <div className="min-w-0">
              <div className="truncate font-mono text-sm text-slate-100" title={i.name}>{i.name}</div>
              <div className="mt-0.5 line-clamp-2 text-xs text-slate-500">{i.description}</div>
              <div className="mt-1.5 flex gap-1.5">
                <Badge tone={i.status?.includes('tainted') ? 'amber' : 'emerald'}><PackageCheck size={11} /> {i.status ?? 'enabled'}</Badge>
                {i.local_version && <Badge>v{i.local_version}</Badge>}
                {type === 'scenarios' && sim.data?.scenarios.includes(i.name) && <Badge tone="violet">simulation</Badge>}
              </div>
            </div>
            <div className="flex shrink-0 flex-col items-end gap-2">
              {admin && type !== 'contexts' && (
                <Button tone="ghost" disabled={busy} onClick={() => setRemoving(i.name)}>Remove</Button>
              )}
              {admin && type === 'scenarios' && sim.data && (
                <label className="flex items-center gap-2 pr-2 text-[11px] text-slate-500" title="Alert only, never ban">
                  simulate <Switch checked={sim.data.scenarios.includes(i.name)} onChange={(v) => simulate(i.name, v)} label={`Simulate ${i.name}`} />
                </label>
              )}
            </div>
          </div>
        ))}
      </div>
      </>}
    </Card>
  );
}

interface StoreItem { name: string; description: string; installed: boolean; status: string; version?: string }
const STORE_TYPES = ['collections', 'scenarios', 'parsers', 'appsec-rules', 'appsec-configs', 'postoverflows'];
const FEATURED = ['crowdsecurity/appsec-virtual-patching', 'crowdsecurity/appsec-generic-rules', 'crowdsecurity/http-dos', 'crowdsecurity/nextcloud', 'crowdsecurity/wordpress', 'crowdsecurity/grafana'];

function HubStore({ admin, onInstalled, restart }: { admin: boolean; onInstalled: () => void; restart: () => Promise<void> }) {
  const { data, error, reload } = useAsync(() => api<Record<string, StoreItem[]>>('/hub/store'), []);
  const [type, setType] = useState('collections');
  const [q, setQ] = useState('');
  const [show, setShow] = useState<'all' | 'available' | 'installed'>('available');
  const [limit, setLimit] = useState(60);
  const [busy, setBusy] = useState<string | null>(null);

  const items = useMemo(() => (data?.[type] ?? [])
    .filter((i) => show === 'all' || (show === 'installed' ? i.installed : !i.installed))
    .filter((i) => !q || `${i.name} ${i.description}`.toLowerCase().includes(q.toLowerCase()))
    .sort((a, b) => Number(FEATURED.includes(b.name)) - Number(FEATURED.includes(a.name)) || a.name.localeCompare(b.name)), [data, type, q, show]);

  const install = async (i: StoreItem) => {
    if (!await ask({
      title: `Install ${i.name}?`, confirmLabel: 'Install & restart',
      body: <>{i.description}<br /><br />CrowdSec restarts after the install so it loads (10–30 s). Existing bans stay in force.</>,
    })) return;
    setBusy(i.name);
    try {
      await api(`/hub/${type}/install`, { method: 'POST', json: { name: i.name } });
      await restart();
      toast(`${i.name} installed`);
      reload(); onInstalled();
    } catch (e: any) { toast(e.message, 'err'); }
    finally { setBusy(null); }
  };

  return (
    <div>
      <ErrorBox error={error} />
      <div className="mb-4 flex flex-wrap items-center gap-2">
        {STORE_TYPES.map((k) => (
          <button key={k} onClick={() => { setType(k); setLimit(60); }}
            className={cx('rounded-lg px-3 py-1.5 text-xs font-medium ring-1 transition', type === k ? 'bg-cyan-500/20 text-cyan-200 ring-cyan-400/40' : 'text-slate-400 ring-white/10 hover:text-white')}>
            {k} <span className="text-slate-500">{data?.[k]?.length ?? ''}</span>
          </button>
        ))}
        <div className="ml-auto flex gap-2">
          <div className="w-36">
            <select className={cx(inputCls, 'h-9 py-0 text-xs')} value={show} onChange={(e) => setShow(e.target.value as typeof show)}>
              <option value="available">Not installed</option><option value="installed">Installed</option><option value="all">All</option>
            </select>
          </div>
          <div className="w-56">
            <input className={cx(inputCls, 'h-9 py-0 text-xs')} placeholder="Search name or description…" value={q} onChange={(e) => { setQ(e.target.value); setLimit(60); }} />
          </div>
        </div>
      </div>
      <div className="grid gap-2.5 md:grid-cols-2 2xl:grid-cols-3">
        {!data && !error && Array.from({ length: 9 }, (_, i) => <Skeleton key={i} className="skeleton-row h-[104px] rounded-xl" style={{ animationDelay: `${i * 40}ms` }} />)}
        {items.slice(0, limit).map((i) => {
          const [author, short] = i.name.includes('/') ? i.name.split('/') : ['', i.name];
          const featured = FEATURED.includes(i.name);
          return (
            <div key={i.name} className={cx('group flex flex-col justify-between gap-3 rounded-xl bg-ink-950/50 p-3.5 ring-1 transition hover:-translate-y-0.5 hover:ring-cyan-400/30',
              featured ? 'ring-violet-400/30' : 'ring-white/5')}>
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="truncate font-mono text-sm text-slate-100" title={i.name}>{short}</span>
                  {featured && <Badge tone="violet"><Sparkles size={10} /> recommended</Badge>}
                </div>
                <div className="text-[11px] text-slate-600">{author}</div>
                <div className="mt-1 line-clamp-2 text-xs text-slate-400">{i.description || 'No description'}</div>
              </div>
              <div className="flex items-center justify-between">
                {i.installed ? <Badge tone="emerald"><PackageCheck size={11} /> installed{i.version && ` v${i.version}`}</Badge> : <span />}
                {admin && !i.installed && (
                  <Button tone="primary" className="h-8 py-0 text-xs" disabled={!!busy} onClick={() => install(i)}>
                    {busy === i.name ? <Loader2 size={13} className="animate-spin" /> : <Download size={13} />} Install
                  </Button>
                )}
              </div>
            </div>
          );
        })}
      </div>
      {data && !items.length && <div className="py-10 text-center text-sm text-slate-500">Nothing matches.</div>}
      {items.length > limit && (
        <div className="mt-4 text-center"><Button tone="ghost" onClick={() => setLimit((l) => l + 60)}>Show more ({items.length - limit} left)</Button></div>
      )}
    </div>
  );
}
