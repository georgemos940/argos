import { useEffect, useState } from 'react';
import { Code2, Gavel, History, Loader2, ShieldQuestion, Timer, TrendingUp } from 'lucide-react';
import { api } from '../api';
import { can, type Role } from '../App';
import { Badge, Button, Card, ErrorBox, PageHeader, SkeletonCard, Switch, ago, ask, cx, inputBase, toast, useAsync } from '../ui';

interface Policy { banHours: number; escalate: boolean; maxHours: number; captcha: boolean; captchaHours: number; captchaMax: number }
interface State { live: string | null; managed: boolean; policy: Policy; generated: string; backup: { at: number } | null }
type Applied = { changed: boolean; back: boolean; seconds: number };

const QUICK = [[1, '1h'], [4, '4h'], [24, '24h'], [168, '7d']] as const;
const human = (h: number) => (h % 24 === 0 && h >= 48 ? `${h / 24}d` : `${h}h`);

export default function PolicyPage({ role }: { role: Role }) {
  const { data, error, reload } = useAsync(() => api<State>('/policy'), []);
  const admin = can(role, 'admin');
  const [p, setP] = useState<Policy | null>(null);
  const [tab, setTab] = useState<'generated' | 'live' | 'raw'>('generated');
  const [raw, setRaw] = useState('');
  const [preview, setPreview] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!data) return;
    setP(data.policy);
    setRaw(data.live ?? '');
    setPreview(data.generated);
    if (!data.managed && data.live) setTab('live');
  }, [data]);

  useEffect(() => {
    if (!p) return;
    const t = setTimeout(() => api<{ generated: string }>('/policy/preview', { method: 'POST', json: p }).then((r) => setPreview(r.generated)).catch(() => {}), 200);
    return () => clearTimeout(t);
  }, [p]);

  const set = (patch: Partial<Policy>) => setP((x) => (x ? { ...x, ...patch } : x));

  const run = async (path: string, init: Parameters<typeof api>[1], done: string) => {
    setBusy(true);
    try {
      const r = await api<Applied>(path, init);
      toast(r.changed ? `${done}, CrowdSec back in ${r.seconds}s` : 'Nothing changed, the file is already like that');
      reload();
    } catch (e: any) { toast(e.message, 'err'); }
    finally { setBusy(false); }
  };

  const apply = async () => {
    const isRaw = tab === 'raw';
    if (!await ask({
      title: 'Apply the ban policy?', confirmLabel: 'Check and apply',
      body: <>CrowdSec checks the new <code className="text-slate-200">profiles.yaml</code> first and restarts into it (about 15 seconds, bans already made stay in place).
        If it refuses the file or does not come back up, the current one is put back.</>,
    })) return;
    run('/policy', { method: 'PUT', json: isRaw ? { raw } : { policy: p } }, 'Ban policy applied');
  };
  const restore = async () => {
    if (!await ask({ title: 'Restore the previous profiles.yaml?', confirmLabel: 'Restore', body: `The file that was live before the last change (saved ${ago(data!.backup!.at)}) goes back, checked and restarted the same way.` })) return;
    run('/policy/restore', { method: 'POST' }, 'Previous policy restored');
  };

  const steps = p ? [1, 2, 3, 4, 5].map((k) => (p.escalate ? Math.min(k * p.banHours, p.maxHours) : p.banHours)) : [];

  return (
    <div className="space-y-7">
      <PageHeader title="Ban policy" eyebrow="Respond"
        subtitle="What CrowdSec does when a scenario fires: how long a ban lasts, longer bans for repeat offenders, a captcha before a ban for web attacks."
        actions={admin && data && (
          <div className="flex gap-2">
            {data.backup && <Button tone="ghost" disabled={busy} onClick={restore}><History size={15} /> Restore previous</Button>}
            <Button tone="primary" disabled={busy || !p} onClick={apply}>{busy ? <Loader2 size={15} className="animate-spin" /> : <Gavel size={15} />} {busy ? 'Checking and restarting…' : 'Apply'}</Button>
          </div>
        )} />
      <ErrorBox error={error} />

      {data && !data.managed && (
        <div className="glass flex items-start gap-3 p-4 text-sm text-slate-300 ring-1 ring-amber-400/25">
          <ShieldQuestion size={18} className="mt-0.5 shrink-0 text-amber-300" />
          <div>The live <code className="text-slate-100">profiles.yaml</code> was not written by Argos (CrowdSec's stock file or your own).
            Applying replaces it; the current file is kept and <b className="text-slate-100">Restore previous</b> brings it back.</div>
        </div>
      )}

      <div className="grid grid-cols-[minmax(0,1fr)] gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        {!p ? <SkeletonCard rows={8} /> : (
          <div className="stagger space-y-6">
            <Card title="Ban" icon={<Timer size={16} />} subtitle="Every IP or range a scenario flags">
              <div className="flex flex-wrap items-center gap-2">
                <input type="number" min={1} max={8760} disabled={!admin} className={cx(inputBase, 'w-24 font-mono')} value={p.banHours}
                  onChange={(e) => set({ banHours: Number(e.target.value) })} />
                <span className="text-sm text-slate-400">hours</span>
                <div className="ml-2 flex gap-1">
                  {QUICK.map(([h, l]) => (
                    <button key={h} disabled={!admin} onClick={() => set({ banHours: h })}
                      className={cx('rounded-lg px-2.5 py-1 font-mono text-xs ring-1 transition', p.banHours === h ? 'bg-cyan-400/15 text-cyan-100 ring-cyan-400/40' : 'text-slate-400 ring-white/10 hover:text-white')}>{l}</button>
                  ))}
                </div>
              </div>
            </Card>

            <Card title="Repeat offenders" icon={<TrendingUp size={16} />} subtitle="Each new ban for the same IP lasts longer"
              actions={<Switch checked={p.escalate} onChange={(v) => admin && set({ escalate: v })} label="Escalate" />}>
              <div className={cx('space-y-4 transition', !p.escalate && 'opacity-40')}>
                <div className="flex flex-wrap items-center gap-2 text-sm text-slate-400">
                  ban × (previous bans + 1), at most
                  <input type="number" min={p.banHours} max={8760} disabled={!admin || !p.escalate} className={cx(inputBase, 'w-24 font-mono')} value={p.maxHours}
                    onChange={(e) => set({ maxHours: Number(e.target.value) })} />
                  hours
                </div>
                <div className="flex items-end gap-2">
                  {steps.map((h, i) => (
                    <div key={i} className="flex-1">
                      <div className="rounded-t-md bg-gradient-to-t from-rose-500/50 to-violet-500/40 transition-all duration-500" style={{ height: `${10 + 60 * (h / Math.max(...steps))}px` }} />
                      <div className="mt-1.5 text-center font-mono text-xs text-slate-200">{human(h)}</div>
                      <div className="text-center text-[10px] text-slate-500">{['1st', '2nd', '3rd', '4th', '5th'][i]}</div>
                    </div>
                  ))}
                </div>
              </div>
            </Card>

            <Card title="Captcha first" icon={<ShieldQuestion size={16} />} subtitle="Web attacks (http scenarios) get a captcha before a ban"
              actions={<Switch checked={p.captcha} onChange={(v) => admin && set({ captcha: v })} label="Captcha" />}>
              <div className={cx('space-y-3 text-sm text-slate-400 transition', !p.captcha && 'opacity-40')}>
                <div className="flex flex-wrap items-center gap-2">
                  captcha for
                  <input type="number" min={1} max={720} disabled={!admin || !p.captcha} className={cx(inputBase, 'w-20 font-mono')} value={p.captchaHours}
                    onChange={(e) => set({ captchaHours: Number(e.target.value) })} />
                  hours, a ban once an IP had
                  <input type="number" min={1} max={50} disabled={!admin || !p.captcha} className={cx(inputBase, 'w-20 font-mono')} value={p.captchaMax}
                    onChange={(e) => set({ captchaMax: Number(e.target.value) })} />
                  decisions in 24h
                </div>
                <p className="text-xs text-slate-500">Needs captcha set up on the HTTP bouncer (for the Traefik plugin: captchaProvider and keys). The firewall bouncer only acts on bans.</p>
              </div>
            </Card>
          </div>
        )}

        <Card title="profiles.yaml" icon={<Code2 size={16} />} hover={false}
          actions={<div className="flex rounded-xl bg-ink-950/60 p-1 ring-1 ring-white/10">
            {([['generated', 'From the form'], ['live', 'Live now'], ...(admin ? [['raw', 'Edit YAML']] : [])] as [typeof tab, string][]).map(([k, l]) => (
              <button key={k} onClick={() => setTab(k)} className={cx('rounded-lg px-3 py-1 text-xs font-medium transition', tab === k ? 'bg-white/10 text-white' : 'text-slate-400 hover:text-white')}>{l}</button>
            ))}
          </div>}>
          {data && (
            <div className="mb-3 flex flex-wrap gap-2">
              <Badge tone={data.managed ? 'emerald' : 'amber'}>{data.managed ? 'managed by Argos' : 'not from Argos'}</Badge>
              {data.backup && <Badge>previous kept {ago(data.backup.at)}</Badge>}
              {tab === 'raw' && <Badge tone="violet">applies exactly what is in the editor</Badge>}
            </div>
          )}
          {tab === 'raw'
            ? <textarea spellCheck={false} className={cx(inputBase, 'scroll-thin h-[520px] w-full resize-y font-mono text-xs leading-relaxed')} value={raw} onChange={(e) => setRaw(e.target.value)} />
            : <pre className="scroll-thin max-h-[560px] overflow-auto rounded-xl bg-ink-950/70 p-4 font-mono text-xs leading-relaxed text-slate-300 ring-1 ring-white/[0.06]">
                {tab === 'live' ? (data?.live ?? 'profiles.yaml not found') : preview}
              </pre>}
        </Card>
      </div>
    </div>
  );
}
