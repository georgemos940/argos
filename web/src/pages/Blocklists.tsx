import { useEffect, useState } from 'react';
import { AlertTriangle, CheckCircle2, Clock, Link2, ListX, Loader2, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { api } from '../api';
import { can, type Role } from '../App';
import BouncerUsage from './BouncerUsage';
import { AnimatedNumber, Badge, Button, Field, Modal, PageHeader, SkeletonCard, Switch, ago, ask, cx, inputBase, inputCls, toast, useAsync } from '../ui';

interface Blocklist {
  id: string; name: string; url: string; description: string; enabled: boolean; refreshHours: number; type: 'ban' | 'captcha';
  lastRun: number | null; lastCount: number | null; lastSkipped: number | null; lastError: string | null;
}

const PRESET_IDS = ['spamhaus-drop', 'firehol-level1', 'tor-exits', 'abuseipdb'];
const REFRESH = [1, 3, 6, 12, 24, 48];

export default function Blocklists({ role }: { role: Role }) {
  const { data, error, reload } = useAsync(() => api<Blocklist[]>('/blocklists'), [], 30_000);
  const [busy, setBusy] = useState<string | null>(null);
  const [lists, setLists] = useState<Blocklist[] | null>(null);
  const [adding, setAdding] = useState(false);
  const admin = can(role, 'admin');
  useEffect(() => setLists(null), [data]);
  const all = lists ?? data;
  const total = (all ?? []).filter((b) => b.enabled).reduce((n, b) => n + (b.lastCount ?? 0), 0);

  const run = async (id: string, fn: () => Promise<Blocklist[]>, msg: string) => {
    setBusy(id);
    try { setLists(await fn()); toast(msg); }
    catch (e: any) { toast(e.message, 'err'); reload(); setLists(null); }
    finally { setBusy(null); }
  };
  const update = (b: Blocklist, patch: Partial<Blocklist>) =>
    run(b.id, () => api('/blocklists/' + b.id, { method: 'PUT', json: { ...b, ...patch } }),
      patch.enabled === false ? `${b.name} turned off` : `${b.name} updated`);
  const toggle = async (b: Blocklist, on: boolean) => {
    if (on && !await ask({
      title: `Turn on ${b.name}?`, confirmLabel: 'Turn on',
      body: <>The list is downloaded now and every {b.refreshHours}h after that. Its IPs are blocked by the bouncers within a minute.
        Private and reserved ranges, your own addresses (SELF_IPS) and Cloudflare are always skipped.</>,
    })) return;
    update(b, { enabled: on });
  };
  const del = async (b: Blocklist) => {
    if (!await ask({ title: `Delete ${b.name}?`, body: 'The list and all bans it created are removed.', tone: 'danger', confirmLabel: 'Delete' })) return;
    run(b.id, () => api('/blocklists/' + b.id, { method: 'DELETE' }), `${b.name} deleted`);
  };

  return (
    <div className="space-y-7">
      <PageHeader title="Blocklists" eyebrow="Respond"
        subtitle="Public lists of known bad IPs, blocked before they even try. Refreshed automatically; old entries expire on their own."
        actions={admin && <Button tone="primary" onClick={() => setAdding(true)}><Plus size={16} /> Custom list</Button>} />

      <div className="glass relative overflow-hidden p-5 sm:p-6">
        <div className="pointer-events-none absolute -top-16 -right-10 h-48 w-48 rounded-full bg-gradient-to-br from-rose-500/25 to-transparent blur-3xl" />
        <div className="relative flex flex-wrap items-center gap-8">
          <div>
            <div className="text-[11px] font-semibold tracking-[0.12em] text-slate-400 uppercase">Blocked by lists</div>
            <div className="mt-1 font-display text-4xl font-semibold text-white tabular"><AnimatedNumber value={total} /></div>
          </div>
          <div className="text-sm text-slate-400">
            <b className="text-slate-200">{(all ?? []).filter((b) => b.enabled).length}</b> of {(all ?? []).length} lists active
          </div>
          {error && <div className="text-sm text-rose-300">{error}</div>}
        </div>
      </div>

      <BouncerUsage />

      <div className="stagger grid gap-5 lg:grid-cols-2">
        {!all && !error && [0, 1, 2, 3].map((i) => <SkeletonCard key={i} rows={2} />)}
        {(all ?? []).map((b) => {
          const loading = busy === b.id;
          const custom = !PRESET_IDS.includes(b.id);
          return (
            <section key={b.id} className={cx('glass hoverable relative overflow-hidden p-5 transition-all', b.enabled && 'ring-1 ring-cyan-400/25')}>
              {b.enabled && <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-300/70 to-transparent" />}
              <div className="flex items-start justify-between gap-4">
                <div className="flex min-w-0 items-start gap-3">
                  <span className={cx('grid h-10 w-10 shrink-0 place-items-center rounded-xl ring-1 transition', b.enabled ? 'bg-gradient-to-br from-rose-500/30 to-violet-500/30 text-rose-100 ring-white/10' : 'bg-white/[0.04] text-slate-500 ring-white/10')}>
                    <ListX size={18} />
                  </span>
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="font-display text-[17px] font-semibold text-white">{b.name}</h3>
                      {custom && <Badge tone="violet">custom</Badge>}
                    </div>
                    <p className="mt-1 text-sm leading-relaxed text-slate-400">{b.description || <span className="font-mono text-xs">{b.url}</span>}</p>
                  </div>
                </div>
                {admin ? (loading ? <Loader2 size={20} className="mt-1 animate-spin text-cyan-300" /> : <Switch checked={b.enabled} onChange={(v) => toggle(b, v)} label={b.name} />)
                  : <Badge tone={b.enabled ? 'emerald' : 'slate'}>{b.enabled ? 'on' : 'off'}</Badge>}
              </div>

              <div className="mt-5 grid grid-cols-3 gap-3">
                <Mini label="Entries" value={b.enabled && b.lastCount != null ? b.lastCount.toLocaleString() : '—'} />
                <Mini label="Refresh" value={`every ${b.refreshHours}h`} icon={<Clock size={11} />} />
                <Mini label="Last update" value={b.lastRun ? ago(b.lastRun) : 'never'} />
              </div>

              {b.lastError && (
                <div className="mt-4 flex items-center gap-2 rounded-lg bg-rose-500/10 px-3 py-2 text-xs text-rose-200 ring-1 ring-rose-500/25">
                  <AlertTriangle size={13} /> {b.lastError}
                </div>
              )}
              {!b.lastError && b.enabled && b.lastSkipped ? (
                <div className="mt-4 flex items-center gap-2 text-xs text-slate-500"><CheckCircle2 size={13} className="text-emerald-400" /> {b.lastSkipped} private/Cloudflare entries skipped for safety</div>
              ) : null}

              {admin && (
                <div className="mt-5 flex flex-wrap items-center gap-2 border-t border-white/[0.05] pt-4">
                  <select className={cx(inputBase, 'h-9 w-auto py-0 text-xs')} value={b.refreshHours} disabled={loading} onChange={(e) => update(b, { refreshHours: Number(e.target.value) })}>
                    {REFRESH.map((h) => <option key={h} value={h}>every {h}h</option>)}
                  </select>
                  <select className={cx(inputBase, 'h-9 w-auto py-0 text-xs')} value={b.type} disabled={loading} onChange={(e) => update(b, { type: e.target.value as Blocklist['type'] })}>
                    <option value="ban">ban</option><option value="captcha">captcha</option>
                  </select>
                  <div className="ml-auto flex gap-1">
                    {b.url !== 'abuseipdb' && <a href={b.url} target="_blank" rel="noreferrer" title="Open the source" className="rounded-lg p-2 text-slate-500 transition hover:bg-white/5 hover:text-white"><Link2 size={15} /></a>}
                    {b.enabled && <Button tone="ghost" disabled={loading} onClick={() => run(b.id, () => api(`/blocklists/${b.id}/refresh`, { method: 'POST' }), `${b.name} refreshed`)}><RefreshCw size={14} className={cx(loading && 'animate-spin')} /> Refresh</Button>}
                    {custom && <Button tone="ghost" disabled={loading} onClick={() => del(b)}><Trash2 size={14} /></Button>}
                  </div>
                </div>
              )}
            </section>
          );
        })}
      </div>
      <AddList open={adding} onClose={() => setAdding(false)} onDone={(l) => setLists(l)} />
    </div>
  );
}

function Mini({ label, value, icon }: { label: string; value: string; icon?: React.ReactNode }) {
  return (
    <div className="rounded-xl bg-ink-950/50 px-3 py-2.5 ring-1 ring-white/[0.05]">
      <div className="flex items-center gap-1 text-[10px] font-semibold tracking-[0.1em] text-slate-500 uppercase">{icon}{label}</div>
      <div className="mt-1 truncate font-mono text-sm text-slate-100">{value}</div>
    </div>
  );
}

function AddList({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: (l: Blocklist[]) => void }) {
  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [refresh, setRefresh] = useState(12);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const id = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40);
  const save = async () => {
    setBusy(true); setError(null);
    try {
      onDone(await api(`/blocklists/${id}`, { method: 'PUT', json: { name, url, refreshHours: refresh, type: 'ban', enabled: true } }));
      toast(`${name} added`); setName(''); setUrl(''); onClose();
    } catch (e: any) { setError(e.message); }
    finally { setBusy(false); }
  };
  return (
    <Modal open={open} onClose={onClose} title="Custom blocklist">
      <div className="space-y-4">
        <Field label="Name"><input className={inputCls} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Emerging Threats" /></Field>
        <Field label="URL" hint="A plain text file with one IP or CIDR per line. Comments after # or ; are ignored.">
          <input className={cx(inputCls, 'font-mono text-xs')} value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt" />
        </Field>
        <Field label="Refresh every">
          <select className={inputCls} value={refresh} onChange={(e) => setRefresh(Number(e.target.value))}>{REFRESH.map((h) => <option key={h} value={h}>{h} hours</option>)}</select>
        </Field>
        {error && <div className="rounded-lg bg-rose-500/10 px-3 py-2 text-sm text-rose-300 ring-1 ring-rose-500/30">{error}</div>}
        <div className="flex justify-end gap-2">
          <Button tone="ghost" onClick={onClose}>Cancel</Button>
          <Button tone="primary" disabled={busy || id.length < 2 || !url} onClick={save}>{busy && <Loader2 size={14} className="animate-spin" />} Add and download</Button>
        </div>
      </div>
    </Modal>
  );
}
