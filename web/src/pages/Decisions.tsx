import { useMemo, useState } from 'react';
import { Ban, Plus, Search, Trash2, Upload, X } from 'lucide-react';
import { api } from '../api';
import { can, type Role } from '../App';
import { Badge, Button, Card, Checkbox, Confirm, Empty, ErrorBox, Field, IpLink, Modal, SkeletonRows, ago, cx, inputCls, shortScenario, toast, useAsync } from '../ui';

const ORIGINS = [{ v: 'all', label: 'All' }, { v: 'crowdsec', label: 'Detected' }, { v: 'cscli', label: 'Manual' }];

interface Row {
  id: number; type: string; scope: string; value: string; duration: string; origin: string;
  reason: string; alertId: number; cn?: string; as_name?: string; events: number; at: string;
}

const DURATIONS = ['1h', '4h', '24h', '168h', '720h', '8760h'];
const durLabel: Record<string, string> = { '1h': '1 hour', '4h': '4 hours', '24h': '1 day', '168h': '7 days', '720h': '30 days', '8760h': '1 year' };

export default function Decisions({ role }: { role: Role }) {
  const { data, error, loading, reload } = useAsync(() => api<Row[]>('/decisions'), [], 30_000);
  const [q, setQ] = useState('');
  const [origin, setOrigin] = useState('all');
  const [sel, setSel] = useState<Set<number>>(new Set());
  const [banOpen, setBanOpen] = useState(false);
  const [bulkOpen, setBulkOpen] = useState(false);
  const op = can(role, 'operator');

  const rows = useMemo(() => (data ?? []).filter((r) =>
    (origin === 'all' || r.origin === origin) &&
    (!q || `${r.value} ${r.reason} ${r.cn} ${r.as_name}`.toLowerCase().includes(q.toLowerCase()))), [data, q, origin]);

  const [pending, setPending] = useState<string[] | null>(null);
  const unban = (values: string[]) => values.length && setPending(values);
  const doUnban = async () => {
    const r = await api<{ deleted: number }>('/decisions/unban', { method: 'POST', json: { values: pending } });
    toast(`Removed ${r.deleted} decision(s)`);
    setPending(null);
    setSel(new Set());
    reload();
  };
  const toggle = (id: number) => setSel((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const selected = rows.filter((r) => sel.has(r.id));

  return (
    <div className="space-y-7">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-3xl font-semibold text-white sm:text-[34px]">Bans</h1>
          <p className="mt-2 max-w-2xl text-sm text-slate-400">Active decisions from this server and manual bans. The community blocklist is counted on the overview.</p>
          <div className="hairline mt-4 w-40" />
        </div>
        {op && (
          <div className="flex gap-2">
            <Button onClick={() => setBulkOpen(true)}><Upload size={16} /> Bulk ban</Button>
            <Button tone="primary" onClick={() => setBanOpen(true)}><Plus size={16} /> Ban</Button>
          </div>
        )}
      </div>

      <Card title={data ? `${rows.length} active` : 'Loading bans…'} icon={<Ban size={16} />} hover={false}
        actions={
          <div className="flex rounded-xl bg-ink-950/60 p-1 ring-1 ring-white/10">
            {ORIGINS.map((o) => (
              <button key={o.v} onClick={() => setOrigin(o.v)}
                className={cx('rounded-lg px-3 py-1.5 text-xs font-medium whitespace-nowrap transition-all duration-200',
                  origin === o.v ? 'bg-gradient-to-r from-cyan-500/25 to-violet-500/25 text-white shadow-[0_0_16px_-6px_rgba(34,211,238,.8)] ring-1 ring-white/10' : 'text-slate-400 hover:text-slate-100')}>
                {o.label} <span className="ml-1 font-mono text-[10.5px] text-slate-500">{o.v === 'all' ? data?.length ?? 0 : (data ?? []).filter((r) => r.origin === o.v).length}</span>
              </button>
            ))}
          </div>
        }>
        <div className="mb-4 flex items-center gap-2">
          <div className="relative min-w-0 flex-1">
            <Search size={15} className="pointer-events-none absolute top-1/2 left-3.5 -translate-y-1/2 text-slate-500" />
            <input className={cx(inputCls, 'pl-10')} placeholder="Filter by IP, reason, country or network…" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          {op && selected.length > 0 && (
            <div className="slide-in flex h-[42px] shrink-0 items-center gap-1 rounded-xl bg-rose-500/[0.08] pr-1 pl-3 ring-1 ring-rose-400/25">
              <span className="text-xs whitespace-nowrap text-rose-200"><b className="font-mono">{selected.length}</b> selected</span>
              <button onClick={() => setSel(new Set())} title="Clear selection" className="rounded-md p-1.5 text-slate-400 transition hover:bg-white/5 hover:text-white"><X size={14} /></button>
              <Button tone="danger" className="h-8 py-0 whitespace-nowrap" onClick={() => unban(selected.map((r) => r.value))}><Trash2 size={14} /> Unban</Button>
            </div>
          )}
        </div>
        <ErrorBox error={error} />
        <div className="scroll-thin overflow-x-auto">
          <table className="data w-full text-sm">
            <thead className="text-left text-xs tracking-wide text-slate-500 uppercase">
              <tr className="border-b border-white/5">
                {op && <th className="w-10 py-2 pl-1"><Checkbox label="Select all" checked={rows.length > 0 && selected.length === rows.length}
                  indeterminate={selected.length > 0 && selected.length < rows.length}
                  onChange={(v) => setSel(v && selected.length < rows.length ? new Set(rows.map((r) => r.id)) : new Set())} /></th>}
                <th className="py-2 pr-4">Target</th><th className="pr-4">Type</th><th className="pr-4">Reason</th>
                <th className="pr-4">Origin</th><th className="pr-4">Expires in</th><th className="pr-4">Since</th>{op && <th />}
              </tr>
            </thead>
            <tbody>
              {!data && !error && <SkeletonRows rows={10} cols={op ? 8 : 6} />}
              {rows.map((r) => (
                <tr key={r.id} onClick={op ? () => toggle(r.id) : undefined}
                  className={cx('border-b border-white/[0.03]', op && 'cursor-pointer', sel.has(r.id) && '!bg-cyan-400/[0.06]')}>
                  {op && <td className="py-2.5 pl-1"><Checkbox label={`Select ${r.value}`} checked={sel.has(r.id)} onChange={() => toggle(r.id)} /></td>}
                  <td className="py-2.5 pr-4">{r.scope === 'Ip' ? <IpLink ip={r.value} cn={r.cn} /> : <span className="font-mono text-slate-200">{r.scope}: {r.value}</span>}</td>
                  <td className="pr-4"><Badge tone={r.type === 'ban' ? 'rose' : 'amber'}>{r.type}</Badge></td>
                  <td className="max-w-[320px] truncate pr-4 text-slate-300" title={r.reason}>{shortScenario(r.reason)}</td>
                  <td className="pr-4"><Badge tone={r.origin === 'cscli' ? 'violet' : 'cyan'}>{r.origin === 'cscli' ? 'manual' : r.origin}</Badge></td>
                  <td className="pr-4 font-mono text-xs text-slate-400">{r.duration.replace(/\.\d+s$/, 's')}</td>
                  <td className="pr-4 text-slate-500">{ago(r.at)}</td>
                  {op && <td className="text-right" onClick={(e) => e.stopPropagation()}><Button tone="ghost" onClick={() => unban([r.value])}>Unban</Button></td>}
                </tr>
              ))}
            </tbody>
          </table>
          {!loading && data && !rows.length && <Empty>No active bans.</Empty>}
        </div>
      </Card>

      <Confirm open={!!pending} onClose={() => setPending(null)} onConfirm={doUnban} tone="danger"
        title={pending?.length === 1 ? `Unban ${pending[0]}?` : `Unban ${pending?.length} IPs?`} confirmLabel="Unban">
        <p>Their decisions are removed and the bouncers let them through within a few seconds. CrowdSec bans them again if they keep attacking.</p>
        {pending && pending.length > 1 && (
          <div className="scroll-thin mt-3 max-h-40 overflow-y-auto rounded-lg bg-ink-950/60 p-2 font-mono text-xs text-slate-300 ring-1 ring-white/5">
            {pending.map((v) => <div key={v}>{v}</div>)}
          </div>
        )}
      </Confirm>
      <BanModal open={banOpen} onClose={() => setBanOpen(false)} onDone={reload} />
      <BulkModal open={bulkOpen} onClose={() => setBulkOpen(false)} onDone={reload} />
    </div>
  );
}

export function BanModal({ open, onClose, onDone, initial }: { open: boolean; onClose: () => void; onDone: () => void; initial?: string }) {
  const [scope, setScope] = useState('Ip');
  const [value, setValue] = useState(initial ?? '');
  const [duration, setDuration] = useState('24h');
  const [type, setType] = useState('ban');
  const [reason, setReason] = useState('');
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api('/decisions', { method: 'POST', json: { scope, value: value || initial, duration, reason, type } });
      toast(`${type === 'ban' ? 'Banned' : 'Captcha for'} ${value || initial}`);
      onClose(); onDone();
    } catch (err: any) { setError(err.message); }
  };
  return (
    <Modal open={open} onClose={onClose} title="New decision">
      <form onSubmit={submit} className="space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <Field label="Scope">
            <select className={inputCls} value={scope} onChange={(e) => setScope(e.target.value)}>
              <option value="Ip">IP</option><option value="Range">Range (CIDR)</option><option value="Country">Country (ISO)</option><option value="As">AS number</option>
            </select>
          </Field>
          <Field label="Action">
            <select className={inputCls} value={type} onChange={(e) => setType(e.target.value)}>
              <option value="ban">Ban</option><option value="captcha">Captcha</option>
            </select>
          </Field>
        </div>
        <Field label="Value" hint={scope === 'Country' ? 'Two letters, e.g. CN' : scope === 'As' ? 'Number only, e.g. 9009' : scope === 'Range' ? 'e.g. 203.0.113.0/24' : undefined}>
          <input className={inputCls} value={value || initial || ''} onChange={(e) => setValue(e.target.value)} autoFocus />
        </Field>
        <Field label="Duration">
          <div className="flex flex-wrap gap-2">
            {DURATIONS.map((d) => (
              <button type="button" key={d} onClick={() => setDuration(d)}
                className={cx('rounded-lg px-3 py-1.5 text-xs ring-1', duration === d ? 'bg-cyan-500/20 text-cyan-200 ring-cyan-400/40' : 'text-slate-400 ring-white/10 hover:text-white')}>
                {durLabel[d]}
              </button>
            ))}
          </div>
        </Field>
        <Field label="Reason"><input className={inputCls} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. abuse on login page" /></Field>
        <ErrorBox error={error} />
        <div className="flex justify-end gap-2"><Button type="button" tone="ghost" onClick={onClose}>Cancel</Button><Button tone="danger">Apply</Button></div>
      </form>
    </Modal>
  );
}

function BulkModal({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: () => void }) {
  const [text, setText] = useState('');
  const [duration, setDuration] = useState('24h');
  const [busy, setBusy] = useState(false);
  const values = text.split(/[\s,;]+/).map((v) => v.trim()).filter((v) => /^[0-9a-fA-F:.]+(\/\d{1,3})?$/.test(v));
  const run = async () => {
    setBusy(true);
    let ok = 0;
    for (const v of values) {
      try { await api('/decisions', { method: 'POST', json: { scope: v.includes('/') ? 'Range' : 'Ip', value: v, duration, reason: 'bulk ban' } }); ok++; } catch { /* keep going */ }
    }
    setBusy(false);
    toast(`Banned ${ok}/${values.length}`);
    onClose(); onDone();
  };
  return (
    <Modal open={open} onClose={onClose} title="Bulk ban">
      <div className="space-y-4">
        <Field label="IPs or ranges" hint="One per line, or separated by commas/spaces.">
          <textarea className={cx(inputCls, 'h-40 font-mono')} value={text} onChange={(e) => setText(e.target.value)} />
        </Field>
        <Field label="Duration">
          <select className={inputCls} value={duration} onChange={(e) => setDuration(e.target.value)}>
            {DURATIONS.map((d) => <option key={d} value={d}>{durLabel[d]}</option>)}
          </select>
        </Field>
        <div className="flex items-center justify-between">
          <span className="text-xs text-slate-400">{values.length} valid entries</span>
          <Button tone="danger" disabled={!values.length || busy} onClick={run}>Ban {values.length}</Button>
        </div>
      </div>
    </Modal>
  );
}
