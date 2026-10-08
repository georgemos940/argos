import { useEffect, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { EyeOff, Loader2, Plus, Save, Trash2, X } from 'lucide-react';
import { api } from '../api';
import { can, type Role } from '../App';
import { Badge, Button, Empty, ErrorBox, PageHeader, SkeletonCard, Switch, ask, cx, inputBase, toast, useAsync } from '../ui';

type FieldKey = 'path' | 'host' | 'user_agent' | 'method' | 'status';
type Op = 'equals' | 'startsWith' | 'endsWith' | 'contains' | 'regex';
interface Condition { field: FieldKey; op: Op; value: string }
interface Rule { id: string; name: string; enabled: boolean; conditions: Condition[] }
interface State { rules: Rule[]; live: string | null; inSync: boolean }

const FIELDS: Record<FieldKey, [string, string]> = {
  path: ['Path', 'evt.Meta.http_path'], host: ['Host', 'evt.Meta.target_fqdn'], user_agent: ['User agent', 'evt.Meta.http_user_agent'],
  method: ['Method', 'evt.Meta.http_verb'], status: ['Status', 'evt.Meta.http_status'],
};
const OPS: Record<Op, [string, string]> = {
  equals: ['is', '=='], startsWith: ['starts with', 'startsWith'], endsWith: ['ends with', 'endsWith'], contains: ['contains', 'contains'], regex: ['matches regex', 'matches'],
};
const PLACEHOLDER: Record<FieldKey, string> = { path: '/healthz', host: 'app.example.com', user_agent: 'UptimeRobot', method: 'OPTIONS', status: '404' };

const newId = () => Math.random().toString(16).slice(2, 14);
const TEMPLATES: { label: string; rule: Omit<Rule, 'id'> }[] = [
  { label: 'Health checks', rule: { name: 'Health checks', enabled: true, conditions: [{ field: 'path', op: 'equals', value: '/healthz' }] } },
  { label: 'App API on a host', rule: { name: 'App API', enabled: true, conditions: [{ field: 'host', op: 'equals', value: 'app.example.com' }, { field: 'path', op: 'startsWith', value: '/api/' }] } },
  { label: 'Static assets', rule: { name: 'Static assets', enabled: true, conditions: [{ field: 'path', op: 'regex', value: '\\.(css|js|png|jpe?g|svg|woff2?|ico)$' }] } },
  { label: 'Uptime monitor', rule: { name: 'Uptime monitor', enabled: true, conditions: [{ field: 'user_agent', op: 'contains', value: 'UptimeRobot' }] } },
];

const expr = (r: Rule) => r.conditions.map((c) => `${FIELDS[c.field][1]} ${OPS[c.op][1]} ${JSON.stringify(c.value)}`).join(' && ');

export default function IgnoreRules({ role }: { role: Role }) {
  const { data, error, reload } = useAsync(() => api<State>('/ignore-rules'), []);
  const admin = can(role, 'admin');
  const [rules, setRules] = useState<Rule[] | null>(null);
  const [busy, setBusy] = useState(false);
  // a rule drafted on the false positives page arrives as router state and stays on top of whatever loads until applied
  const location = useLocation();
  const navigate = useNavigate();
  const [draft] = useState(() => {
    const d = (location.state as { add?: Omit<Rule, 'id' | 'enabled'> } | null)?.add;
    return d ? { ...(d as Rule), id: newId(), enabled: true } : null;
  });
  const added = useRef<Rule | null>(draft);
  useEffect(() => {
    if (!draft) return;
    navigate('.', { replace: true, state: null });
    toast('Rule added at the bottom, check it and Apply');
  }, [draft, navigate]);
  useEffect(() => {
    if (!data) return;
    const a = added.current;
    setRules(a && !data.rules.some((r) => r.id === a.id) ? [...data.rules, a] : data.rules);
  }, [data]);

  const dirty = !!data && !!rules && JSON.stringify(rules) !== JSON.stringify(data.rules);
  const edit = (id: string, patch: Partial<Rule>) => setRules((rs) => rs!.map((r) => (r.id === id ? { ...r, ...patch } : r)));
  const editCond = (r: Rule, i: number, patch: Partial<Condition>) => edit(r.id, { conditions: r.conditions.map((c, j) => (j === i ? { ...c, ...patch } : c)) });
  const add = (rule: Omit<Rule, 'id'>) => setRules((rs) => [...(rs ?? []), { ...structuredClone(rule), id: newId() }]);

  const save = async () => {
    if (!await ask({
      title: 'Apply the ignore rules?', confirmLabel: 'Check and apply',
      body: <>Argos writes them as a whitelist parser, CrowdSec checks it and restarts (about 15 seconds). If it refuses the file or does not come back up, the old one is put back.</>,
    })) return;
    setBusy(true);
    try {
      const r = await api<{ changed: boolean; seconds: number }>('/ignore-rules', { method: 'PUT', json: { rules } });
      toast(r.changed ? `Ignore rules live, CrowdSec back in ${r.seconds}s` : 'Saved, nothing changed in CrowdSec');
      added.current = null;
      reload();
    } catch (e: any) { toast(e.message, 'err'); }
    finally { setBusy(false); }
  };

  return (
    <div className="space-y-7">
      <PageHeader title="Ignore rules" eyebrow="Respond"
        subtitle="Requests that should never count toward a ban: health checks, your app's own API calls, a monitor. They are dropped before any scenario sees them."
        actions={admin && rules && (
          <div className="flex gap-2">
            {dirty && <Button tone="ghost" disabled={busy} onClick={() => { added.current = null; setRules(data!.rules); }}>Discard</Button>}
            <Button tone="primary" disabled={busy || (!dirty && !!data?.inSync)} onClick={save}>
              {busy ? <Loader2 size={15} className="animate-spin" /> : <Save size={15} />} {busy ? 'Checking and restarting…' : 'Apply'}
            </Button>
          </div>
        )} />
      <ErrorBox error={error} />

      <div className="glass flex flex-wrap items-center gap-x-6 gap-y-2 p-4 text-sm text-slate-400">
        <span>Allowlists skip an <b className="text-slate-200">IP</b>, ignore rules skip a <b className="text-slate-200">request</b>. Web firewall (AppSec) blocks are not affected.</span>
        {data && <span className="ml-auto flex gap-2">
          {dirty ? <Badge tone="amber">unsaved changes</Badge> : data.inSync ? <Badge tone="emerald">live in CrowdSec</Badge> : <Badge tone="amber">not applied yet</Badge>}
        </span>}
      </div>

      {admin && (
        <div className="flex flex-wrap items-center gap-2">
          <Button onClick={() => add({ name: '', enabled: true, conditions: [{ field: 'path', op: 'startsWith', value: '' }] })}><Plus size={15} /> New rule</Button>
          <span className="ml-2 text-xs text-slate-500">or start from</span>
          {TEMPLATES.map((t) => (
            <button key={t.label} onClick={() => add(t.rule)} className="rounded-lg px-2.5 py-1 text-xs text-slate-400 ring-1 ring-white/10 transition hover:bg-cyan-400/10 hover:text-cyan-100 hover:ring-cyan-400/30">{t.label}</button>
          ))}
        </div>
      )}

      <div className="stagger space-y-4">
        {!rules && !error && [0, 1].map((i) => <SkeletonCard key={i} rows={2} />)}
        {rules && !rules.length && <div className="glass"><Empty>No ignore rules. Every request counts.</Empty></div>}
        {(rules ?? []).map((r) => (
          <section key={r.id} className={cx('glass relative overflow-hidden p-5 transition-all', r.enabled ? 'ring-1 ring-cyan-400/20' : 'opacity-70')}>
            <div className="flex flex-wrap items-center gap-3">
              <span className="grid h-9 w-9 place-items-center rounded-xl bg-gradient-to-br from-cyan-400/20 to-violet-500/20 text-cyan-200 ring-1 ring-white/10"><EyeOff size={16} /></span>
              <input disabled={!admin} className={cx(inputBase, 'min-w-0 flex-1 bg-transparent font-medium ring-transparent')} value={r.name} placeholder="Rule name"
                onChange={(e) => edit(r.id, { name: e.target.value })} />
              <Switch checked={r.enabled} onChange={(v) => admin && edit(r.id, { enabled: v })} label={r.name} />
              {admin && <Button tone="ghost" onClick={() => setRules((rs) => rs!.filter((x) => x.id !== r.id))}><Trash2 size={14} /></Button>}
            </div>

            <div className="mt-4 space-y-2">
              {r.conditions.map((c, i) => (
                <div key={i} className="flex flex-wrap items-center gap-2">
                  <span className="w-10 text-right font-mono text-[11px] text-slate-500">{i ? 'and' : 'if'}</span>
                  <select disabled={!admin} className={cx(inputBase, 'h-9 py-0 text-xs')} value={c.field} onChange={(e) => editCond(r, i, { field: e.target.value as FieldKey })}>
                    {Object.entries(FIELDS).map(([k, [l]]) => <option key={k} value={k}>{l}</option>)}
                  </select>
                  <select disabled={!admin} className={cx(inputBase, 'h-9 py-0 text-xs')} value={c.op} onChange={(e) => editCond(r, i, { op: e.target.value as Op })}>
                    {Object.entries(OPS).map(([k, [l]]) => <option key={k} value={k}>{l}</option>)}
                  </select>
                  <input disabled={!admin} className={cx(inputBase, 'h-9 min-w-[180px] flex-1 py-0 font-mono text-xs')} value={c.value} placeholder={PLACEHOLDER[c.field]}
                    onChange={(e) => editCond(r, i, { value: e.target.value })} />
                  {admin && r.conditions.length > 1 && (
                    <button onClick={() => edit(r.id, { conditions: r.conditions.filter((_, j) => j !== i) })} className="rounded-lg p-1.5 text-slate-500 transition hover:bg-white/5 hover:text-white"><X size={14} /></button>
                  )}
                </div>
              ))}
              {admin && r.conditions.length < 8 && (
                <button onClick={() => edit(r.id, { conditions: [...r.conditions, { field: 'path', op: 'startsWith', value: '' }] })}
                  className="ml-12 text-xs text-cyan-300/80 transition hover:text-cyan-200">+ and</button>
              )}
            </div>
            <code className="mt-4 block truncate rounded-lg bg-ink-950/60 px-3 py-2 font-mono text-[11px] text-slate-500 ring-1 ring-white/[0.05]" title={expr(r)}>{expr(r)}</code>
          </section>
        ))}
      </div>
    </div>
  );
}
