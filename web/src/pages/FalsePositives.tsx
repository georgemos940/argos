import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { CheckCircle2, EyeOff, Loader2, ScanSearch, ShieldOff, ThumbsDown, Unlock } from 'lucide-react';
import { api } from '../api';
import { can, type Role } from '../App';
import { Badge, Button, Card, Empty, ErrorBox, IpLink, PageHeader, SkeletonCard, ago, ask, cx, shortScenario, toast, useAsync } from '../ui';

interface Reason { text: string; weight: number }
interface RuleDraft { name: string; conditions: { field: string; op: string; value: string }[] }
interface Suspect {
  key: string; ip: string; cn?: string; as_name?: string; score: number; reasons: Reason[]; scenarios: string[]; alerts: number; events: number; lastAt: string;
  sites: string[]; requests: { host: string; path: string; status: string }[]; decision?: { id: number; type: string; duration: string }; rule?: RuleDraft;
}
interface Group { key: string; host: string; prefix: string; ips: number; events: number; statuses: Record<string, number> }
interface Result { suspects: Suspect[]; groups: Group[]; scanned: number }

const statusTone = (s: string) => (/^[23]/.test(s) ? 'text-emerald-300' : /^4/.test(s) ? 'text-amber-300' : 'text-rose-300');

export default function FalsePositives({ role }: { role: Role }) {
  const { data, error, reload } = useAsync(() => api<Result>('/false-positives'), []);
  const [busy, setBusy] = useState<string | null>(null);
  const navigate = useNavigate();
  const op = can(role, 'operator');
  const admin = can(role, 'admin');

  const run = async (key: string, fn: () => Promise<unknown>, msg: string) => {
    setBusy(key);
    try { await fn(); toast(msg); reload(); } catch (e: any) { toast(e.message, 'err'); } finally { setBusy(null); }
  };
  const allow = async (s: Suspect) => {
    if (!await ask({
      title: `Allow ${s.ip}?`, confirmLabel: 'Allow and unban',
      body: <>It goes into the <b className="text-slate-200">argos-false-positives</b> allowlist, so CrowdSec never bans it again, and any ban on it is lifted now.</>,
    })) return;
    run(s.key, () => api('/false-positives/allow', { method: 'POST', json: { ip: s.ip, note: `false positive: ${s.scenarios.map(shortScenario).join(', ')}`.slice(0, 100) } }), `${s.ip} allowed and unbanned`);
  };
  const unban = (s: Suspect) => run(s.key, () => api('/decisions/unban', { method: 'POST', json: { values: [s.ip] } }), `${s.ip} unbanned`);
  const dismiss = (key: string, what: string) => run(key, () => api('/false-positives/dismiss', { method: 'POST', json: { key } }), `${what} hidden for 30 days`);
  const toRule = (rule: RuleDraft) => navigate('/ignore-rules', { state: { add: rule } });

  return (
    <div className="space-y-7">
      <PageHeader title="False positives" eyebrow="Monitor"
        subtitle="Bans from the last 7 days that look like a real visitor or your own app rather than an attacker. Each one says why, nothing changes until you act." />
      <ErrorBox error={error} />

      {data && (
        <div className="glass flex flex-wrap items-center gap-x-8 gap-y-2 p-4 text-sm text-slate-400">
          <span><b className="font-mono text-slate-100">{data.scanned}</b> alerts checked</span>
          <span><b className={cx('font-mono', data.suspects.length ? 'text-amber-200' : 'text-emerald-300')}>{data.suspects.length}</b> look like false positives</span>
          <span className="text-xs text-slate-500">Network type, response codes, probe paths, scenario kind and past unbans all count.</span>
        </div>
      )}

      {!!data?.groups.length && (
        <Card title="Your app tripping CrowdSec" icon={<EyeOff size={16} />} subtitle="Several visitors from home networks got errors on the same part of a site. That is usually the app, not an attack.">
          <div className="space-y-3">
            {data.groups.map((g) => (
              <div key={g.key} className="flex flex-wrap items-center gap-3 rounded-xl bg-ink-950/50 px-4 py-3 ring-1 ring-white/[0.05]">
                <div className="min-w-0 flex-1">
                  <div className="font-mono text-sm text-cyan-200">{g.host}<span className="text-slate-100">{g.prefix}</span></div>
                  <div className="text-xs text-slate-500">{g.ips} visitors · {g.events} requests · {Object.entries(g.statuses).map(([s, n]) => `${n}× ${s}`).join(', ')}</div>
                </div>
                {admin && <Button onClick={() => toRule({ name: `App traffic on ${g.prefix}`, conditions: [...(g.host ? [{ field: 'host', op: 'equals', value: g.host }] : []), { field: 'path', op: 'startsWith', value: g.prefix }] })}><EyeOff size={14} /> Ignore rule</Button>}
                {op && <Button tone="ghost" disabled={busy === g.key} onClick={() => dismiss(g.key, `${g.host}${g.prefix}`)}>Hide</Button>}
              </div>
            ))}
          </div>
        </Card>
      )}

      <div className="stagger space-y-4">
        {!data && !error && [0, 1].map((i) => <SkeletonCard key={i} rows={3} />)}
        {data && !data.suspects.length && (
          <div className="glass"><Empty><CheckCircle2 size={22} className="mx-auto mb-2 text-emerald-400" />Nothing in the last 7 days looks like a false positive.</Empty></div>
        )}
        {(data?.suspects ?? []).map((s) => {
          const loading = busy === s.key;
          return (
            <section key={s.key} className="glass relative overflow-hidden p-5">
              <div className={cx('pointer-events-none absolute inset-y-0 left-0 w-1', s.score >= 6 ? 'bg-amber-400/70' : 'bg-amber-400/30')} />
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <IpLink ip={s.ip} cn={s.cn} />
                    <Badge tone={s.score >= 6 ? 'amber' : 'slate'}>{s.score >= 6 ? 'likely' : 'possible'} false positive</Badge>
                    {s.decision ? <Badge tone="rose">{s.decision.type} · {s.decision.duration.replace(/(\d+h)\d+m.*$/, '$1')}</Badge> : <Badge>no active ban</Badge>}
                  </div>
                  <div className="mt-1 text-xs text-slate-500">
                    {s.as_name ?? 'unknown network'} · {s.alerts} alert{s.alerts > 1 ? 's' : ''}, {s.events} events · last {ago(s.lastAt)} · {s.scenarios.map(shortScenario).join(', ')}
                  </div>
                </div>
                {loading && <Loader2 size={18} className="animate-spin text-cyan-300" />}
              </div>

              <div className="mt-4 grid gap-4 lg:grid-cols-2">
                <ul className="space-y-1.5">
                  {s.reasons.map((r) => (
                    <li key={r.text} className="flex items-start gap-2 text-sm">
                      <span className={cx('mt-0.5 w-7 shrink-0 text-right font-mono text-xs', r.weight > 0 ? 'text-emerald-300' : 'text-rose-300')}>{r.weight > 0 ? `+${r.weight}` : r.weight}</span>
                      <span className="text-slate-300">{r.text}</span>
                    </li>
                  ))}
                </ul>
                <div className="scroll-thin max-h-40 overflow-auto rounded-xl bg-ink-950/60 p-3 ring-1 ring-white/[0.05]">
                  {s.requests.map((q, i) => (
                    <div key={i} className="flex gap-3 font-mono text-[11px] leading-5">
                      <span className={cx('w-8 shrink-0', statusTone(q.status))}>{q.status || '—'}</span>
                      <span className="truncate text-slate-400" title={q.host + q.path}><span className="text-slate-600">{q.host}</span>{q.path}</span>
                    </div>
                  ))}
                  {!s.requests.length && <div className="text-xs text-slate-500">No request details on these alerts.</div>}
                </div>
              </div>

              {op && (
                <div className="mt-4 flex flex-wrap gap-2 border-t border-white/[0.05] pt-4">
                  <Button tone="primary" disabled={loading} onClick={() => allow(s)}><ShieldOff size={14} /> Allow and unban</Button>
                  {s.decision && <Button disabled={loading} onClick={() => unban(s)}><Unlock size={14} /> Unban only</Button>}
                  {admin && s.rule && <Button disabled={loading} onClick={() => toRule(s.rule!)} title={s.rule.conditions.map((c) => `${c.field} ${c.op} ${c.value}`).join(' and ')}><EyeOff size={14} /> Ignore these requests</Button>}
                  <Button tone="ghost" className="ml-auto" disabled={loading} onClick={() => dismiss(s.key, s.ip)}><ThumbsDown size={14} /> Not a false positive</Button>
                </div>
              )}
            </section>
          );
        })}
      </div>
      <p className="flex items-center gap-2 text-xs text-slate-600"><ScanSearch size={13} /> Hints, not verdicts. A real attacker on a home network can look like this too, check the requests first.</p>
    </div>
  );
}
