import { useState } from 'react';
import { CheckCircle2, CircleSlash, Cloud, FlaskConical, Link2, Loader2, Play } from 'lucide-react';
import { api } from '../api';
import { can, type Role } from '../App';
import { Badge, Button, Card, ErrorBox, Field, PageHeader, SkeletonList, Switch, ask, cx, inputBase, inputCls, toast, useAsync } from '../ui';

const SAMPLE = JSON.stringify({
  ClientHost: '203.0.113.9', DownstreamContentSize: 152, DownstreamStatus: 404, Duration: 52346331, RequestHost: 'panel.example.com',
  RequestMethod: 'GET', RequestPath: '/wp-login.php', RequestProtocol: 'HTTP/2.0', RouterName: 'panel-api@docker',
  StartUTC: '2026-10-08T02:20:04.398359869Z', level: 'info', msg: '', time: '2026-10-08T02:20:04Z', 'request_User-Agent': 'Mozilla/5.0',
});

function ExplainOutput({ text }: { text: string }) {
  return (
    <pre className="scroll-thin max-h-[480px] overflow-auto rounded-xl bg-ink-950/80 p-4 font-mono text-[12px] leading-relaxed ring-1 ring-white/5">
      {text.split('\n').map((l, i) => {
        const ok = l.includes('🟢');
        const bad = l.includes('🔴');
        const scen = /scenario|bucket|overflow/i.test(l);
        return <div key={i} className={cx(bad ? 'text-slate-600' : ok ? 'text-emerald-300' : scen ? 'text-amber-200' : /^\S/.test(l) ? 'text-cyan-200' : 'text-slate-400')}>{l || ' '}</div>;
      })}
    </pre>
  );
}

function LogTester({ role }: { role: Role }) {
  const [log, setLog] = useState('');
  const [type, setType] = useState('traefik');
  const [out, setOut] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = async () => {
    setBusy(true); setError(null);
    try { setOut((await api<{ output: string }>('/explain', { method: 'POST', json: { log, type } })).output); }
    catch (e: any) { setError(e.message); setOut(null); }
    finally { setBusy(false); }
  };
  const scenarios = out?.split(/\n(?=\S)/).filter((block) => !/^\s*line:/.test(block)).find((block) => /scenario|bucket/i.test(block.split('\n')[0])) ?? '';
  const matched = /🟢/.test(scenarios);
  return (
    <Card title="Log line tester" icon={<FlaskConical size={15} />} hover={false}
      subtitle="Paste one line from a log and see which parser reads it and which scenario it would trigger. Useful when you do not know why an IP got banned.">
      <div className="space-y-4">
        <div className="flex flex-wrap gap-2">
          <select className={cx(inputBase, 'w-36')} value={type} onChange={(e) => setType(e.target.value)}>
            {['traefik', 'nginx', 'apache2', 'syslog', 'auth.log'].map((t) => <option key={t}>{t}</option>)}
          </select>
          <button type="button" onClick={() => { setLog(SAMPLE); setType('traefik'); }} className="rounded-lg px-3 text-xs text-cyan-300 hover:bg-cyan-400/10">use a sample line</button>
        </div>
        <textarea rows={3} className={cx(inputCls, 'resize-y font-mono text-[12.5px]')} value={log} onChange={(e) => setLog(e.target.value.replace(/[\r\n]+/g, ' '))}
          placeholder='{"ClientHost":"203.0.113.9","RequestMethod":"GET","RequestPath":"/.env", …}' />
        <ErrorBox error={error} />
        <div className="flex items-center justify-between gap-3">
          {out && <Badge tone={matched ? 'amber' : 'emerald'}>{matched ? 'would count towards a scenario' : 'parsed, no scenario'}</Badge>}
          <Button tone="primary" className="ml-auto" disabled={!log.trim() || busy || !can(role, 'operator')} onClick={run}>
            {busy ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />} Explain
          </Button>
        </div>
        {busy && <SkeletonList rows={5} />}
        {out && !busy && <ExplainOutput text={out} />}
      </div>
    </Card>
  );
}

const OPTIONS: { k: string; label: string; hint: string }[] = [
  { k: 'custom', label: 'Custom alerts', hint: 'Share alerts from your own scenarios' },
  { k: 'manual', label: 'Manual decisions', hint: 'Share bans added by hand' },
  { k: 'tainted', label: 'Tainted alerts', hint: 'Share alerts from modified hub scenarios' },
  { k: 'context', label: 'Alert context', hint: 'Send the context (paths, user agents) with alerts' },
  { k: 'console_management', label: 'Console management', hint: 'Let the Console push decisions and blocklist subscriptions here' },
];

function ConsoleCard({ role }: { role: Role }) {
  const { data, error, reload } = useAsync(() => api<Record<string, boolean> & { error?: string }>('/console'), []);
  const [key, setKey] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const admin = can(role, 'admin');

  const enroll = async () => {
    if (!await ask({ title: 'Enroll in the CrowdSec Console?', confirmLabel: 'Enroll',
      body: 'CrowdSec restarts after enrolling (10–30 s). Then accept the instance at app.crowdsec.net → Security Engines.' })) return;
    setBusy('enroll');
    try { await api('/console/enroll', { method: 'POST', json: { key } }); toast('Enrolled. Accept it in the Console.'); setKey(''); reload(); }
    catch (e: any) { toast(e.message, 'err'); }
    finally { setBusy(null); }
  };
  const option = async (name: string, enabled: boolean) => {
    setBusy(name);
    try { await api('/console/option', { method: 'POST', json: { name, enabled } }); toast(`${name} ${enabled ? 'on' : 'off'}, CrowdSec restarted`); reload(); }
    catch (e: any) { toast(e.message, 'err'); }
    finally { setBusy(null); }
  };

  return (
    <Card title="CrowdSec Console" icon={<Cloud size={15} />} hover={false}
      subtitle="app.crowdsec.net: one view of all your engines, the official blocklists and CTI keys."
      actions={<a href="https://app.crowdsec.net/" target="_blank" rel="noreferrer" className="flex items-center gap-1 text-xs text-cyan-300 hover:underline"><Link2 size={12} /> Open the Console</a>}>
      <div className="space-y-6">
        <div>
          <Field label="Enrollment key" hint="Console → Security Engines → Enroll → copy the key from the command it shows.">
            <div className="flex gap-2">
              <input className={cx(inputCls, 'font-mono text-xs')} value={key} onChange={(e) => setKey(e.target.value.trim())} placeholder="cl1a2b3c4d…" disabled={!admin} />
              <Button tone="primary" disabled={!admin || key.length < 10 || busy === 'enroll'} onClick={enroll}>
                {busy === 'enroll' && <Loader2 size={14} className="animate-spin" />} Enroll
              </Button>
            </div>
          </Field>
        </div>
        <div>
          <div className="mb-2 text-xs font-medium text-slate-400">What this engine shares with the Console</div>
          <ErrorBox error={error ?? data?.error ?? null} />
          {!data && !error && <SkeletonList rows={5} />}
          {data && !data.error && (
            <ul className="divide-y divide-white/[0.05]">
              {OPTIONS.map((o) => (
                <li key={o.k} className="flex items-center justify-between gap-4 py-3">
                  <div className="flex items-start gap-3">
                    {data[o.k] ? <CheckCircle2 size={16} className="mt-0.5 text-emerald-400" /> : <CircleSlash size={16} className="mt-0.5 text-slate-600" />}
                    <div><div className="text-sm text-slate-100">{o.label}</div><div className="text-xs text-slate-500">{o.hint}</div></div>
                  </div>
                  {busy === o.k ? <Loader2 size={18} className="animate-spin text-cyan-300" />
                    : <Switch checked={!!data[o.k]} onChange={(v) => admin && option(o.k, v)} label={o.label} />}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </Card>
  );
}

export default function Tools({ role }: { role: Role }) {
  return (
    <div className="space-y-7">
      <PageHeader title="Tools" eyebrow="System" subtitle="Debug detections and connect this engine to the CrowdSec Console." />
      <div className="grid items-start gap-6 2xl:grid-cols-2">
        <LogTester role={role} />
        <ConsoleCard role={role} />
      </div>
    </div>
  );
}

