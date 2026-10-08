import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Activity, ShieldBan, ShieldCheck, ShieldOff, Zap } from 'lucide-react';
import { api, type SlimAlert } from '../api';
import { AlertDetail } from './AlertDetail';
import { Badge, Card, Empty, IpLink, PageHeader, SkeletonList, SkeletonRows, Stat, ago, cx, shortScenario, useAsync } from '../ui';

interface Waf {
  metrics: { 'appsec-engine'?: Record<string, { processed?: number; blocked?: number }>; 'appsec-rule'?: Record<string, Record<string, { triggered?: number }>> };
  alerts: SlimAlert[];
}

export default function WafPage() {
  const { data, error } = useAsync(() => api<Waf>('/waf'), [], 30_000);
  const [open, setOpen] = useState<number | null>(null);

  const engines = Object.entries(data?.metrics['appsec-engine'] ?? {});
  const processed = engines.reduce((n, [, e]) => n + (e.processed ?? 0), 0);
  const blocked = engines.reduce((n, [, e]) => n + (e.blocked ?? 0), 0);
  const active = engines.length > 0;
  const rules = useMemo(() => {
    const m = new Map<string, number>();
    for (const perEngine of Object.values(data?.metrics['appsec-rule'] ?? {}))
      for (const [rule, v] of Object.entries(perEngine)) m.set(rule, (m.get(rule) ?? 0) + (v.triggered ?? 0));
    return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 12);
  }, [data]);

  return (
    <div className="space-y-7">
      <PageHeader title={<>Web <span className="text-gradient">firewall</span></>} eyebrow="AppSec"
        subtitle="CrowdSec inspects every request before it reaches the app and blocks known exploits (virtual patching for public CVEs)." />

      {data && !active && (
        <div className="glass flex flex-wrap items-center gap-4 p-5 ring-1 ring-amber-400/25">
          <span className="grid h-11 w-11 place-items-center rounded-xl bg-amber-400/15 text-amber-300 ring-1 ring-amber-400/30"><ShieldOff size={20} /></span>
          <div className="min-w-0 flex-1">
            <div className="font-display text-lg text-white">The firewall is not receiving requests</div>
            <div className="text-sm text-slate-400">Install the AppSec collections from the hub and turn on AppSec in the Traefik bouncer. Until then only log-based detection runs.</div>
          </div>
          <Link to="/infra" className="text-sm text-cyan-300 hover:underline">Hub →</Link>
        </div>
      )}

      <div className="stagger grid grid-cols-2 gap-4 xl:grid-cols-4">
        <Stat label="Status" value={!data ? '…' : active ? <Badge tone="emerald"><ShieldCheck size={12} /> active</Badge> : <Badge tone="amber">off</Badge>}
          hint={active ? `${engines.length} engine${engines.length > 1 ? 's' : ''}` : 'no AppSec engine'} accent="emerald" icon={<ShieldCheck size={16} />} />
        <Stat label="Requests inspected" value={processed} hint="since CrowdSec started" accent="cyan" icon={<Activity size={16} />} />
        <Stat label="Blocked" value={blocked} hint={processed ? `${((blocked / processed) * 100).toFixed(2)}% of requests` : 'in-band rules'} accent="rose" icon={<ShieldBan size={16} />} />
        <Stat label="WAF alerts (7d)" value={data?.alerts.length ?? 0} hint="attackers caught by rules" accent="violet" icon={<Zap size={16} />} />
      </div>

      <div className="grid gap-6 xl:grid-cols-3">
        <Card title="Blocked attacks" className="xl:col-span-2" hover={false} subtitle="Last 7 days. Click one for every request.">
          <div className="scroll-thin overflow-x-auto">
            <table className="data w-full text-sm">
              <thead className="text-left"><tr><th className="pr-4">When</th><th className="pr-4">Source</th><th className="pr-4">Rule</th><th className="pr-4">Site</th><th>Decision</th></tr></thead>
              <tbody>
                {!data && !error && <SkeletonRows rows={6} cols={5} />}
                {(data?.alerts ?? []).map((a) => (
                  <tr key={a.id} onClick={() => setOpen(a.id)} className="cursor-pointer">
                    <td className="py-2.5 pr-4 whitespace-nowrap text-slate-400">{ago(a.start_at)}</td>
                    <td className="pr-4" onClick={(e) => e.stopPropagation()}><IpLink ip={a.source.value} cn={a.source.cn} /></td>
                    <td className="pr-4 text-slate-200">{shortScenario(a.scenario)}</td>
                    <td className="pr-4">{a.target ? <Badge tone="violet">{a.target}</Badge> : <span className="text-slate-600">—</span>}</td>
                    <td>{a.decisions.length ? <Badge tone="rose">ban {a.decisions[0].duration}</Badge> : <Badge>none</Badge>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {data && !data.alerts.length && <Empty>{active ? 'Nothing blocked in the last 7 days.' : 'No WAF alerts yet.'}</Empty>}
          </div>
        </Card>
        <Card title="Rules that fired" hover={false} subtitle="Since CrowdSec started">
          {!data && <SkeletonList rows={6} />}
          {rules.map(([r, n]) => {
            const max = rules[0][1] || 1;
            return (
              <div key={r} className="mb-3">
                <div className="flex justify-between gap-3 text-xs"><span className="truncate font-mono text-slate-300">{r}</span><span className="font-mono text-slate-500">{n}</span></div>
                <div className="mt-1 h-1.5 rounded-full bg-white/5"><div className={cx('h-full rounded-full bg-gradient-to-r from-rose-500 to-violet-500')} style={{ width: `${(n / max) * 100}%`, transition: 'width 1s' }} /></div>
              </div>
            );
          })}
          {data && !rules.length && <div className="text-sm text-slate-500">No rule has fired yet.</div>}
        </Card>
      </div>
      <AlertDetail id={open} onClose={() => setOpen(null)} />
    </div>
  );
}
