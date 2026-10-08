import { useState } from 'react';
import { Activity, Search } from 'lucide-react';
import { api, type SlimAlert } from '../api';
import { AlertDetail } from './AlertDetail';
import { Badge, Card, Empty, ErrorBox, IpLink, SkeletonRows, ago, cx, inputBase, shortScenario, useAsync } from '../ui';

export default function Alerts() {
  const [since, setSince] = useState('24h');
  const [q, setQ] = useState('');
  const [open, setOpen] = useState<number | null>(null);
  const { data, error, loading } = useAsync(() => api<SlimAlert[]>(`/alerts?since=${since}&limit=2000`), [since], 30_000);

  const rows = (data ?? []).filter((a) =>
    !q || `${a.scenario} ${a.source.value} ${a.source.cn} ${a.source.as_name} ${a.target}`.toLowerCase().includes(q.toLowerCase()));

  return (
    <div className="space-y-7">
      <div>
        <h1 className="font-display text-3xl font-semibold text-white sm:text-[34px]">Alerts</h1>
        <p className="mt-2 max-w-2xl text-sm text-slate-400">Every attack CrowdSec detected on this server. Click one to see each request.</p>
          <div className="hairline mt-4 w-40" />
      </div>
      <Card title={data ? `${rows.length} alerts` : 'Loading alerts…'} hover={false} icon={<Activity size={16} />}
        actions={
          <div className="flex gap-2">
            <div className="relative">
              <Search size={14} className="pointer-events-none absolute top-1/2 left-3 -translate-y-1/2 text-slate-500" />
              <input className={cx(inputBase, 'w-64 pl-8')} placeholder="Filter: IP, scenario, country, site…" value={q} onChange={(e) => setQ(e.target.value)} />
            </div>
            <select className={cx(inputBase, 'w-28')} value={since} onChange={(e) => setSince(e.target.value)}>
              <option value="1h">1 hour</option><option value="24h">24 hours</option><option value="168h">7 days</option><option value="720h">30 days</option>
            </select>
          </div>
        }>
        <ErrorBox error={error} />
        <div className="scroll-thin overflow-x-auto">
          <table className="data w-full text-sm">
            <thead className="text-left text-xs tracking-wide text-slate-500 uppercase">
              <tr className="border-b border-white/5">
                <th className="py-2 pr-4">When</th><th className="pr-4">Source</th><th className="pr-4">Network</th>
                <th className="pr-4">Scenario</th><th className="pr-4">Site</th><th className="pr-4 text-right">Events</th><th>Decision</th>
              </tr>
            </thead>
            <tbody>
              {!data && !error && <SkeletonRows rows={10} cols={7} />}
              {rows.map((a) => (
                <tr key={a.id} onClick={() => setOpen(a.id)} className="cursor-pointer border-b border-white/[0.03] transition hover:bg-white/[0.03]">
                  <td className="py-2.5 pr-4 whitespace-nowrap text-slate-400" title={new Date(a.start_at).toLocaleString()}>{ago(a.start_at)}</td>
                  <td className="pr-4" onClick={(e) => e.stopPropagation()}><IpLink ip={a.source.value} cn={a.source.cn} /></td>
                  <td className="max-w-[220px] truncate pr-4 text-slate-400">{a.source.as_name ?? '—'}</td>
                  <td className="pr-4 text-slate-200">{shortScenario(a.scenario)}</td>
                  <td className="pr-4">{a.target ? <Badge tone="violet">{a.target}</Badge> : <span className="text-slate-600">—</span>}</td>
                  <td className="pr-4 text-right font-mono text-slate-300">{a.events_count}</td>
                  <td>{a.decisions.length ? <Badge tone="rose">{a.decisions[0].type} {a.decisions[0].duration}</Badge> : <Badge>none</Badge>}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!loading && data && !rows.length && <Empty>No alerts in this window.</Empty>}
        </div>
      </Card>
      <AlertDetail id={open} onClose={() => setOpen(null)} />
    </div>
  );
}
