import { useState } from 'react';
import { ScrollText } from 'lucide-react';
import { api } from '../api';
import { Badge, Card, ErrorBox, SkeletonRows, cx, inputBase, useAsync } from '../ui';

interface Entry { id: number; ts: number; username: string | null; action: string; target: string | null; detail: string | null }

const tone = (a: string) =>
  a.includes('failed') || a.includes('delete') || a.startsWith('decision.add') ? 'rose'
    : a.startsWith('login') || a.startsWith('setup') ? 'cyan' : a.startsWith('cloudflare') ? 'amber' : 'violet';

export default function Audit() {
  const { data, error } = useAsync(() => api<Entry[]>('/audit?limit=1000'), [], 30_000);
  const [q, setQ] = useState('');
  const rows = (data ?? []).filter((e) => !q || `${e.username} ${e.action} ${e.target} ${e.detail}`.toLowerCase().includes(q.toLowerCase()));
  return (
    <div className="space-y-7">
      <div>
        <h1 className="font-display text-3xl font-semibold text-white sm:text-[34px]">Audit log</h1>
        <p className="mt-2 max-w-2xl text-sm text-slate-400">Every sign-in and every change made through Argos.</p>
          <div className="hairline mt-4 w-40" />
      </div>
      <Card title={data ? `${rows.length} entries` : 'Loading…'} hover={false} icon={<ScrollText size={16} />}
        actions={<input className={cx(inputBase, 'w-64')} placeholder="Filter…" value={q} onChange={(e) => setQ(e.target.value)} />}>
        <ErrorBox error={error} />
        <table className="data w-full text-sm">
          <thead className="text-left text-xs tracking-wide text-slate-500 uppercase">
            <tr className="border-b border-white/5"><th className="py-2 pr-4">When</th><th className="pr-4">Who</th><th className="pr-4">Action</th><th className="pr-4">Target</th><th>Detail</th></tr>
          </thead>
          <tbody>
            {!data && !error && <SkeletonRows rows={12} cols={5} />}
            {rows.map((e) => (
              <tr key={e.id} className="border-b border-white/[0.03]">
                <td className="py-2 pr-4 whitespace-nowrap text-slate-400">{new Date(e.ts).toLocaleString()}</td>
                <td className="pr-4 text-slate-200">{e.username ?? '—'}</td>
                <td className="pr-4"><Badge tone={tone(e.action) as any}>{e.action}</Badge></td>
                <td className="max-w-[220px] truncate pr-4 font-mono text-xs text-slate-300">{e.target}</td>
                <td className="max-w-[420px] truncate font-mono text-xs text-slate-500" title={e.detail ?? ''}>{e.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
