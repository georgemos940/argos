import { Gauge } from 'lucide-react';
import { api } from '../api';
import { Card, Empty, SkeletonList, useAsync } from '../ui';

interface Origin { origin: string; label: string; bytes: number; packets: number; active: number }
interface Bouncer { name: string; processed: { bytes: number; packets: number }; origins: Origin[]; dropped: number }

const bytes = (n: number) => {
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n < 10 && i ? n.toFixed(1) : Math.round(n)} ${u[i]}`;
};
const short = (n: number) => (n >= 1e9 ? `${(n / 1e9).toFixed(1)}B` : n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e4 ? `${(n / 1e3).toFixed(1)}k` : n.toLocaleString());

// what each bouncer actually dropped, per decision source
export default function BouncerUsage({ className }: { className?: string }) {
  const { data, error } = useAsync(() => api<{ bouncers: Bouncer[]; error?: string }>('/bouncer-metrics'), [], 60_000);
  const list = data?.bouncers ?? [];
  return (
    <Card title="What the bouncers dropped" icon={<Gauge size={16} />} className={className}
      subtitle="Per decision source, from the usage reports bouncers send to CrowdSec. Bouncers that do not report (the Traefik plugin, for now) are not listed.">
      {!data && !error && <SkeletonList rows={4} />}
      {(error || data?.error) && <div className="text-sm text-rose-300">{error || data?.error}</div>}
      {data && !data.error && !list.length && <Empty>No bouncer has sent usage metrics yet.</Empty>}
      <div className="space-y-6">
        {list.map((b) => {
          const top = Math.max(1, ...b.origins.map((o) => o.packets));
          return (
            <div key={b.name}>
              <div className="mb-3 flex flex-wrap items-baseline justify-between gap-2">
                <div className="font-medium text-white">{b.name}</div>
                <div className="text-xs text-slate-500">
                  <b className="font-mono text-slate-200">{short(b.dropped)}</b> packets dropped
                  {b.processed.packets > 0 && <> of <span className="font-mono">{short(b.processed.packets)}</span> seen ({bytes(b.processed.bytes)})</>}
                </div>
              </div>
              <div className="space-y-2.5">
                {b.origins.map((o) => (
                  <div key={o.origin} className="grid grid-cols-[minmax(0,9rem)_1fr_auto] items-center gap-3 text-sm sm:grid-cols-[minmax(0,12rem)_1fr_auto]">
                    <div className="truncate text-slate-300" title={o.origin}>{o.label}</div>
                    <div className="h-2 overflow-hidden rounded-full bg-white/[0.05]">
                      <div className="h-full rounded-full bg-gradient-to-r from-rose-500 to-violet-500 transition-all duration-700" style={{ width: `${Math.max(2, (o.packets / top) * 100)}%` }} />
                    </div>
                    <div className="w-40 text-right font-mono text-xs text-slate-400">
                      <span className="text-slate-100">{short(o.packets)}</span> · {bytes(o.bytes)}
                      {o.active > 0 && <span className="block text-[10.5px] text-slate-500">{o.active.toLocaleString()} active</span>}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </Card>
  );
}
