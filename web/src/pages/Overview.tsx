import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Activity, Ban, CloudLightning, Crosshair, Globe, Radio, ShieldAlert, Users } from 'lucide-react';
import { api, type SlimAlert } from '../api';
import WorldMap, { type MapPoint } from '../WorldMap';
import { Badge, Card, ErrorBox, IpLink, PageHeader, Skeleton, SkeletonList, Stat, ago, countryName, cx, flag, shortScenario, useAsync } from '../ui';

type Window = '24h' | '7d' | '30d';
interface Overview {
  totals: { alerts: number; uniqueIps: number };
  timeline: { t: number; alerts: number; bans: number }[];
  countries: { key: string; count: number }[];
  asns: { key: string; count: number }[];
  scenarios: { key: string; count: number }[];
  sites: { key: string; count: number }[];
  paths: { key: string; count: number }[];
  points: MapPoint[];
  active: Record<string, number>;
  lapiUp: boolean;
  latest: SlimAlert[];
}

function TopList({ items, render, total }: { items: { key: string; count: number }[]; render?: (k: string) => React.ReactNode; total?: number }) {
  const max = Math.max(1, ...items.map((i) => i.count));
  if (!items.length) return <div className="py-6 text-center text-sm text-slate-500">Nothing yet</div>;
  return (
    <ul className="stagger space-y-1.5">
      {items.map((i, n) => (
        <li key={i.key} className="group relative overflow-hidden rounded-xl px-3 py-2 transition hover:bg-white/[0.03]">
          <div className="absolute inset-y-1 left-0 rounded-lg bg-gradient-to-r from-cyan-400/25 via-sky-500/15 to-violet-500/10 transition-[width] duration-1000 ease-out group-hover:from-cyan-400/35"
            style={{ width: `${(i.count / max) * 100}%` }} />
          <div className="relative flex items-center justify-between gap-3 text-sm">
            <span className="flex min-w-0 items-center gap-2.5">
              <span className="w-4 shrink-0 text-right font-mono text-[10px] text-slate-600">{n + 1}</span>
              <span className="truncate text-slate-200">{render ? render(i.key) : i.key}</span>
            </span>
            <span className="shrink-0 font-mono text-xs text-slate-400 tabular">{i.count}{total ? <span className="text-slate-600"> · {Math.round((i.count / total) * 100)}%</span> : ''}</span>
          </div>
        </li>
      ))}
    </ul>
  );
}

export default function Overview({ home }: { home?: [number, number] }) {
  const [window, setWindow] = useState<Window>('24h');
  const { data, error } = useAsync(() => api<Overview>(`/overview?window=${window}`), [window], 20_000);
  const [live, setLive] = useState<SlimAlert[]>([]);
  const [hot, setHot] = useState<{ lat: number; lon: number }[]>([]);

  useEffect(() => {
    const es = new EventSource('/api/stream');
    es.addEventListener('alert', (e) => {
      const a = JSON.parse((e as MessageEvent).data) as SlimAlert;
      setLive((x) => [a, ...x].slice(0, 40));
      if (a.source.latitude !== undefined && a.source.longitude !== undefined) {
        const h = { lat: a.source.latitude, lon: a.source.longitude };
        setHot((x) => [...x, h]);
        setTimeout(() => setHot((x) => x.filter((y) => y !== h)), 15_000);
      }
    });
    return () => es.close();
  }, []);

  const feed = [...live, ...(data?.latest ?? [])].filter((a, i, arr) => arr.findIndex((b) => b.id === a.id) === i).slice(0, 25);
  const local = data?.active.crowdsec ?? 0;
  const manual = data?.active.cscli ?? 0;
  const community = (data?.active.CAPI ?? 0) + (data?.active.lists ?? 0);
  const fmtTick = (t: number) => new Date(t).toLocaleString([], window === '24h' ? { hour: '2-digit', minute: '2-digit' } : { day: '2-digit', month: 'short' });

  const sparkAlerts = (data?.timeline ?? []).map((b) => b.alerts);
  const sparkBans = (data?.timeline ?? []).map((b) => b.bans);

  return (
    <div className="space-y-7">
      <PageHeader
        eyebrow={<span className="flex items-center gap-2">
          <span className={cx('h-1.5 w-1.5 rounded-full', data?.lapiUp ? 'bg-emerald-400 shadow-[0_0_10px_2px] shadow-emerald-400/70' : 'bg-rose-500')} />
          {data ? (data.lapiUp ? 'CrowdSec engine online' : 'LAPI unreachable') : 'connecting…'}
        </span>}
        title={<>Threat <span className="text-gradient">overview</span></>}
        subtitle="Who is attacking, from where, what they try and what we do about it. Updates live."
        actions={
          <div className="relative flex rounded-2xl bg-white/[0.04] p-1 ring-1 ring-white/10">
            {(['24h', '7d', '30d'] as Window[]).map((w) => (
              <button key={w} onClick={() => setWindow(w)}
                className={cx('relative rounded-xl px-5 py-2 text-sm font-semibold transition-all duration-300', window === w ? 'bg-gradient-to-r from-cyan-500/30 to-violet-500/30 text-white shadow-[0_0_24px_-6px_rgba(34,211,238,.6)] ring-1 ring-white/15' : 'text-slate-400 hover:text-white')}>
                {w}
              </button>
            ))}
          </div>
        }
      />
      <ErrorBox error={error} />

      {!data ? (
        <div className="grid grid-cols-2 gap-4 xl:grid-cols-5">{Array.from({ length: 5 }, (_, i) => <Skeleton key={i} className="h-36 rounded-[1.25rem]" />)}</div>
      ) : (
        <div className="stagger grid grid-cols-2 gap-4 xl:grid-cols-5">
          <Stat label="Attacks" value={data.totals.alerts} hint={`last ${window}`} icon={<ShieldAlert size={16} />} accent="rose" spark={sparkAlerts} />
          <Stat label="Attacking IPs" value={data.totals.uniqueIps} hint="unique sources" icon={<Users size={16} />} accent="amber" />
          <Stat label="Our bans" value={local} hint="decided by this server" icon={<Ban size={16} />} accent="cyan" spark={sparkBans} />
          <Stat label="Manual bans" value={manual} hint="added by people" icon={<Crosshair size={16} />} accent="violet" />
          <Stat label="Community blocklist" value={community} hint="CAPI + blocklists" icon={<Globe size={16} />} accent="emerald" />
        </div>
      )}

      <div className="grid gap-6 2xl:grid-cols-3">
        <Card title="Where attacks come from" icon={<Globe size={15} />} className="2xl:col-span-2" hover={false}
          subtitle="Each line runs from an attacker to our server. New attacks pulse on the map.">
          <WorldMap points={data?.points ?? []} hot={hot} home={home} />
        </Card>
        <Card title="Live feed" icon={<Radio size={15} className="glow-pulse text-rose-300" />} className="flex flex-col" hover={false} subtitle="Newest first">
          <ul className="scroll-thin -mx-2 max-h-[440px] flex-1 space-y-1 overflow-y-auto px-2">
            {feed.map((a) => (
              <li key={a.id} className={cx('slide-in rounded-xl px-3 py-2.5 transition hover:bg-white/[0.03]', live.some((l) => l.id === a.id) && 'ring-1 ring-rose-500/30')}>
                <div className="flex items-center justify-between gap-2">
                  <IpLink ip={a.source.value} cn={a.source.cn} />
                  <span className="shrink-0 text-xs text-slate-500">{ago(a.stop_at)}</span>
                </div>
                <div className="mt-1 flex items-center gap-2 text-xs">
                  <span className="truncate text-slate-400">{shortScenario(a.scenario)}</span>
                  {a.target && <Badge tone="violet">{a.target}</Badge>}
                  {a.decisions.length > 0 && <Badge tone="rose">ban {a.decisions[0].duration}</Badge>}
                </div>
              </li>
            ))}
            {!data && !feed.length && <li><SkeletonList rows={7} /></li>}{data && !feed.length && <li className="py-10 text-center text-sm text-slate-500">Waiting for attacks…</li>}
          </ul>
          <Link to="/alerts" className="mt-3 text-center text-xs text-cyan-300 hover:underline">All alerts →</Link>
        </Card>
      </div>

      <Card title="Attacks over time" icon={<Activity size={16} />}>
        <div className="h-64">
          {!data ? <Skeleton className="h-full w-full rounded-xl" /> : <ResponsiveContainer>
            <AreaChart data={data?.timeline ?? []} margin={{ left: -20, right: 8 }}>
              <defs>
                <linearGradient id="ga" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#22d3ee" stopOpacity={0.5} /><stop offset="1" stopColor="#22d3ee" stopOpacity={0} /></linearGradient>
                <linearGradient id="gb" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#f43f5e" stopOpacity={0.5} /><stop offset="1" stopColor="#f43f5e" stopOpacity={0} /></linearGradient>
              </defs>
              <CartesianGrid stroke="#1c2540" vertical={false} />
              <XAxis dataKey="t" tickFormatter={fmtTick} stroke="#64748b" fontSize={11} minTickGap={30} />
              <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
              <Tooltip contentStyle={{ background: '#0e1324', border: '1px solid #2a355a', borderRadius: 12 }} labelFormatter={(t) => new Date(t).toLocaleString()} />
              <Area type="monotone" dataKey="alerts" name="attacks" stroke="#22d3ee" fill="url(#ga)" strokeWidth={2} />
              <Area type="monotone" dataKey="bans" name="led to a ban" stroke="#f43f5e" fill="url(#gb)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>}
        </div>
      </Card>

      <div className="grid gap-6 md:grid-cols-2 2xl:grid-cols-4">
        <Card title="Top countries">{!data ? <SkeletonList /> : <TopList items={data.countries.slice(0, 10)} total={data?.totals.alerts} render={(k) => <>{flag(k)} {countryName(k)}</>} />}</Card>
        <Card title="Top networks (ASN)">{!data ? <SkeletonList /> : <TopList items={data.asns} />}</Card>
        <Card title="Top scenarios">{!data ? <SkeletonList /> : <TopList items={data.scenarios} render={shortScenario} />}</Card>
        <Card title="Targeted sites" icon={<Crosshair size={14} />}>{!data ? <SkeletonList /> : <TopList items={data.sites} />}</Card>
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
        <Card title="Paths attackers probed" icon={<ShieldAlert size={14} />}>
          {!data ? <SkeletonList rows={8} /> : <TopList items={data.paths} render={(k) => <span className="font-mono text-xs">{k}</span>} />}
        </Card>
        <CloudflareMini />
      </div>
    </div>
  );
}

function CloudflareMini() {
  const { data } = useAsync(() => api<{ configured: boolean; zones: { id: string; name: string; level: string; rps: number | null }[] }>('/cloudflare'), [], 30_000);
  return (
    <Card title="Cloudflare zones" icon={<CloudLightning size={14} />} actions={<Link to="/infra" className="text-xs text-cyan-300 hover:underline">Manage →</Link>}>
      {!data ? <SkeletonList rows={5} /> : !data.configured ? <div className="text-sm text-slate-500">Not configured.</div> : (
        <ul className="divide-y divide-white/5">
          {data.zones.map((z) => (
            <li key={z.id} className="flex items-center justify-between py-2.5 text-sm">
              <span className="text-slate-200">{z.name}</span>
              <span className="flex items-center gap-3">
                <span className="font-mono text-xs text-slate-400">{z.rps ?? 0} req/s</span>
                <Badge tone={z.level === 'under_attack' ? 'rose' : 'emerald'}>{z.level === 'under_attack' ? 'UNDER ATTACK' : z.level}</Badge>
              </span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
