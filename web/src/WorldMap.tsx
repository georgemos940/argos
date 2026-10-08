import { useMemo, useState } from 'react';
import { geoGraticule10, geoNaturalEarth1, geoPath } from 'd3-geo';
import { feature } from 'topojson-client';
import world from 'world-atlas/countries-110m.json';
import { countryName, flag } from './ui';

export interface MapPoint { lat: number; lon: number; cn: string; count: number; ips: string[] }

const W = 960;
const H = 470;
const land = feature(world as any, (world as any).objects.countries) as any;
export default function WorldMap({ points, hot = [], home: at = [8.68, 50.11] }: {
  points: MapPoint[]; hot?: { lat: number; lon: number }[]; home?: [number, number];
}) {
  const [hover, setHover] = useState<MapPoint | null>(null);
  const projection = useMemo(() => geoNaturalEarth1().fitExtent([[8, 8], [W - 8, H - 8]], { type: 'Sphere' } as any), []);
  const path = useMemo(() => geoPath(projection), [projection]);
  const max = Math.max(1, ...points.map((p) => p.count));
  const home = projection(at)!;

  // arc bends up with distance
  const arc = (from: [number, number]) => {
    const [x1, y1] = from;
    const [x2, y2] = home;
    const mx = (x1 + x2) / 2;
    const my = (y1 + y2) / 2;
    const d = Math.hypot(x2 - x1, y2 - y1);
    return `M${x1},${y1} Q${mx},${my - d * 0.35} ${x2},${y2}`;
  };

  return (
    <div className="relative">
      <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full">
        <defs>
          <radialGradient id="ocean" cx="50%" cy="45%" r="65%"><stop offset="0" stopColor="#0d1530" /><stop offset="1" stopColor="#060a16" /></radialGradient>
          <linearGradient id="landfill" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stopColor="#1b2546" /><stop offset="1" stopColor="#141b33" /></linearGradient>
          <linearGradient id="arcgrad" x1="0" x2="1"><stop offset="0" stopColor="#fb7185" stopOpacity=".1" /><stop offset=".6" stopColor="#f472b6" /><stop offset="1" stopColor="#22d3ee" /></linearGradient>
          <radialGradient id="halo"><stop offset="0" stopColor="#fb7185" stopOpacity=".55" /><stop offset="1" stopColor="#fb7185" stopOpacity="0" /></radialGradient>
          <radialGradient id="homehalo"><stop offset="0" stopColor="#22d3ee" stopOpacity=".7" /><stop offset="1" stopColor="#22d3ee" stopOpacity="0" /></radialGradient>
          <filter id="glow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="2.2" result="b" /><feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge></filter>
        </defs>

        <path d={path({ type: 'Sphere' } as any) ?? ''} fill="url(#ocean)" stroke="#1f2a4d" strokeWidth={1} />
        <path d={path(geoGraticule10()) ?? ''} fill="none" stroke="#23305a" strokeWidth={0.4} strokeOpacity={0.55} />
        <g>
          {land.features.map((f: any, i: number) => (
            <path key={i} d={path(f) ?? ''} fill="url(#landfill)" stroke="#33427a" strokeWidth={0.45} strokeOpacity={0.8} />
          ))}
        </g>

        <g filter="url(#glow)">
          {points.map((p, i) => {
            const xy = projection([p.lon, p.lat]);
            if (!xy) return null;
            const width = 0.6 + 1.6 * Math.sqrt(p.count / max);
            return (
              <g key={`a${i}`}>
                <path d={arc(xy as [number, number])} fill="none" stroke="url(#arcgrad)" strokeWidth={width} strokeOpacity={0.35} />
                <path d={arc(xy as [number, number])} fill="none" stroke="url(#arcgrad)" strokeWidth={width + 0.4} strokeLinecap="round"
                  pathLength={100} strokeDasharray="8 92" style={{ animation: `dash-travel ${2.6 + (i % 5) * 0.4}s linear ${(i % 7) * 0.35}s infinite` }} />
              </g>
            );
          })}
        </g>

        <g>
          {points.map((p, i) => {
            const xy = projection([p.lon, p.lat]);
            if (!xy) return null;
            const r = 2.5 + 7 * Math.sqrt(p.count / max);
            return (
              <g key={i} onMouseEnter={() => setHover(p)} onMouseLeave={() => setHover(null)} className="cursor-pointer">
                <circle cx={xy[0]} cy={xy[1]} r={r * 2.6} fill="url(#halo)" />
                <circle cx={xy[0]} cy={xy[1]} r={r} fill="#fb7185" fillOpacity={0.9} stroke="#ffe4e6" strokeWidth={0.7} />
              </g>
            );
          })}
          {hot.map((h, i) => {
            const xy = projection([h.lon, h.lat]);
            return xy ? <circle key={`h${i}`} cx={xy[0]} cy={xy[1]} r={7} fill="none" stroke="#fb7185" strokeWidth={2} className="ping-slow" /> : null;
          })}
        </g>

        <g>
          <circle cx={home[0]} cy={home[1]} r={22} fill="url(#homehalo)" className="glow-pulse" />
          <circle cx={home[0]} cy={home[1]} r={9} fill="none" stroke="#22d3ee" strokeWidth={1.5} className="ping-slow" />
          <circle cx={home[0]} cy={home[1]} r={4.5} fill="#22d3ee" stroke="#ecfeff" strokeWidth={1.2} />
        </g>
      </svg>

      <div className="pointer-events-none absolute bottom-3 left-3 flex items-center gap-4 rounded-full bg-ink-950/70 px-3 py-1.5 text-[11px] text-slate-400 ring-1 ring-white/10 backdrop-blur">
        <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-rose-400" /> attacker</span>
        <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-cyan-400" /> our server</span>
      </div>

      {hover && (
        <div className="glass slide-in pointer-events-none absolute top-3 left-3 px-4 py-3 text-xs">
          <div className="font-display text-sm font-semibold text-white">{flag(hover.cn)} {countryName(hover.cn)}</div>
          <div className="mt-0.5 text-slate-400">{hover.count} attack{hover.count > 1 ? 's' : ''}</div>
          <div className="mt-1.5 font-mono text-[11px] text-rose-200">{hover.ips.join(' · ')}</div>
        </div>
      )}
    </div>
  );
}
