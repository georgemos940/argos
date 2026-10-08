import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { Link } from 'react-router-dom';
import { AlertTriangle, Loader2, X } from 'lucide-react';

export const cx = (...c: (string | false | null | undefined)[]) => c.filter(Boolean).join(' ');

export function Card({ title, icon, actions, children, className, hover = true, subtitle }: {
  title?: ReactNode; icon?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; hover?: boolean; subtitle?: ReactNode;
}) {
  return (
    <section className={cx('glass p-5 sm:p-6', hover && 'hoverable', className)}>
      {(title || actions) && (
        <header className="mb-5 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="flex items-center gap-2.5 text-[15px] font-semibold text-white">
              {icon && <span className="grid h-7 w-7 place-items-center rounded-lg bg-gradient-to-br from-cyan-400/20 to-violet-500/20 text-cyan-200 ring-1 ring-white/10">{icon}</span>}
              {title}
            </h2>
            {subtitle && <p className="mt-1 text-xs text-slate-500">{subtitle}</p>}
          </div>
          {actions}
        </header>
      )}
      {children}
    </section>
  );
}

const ACCENT = {
  cyan: { text: 'text-cyan-300', blob: 'from-cyan-400/25', stroke: '#22d3ee' },
  violet: { text: 'text-violet-300', blob: 'from-violet-400/25', stroke: '#a78bfa' },
  rose: { text: 'text-rose-300', blob: 'from-rose-400/25', stroke: '#fb7185' },
  emerald: { text: 'text-emerald-300', blob: 'from-emerald-400/25', stroke: '#34d399' },
  amber: { text: 'text-amber-300', blob: 'from-amber-400/25', stroke: '#fbbf24' },
};

export function Stat({ label, value, hint, accent = 'cyan', icon, spark }: {
  label: string; value: ReactNode; hint?: ReactNode; accent?: keyof typeof ACCENT; icon?: ReactNode; spark?: number[];
}) {
  const a = ACCENT[accent];
  return (
    <div className="glass hoverable relative overflow-hidden p-5">
      <div className={cx('pointer-events-none absolute -top-12 -right-12 h-36 w-36 rounded-full bg-gradient-to-br to-transparent blur-2xl glow-pulse', a.blob)} />
      <div className="relative flex items-center justify-between text-[11px] font-semibold tracking-[0.1em] text-slate-400 uppercase">
        {label}<span className={cx('grid h-8 w-8 place-items-center rounded-xl bg-white/[0.04] ring-1 ring-white/10', a.text)}>{icon}</span>
      </div>
      <div className="relative mt-3 font-display text-[34px] leading-none font-semibold text-white tabular">
        {typeof value === 'number' ? <AnimatedNumber value={value} /> : value}
      </div>
      <div className="relative mt-3 flex items-end justify-between gap-3">
        {hint && <div className="text-xs text-slate-500">{hint}</div>}
        {spark && spark.length > 1 && <Sparkline data={spark} color={a.stroke} />}
      </div>
    </div>
  );
}

export function AnimatedNumber({ value, duration = 900 }: { value: number; duration?: number }) {
  const [shown, setShown] = useState(0);
  const from = useRef(0);
  useEffect(() => {
    const start = performance.now();
    const a = from.current;
    let raf = 0;
    const step = (t: number) => {
      const p = Math.min(1, (t - start) / duration);
      const eased = 1 - Math.pow(1 - p, 3);
      setShown(a + (value - a) * eased);
      if (p < 1) raf = requestAnimationFrame(step);
      else from.current = value;
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [value, duration]);
  return <>{Math.round(shown).toLocaleString()}</>;
}

export function Sparkline({ data, color = '#22d3ee', w = 110, h = 34 }: { data: number[]; color?: string; w?: number; h?: number }) {
  const id = useId();
  const max = Math.max(1, ...data);
  const pts = data.map((v, i) => [(i / (data.length - 1)) * w, h - 3 - (v / max) * (h - 6)]);
  const line = pts.map((p, i) => `${i ? 'L' : 'M'}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(' ');
  return (
    <svg width={w} height={h} className="shrink-0 overflow-visible">
      <defs><linearGradient id={id} x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor={color} stopOpacity=".35" /><stop offset="1" stopColor={color} stopOpacity="0" /></linearGradient></defs>
      <path d={`${line} L${w},${h} L0,${h} Z`} fill={`url(#${id})`} />
      <path d={line} fill="none" stroke={color} strokeWidth={1.75} strokeLinejoin="round" strokeLinecap="round"
        pathLength={1} strokeDasharray={1} style={{ animation: 'travel 1.2s ease-out both' }} />
      <circle cx={pts[pts.length - 1][0]} cy={pts[pts.length - 1][1]} r={2.5} fill={color} className="glow-pulse" />
    </svg>
  );
}

export function PageHeader({ title, subtitle, actions, eyebrow }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode; eyebrow?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-4">
      <div>
        {eyebrow && <div className="mb-2 text-[11px] font-semibold tracking-[0.18em] text-cyan-300/80 uppercase">{eyebrow}</div>}
        <h1 className="font-display text-3xl font-semibold text-white sm:text-[34px]">{title}</h1>
        {subtitle && <p className="mt-2 max-w-2xl text-sm text-slate-400">{subtitle}</p>}
        <div className="hairline mt-4 w-40" />
      </div>
      {actions}
    </div>
  );
}

export function Skeleton({ className, style }: { className?: string; style?: React.CSSProperties }) {
  return <div className={cx('skeleton', className)} style={style} />;
}

const W = ['w-3/4', 'w-1/2', 'w-2/3', 'w-5/6', 'w-2/5', 'w-3/5'];

export function SkeletonRows({ rows = 8, cols }: { rows?: number; cols: number }) {
  return (
    <>
      {Array.from({ length: rows }, (_, r) => (
        <tr key={r} className="skeleton-row" style={{ animationDelay: `${r * 45}ms` }}>
          {Array.from({ length: cols }, (_, c) => (
            <td key={c} className="py-3 pr-4"><Skeleton className={cx('h-3.5', W[(r + c * 3) % W.length])} /></td>
          ))}
        </tr>
      ))}
    </>
  );
}

export function SkeletonList({ rows = 6, avatar }: { rows?: number; avatar?: boolean }) {
  return (
    <div className="space-y-3.5">
      {Array.from({ length: rows }, (_, r) => (
        <div key={r} className="skeleton-row flex items-center gap-3" style={{ animationDelay: `${r * 50}ms` }}>
          {avatar && <Skeleton className="h-8 w-8 shrink-0 rounded-lg" />}
          <div className="flex-1 space-y-1.5"><Skeleton className={cx('h-3.5', W[r % W.length])} /><Skeleton className="h-2.5 w-1/3 opacity-60" /></div>
          <Skeleton className="h-5 w-12 rounded-full" />
        </div>
      ))}
    </div>
  );
}

export function SkeletonCard({ rows = 5, className }: { rows?: number; className?: string }) {
  return (
    <div className={cx('glass p-5 sm:p-6', className)}>
      <div className="mb-6 flex items-center gap-2.5"><Skeleton className="h-7 w-7 rounded-lg" /><Skeleton className="h-4 w-40" /></div>
      <SkeletonList rows={rows} />
    </div>
  );
}

export function Badge({ children, tone = 'slate' }: { children: ReactNode; tone?: 'slate' | 'rose' | 'emerald' | 'amber' | 'cyan' | 'violet' }) {
  const t = {
    slate: 'bg-slate-500/10 text-slate-300 ring-slate-500/20', rose: 'bg-rose-500/10 text-rose-300 ring-rose-500/30',
    emerald: 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/30', amber: 'bg-amber-500/10 text-amber-300 ring-amber-500/30',
    cyan: 'bg-cyan-500/10 text-cyan-300 ring-cyan-500/30', violet: 'bg-violet-500/10 text-violet-300 ring-violet-500/30',
  }[tone];
  return <span className={cx('inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[11px] font-medium ring-1 ring-inset whitespace-nowrap', t)}>{children}</span>;
}

export function Button({ children, tone = 'default', className, ...p }: React.ButtonHTMLAttributes<HTMLButtonElement> & { tone?: 'default' | 'primary' | 'danger' | 'ghost' }) {
  const t = {
    default: 'bg-white/[0.05] hover:bg-white/[0.09] text-slate-100 ring-1 ring-white/10 hover:ring-white/20',
    primary: 'bg-gradient-to-r from-cyan-500 via-sky-500 to-violet-500 text-white shadow-[0_8px_30px_-8px_rgba(34,211,238,.6)] hover:shadow-[0_10px_40px_-6px_rgba(139,92,246,.7)] bg-[length:200%_100%] hover:bg-right',
    danger: 'bg-gradient-to-r from-rose-600 to-pink-600 text-white shadow-[0_8px_30px_-10px_rgba(244,63,94,.7)] hover:brightness-110',
    ghost: 'hover:bg-white/[0.06] text-slate-300 hover:text-white',
  }[tone];
  return (
    <button {...p} className={cx('group relative inline-flex items-center justify-center gap-2 overflow-hidden rounded-xl px-3.5 py-2 text-sm font-medium transition-all duration-300 active:scale-[.97] disabled:cursor-not-allowed disabled:opacity-40', t, className)}>
      {tone === 'primary' && <span className="pointer-events-none absolute inset-0 -translate-x-full bg-gradient-to-r from-transparent via-white/25 to-transparent transition-transform duration-700 group-hover:translate-x-full" />}
      {children}
    </button>
  );
}

export function Checkbox({ checked, indeterminate, onChange, label }: { checked: boolean; indeterminate?: boolean; onChange: (v: boolean) => void; label?: string }) {
  const on = checked || indeterminate;
  return (
    <button type="button" role="checkbox" aria-checked={indeterminate ? 'mixed' : checked} aria-label={label}
      onClick={(e) => { e.stopPropagation(); onChange(!checked); }}
      className={cx('relative grid h-[18px] w-[18px] shrink-0 place-items-center rounded-[6px] transition-all duration-200 active:scale-90',
        on ? 'bg-gradient-to-br from-cyan-400 to-violet-500 shadow-[0_0_14px_-2px_rgba(34,211,238,.7)]'
          : 'bg-ink-950/70 ring-1 ring-white/15 hover:ring-cyan-400/50')}>
      <svg viewBox="0 0 16 16" className="h-3 w-3 text-ink-950" fill="none" stroke="currentColor" strokeWidth={2.6} strokeLinecap="round" strokeLinejoin="round">
        {indeterminate
          ? <path d="M4 8h8" />
          : <path d="M3.5 8.5l3 3 6-7" pathLength={1} strokeDasharray={1} strokeDashoffset={checked ? 0 : 1} style={{ transition: 'stroke-dashoffset .25s ease-out' }} />}
      </svg>
    </button>
  );
}

export function Switch({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label?: string }) {
  return (
    <button type="button" role="switch" aria-checked={checked} aria-label={label} onClick={() => onChange(!checked)}
      className={cx('relative h-6 w-11 shrink-0 rounded-full transition-all duration-300',
        checked ? 'bg-gradient-to-r from-cyan-500 to-violet-500 shadow-[0_0_18px_-4px_rgba(34,211,238,.8)]' : 'bg-white/10 ring-1 ring-white/10')}>
      <span className={cx('absolute top-0.5 left-0.5 h-5 w-5 rounded-full bg-white shadow transition-transform duration-300 ease-[cubic-bezier(.2,.8,.2,1)]', checked && 'translate-x-5')} />
    </button>
  );
}

export const inputBase = 'rounded-xl bg-ink-950/70 px-3.5 py-2.5 text-sm text-slate-100 ring-1 ring-white/10 transition placeholder:text-slate-500 hover:ring-white/20 focus:ring-2 focus:ring-cyan-400/60 focus:shadow-[0_0_0_6px_rgba(34,211,238,.08)] focus:outline-none';
export const inputCls = `w-full ${inputBase}`;

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <label className="block space-y-1.5">
      <span className="text-xs font-medium text-slate-400">{label}</span>
      {children}
      {hint && <span className="block text-xs text-slate-500">{hint}</span>}
    </label>
  );
}

// portal: backdrop-filter on cards traps fixed children
export function Modal({ open, onClose, title, children, wide }: { open: boolean; onClose: () => void; title: ReactNode; children: ReactNode; wide?: boolean }) {
  const close = useRef(onClose);
  close.current = onClose;
  useEffect(() => {
    if (!open) return;
    const k = (e: KeyboardEvent) => e.key === 'Escape' && close.current();
    window.addEventListener('keydown', k);
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => { window.removeEventListener('keydown', k); document.body.style.overflow = prev; };
  }, [open]);
  if (!open) return null;
  return createPortal(
    <div className="fixed inset-0 z-[70] flex items-center justify-center p-4" role="dialog" aria-modal="true">
      <div className="absolute inset-0 bg-ink-950/75 backdrop-blur-md" style={{ animation: 'fade-in .2s ease-out both' }} onClick={() => close.current()} />
      <div className={cx('modal-card relative flex max-h-[calc(100dvh-2rem)] w-full flex-col', wide ? 'max-w-4xl' : 'max-w-lg')}>
        <div className="pointer-events-none absolute inset-x-10 -top-px h-px bg-gradient-to-r from-transparent via-cyan-300/70 to-transparent" />
        <div className="flex shrink-0 items-center justify-between gap-4 border-b border-white/[0.06] px-6 py-5 sm:px-7">
          <h3 className="font-display text-lg font-semibold text-white sm:text-xl">{title}</h3>
          <button onClick={() => close.current()} aria-label="Close" className="rounded-lg p-1.5 text-slate-400 transition hover:rotate-90 hover:bg-white/5 hover:text-white"><X size={18} /></button>
        </div>
        <div className="scroll-thin min-h-0 overflow-y-auto px-6 py-6 sm:px-7">{children}</div>
      </div>
    </div>,
    document.body,
  );
}

type AskOptions = {
  title: ReactNode; body?: ReactNode; confirmLabel?: string; tone?: 'primary' | 'danger';
  input?: { label: string; placeholder?: string; mono?: boolean; maxLength?: number };
};
type AskRequest = AskOptions & { resolve: (v: string | boolean | null) => void };

// confirm/prompt replacement
export function ask(o: AskOptions & { input: NonNullable<AskOptions['input']> }): Promise<string | null>;
export function ask(o: AskOptions): Promise<boolean>;
export function ask(o: AskOptions): Promise<any> {
  return new Promise((resolve) => window.dispatchEvent(new CustomEvent('argos:ask', { detail: { ...o, resolve } })));
}

export function AskHost() {
  const [req, setReq] = useState<AskRequest | null>(null);
  const [text, setText] = useState('');
  useEffect(() => {
    const h = (e: Event) => { setText(''); setReq((e as CustomEvent).detail); };
    window.addEventListener('argos:ask', h);
    return () => window.removeEventListener('argos:ask', h);
  }, []);
  const done = (ok: boolean) => {
    if (!req) return;
    req.resolve(ok ? (req.input ? text : true) : req.input ? null : false);
    setReq(null);
  };
  const tone = req?.tone ?? 'primary';
  return (
    <Modal open={!!req} onClose={() => done(false)} title={
      <span className="flex items-center gap-3">
        <span className={cx('grid h-9 w-9 place-items-center rounded-xl ring-1', tone === 'danger' ? 'bg-rose-500/15 text-rose-300 ring-rose-400/30' : 'bg-cyan-400/15 text-cyan-200 ring-cyan-400/30')}>
          <AlertTriangle size={18} />
        </span>
        {req?.title}
      </span>
    }>
      <form onSubmit={(e) => { e.preventDefault(); if (!req?.input || text) done(true); }}>
        {req?.body && <div className="text-sm leading-relaxed text-slate-400">{req.body}</div>}
        {req?.input && (
          <div className={cx(req.body ? 'mt-5' : '')}>
            <Field label={req.input.label}>
              <input autoFocus className={cx(inputCls, req.input.mono && 'font-mono tracking-[0.35em]')} value={text} maxLength={req.input.maxLength}
                placeholder={req.input.placeholder} onChange={(e) => setText(e.target.value)} />
            </Field>
          </div>
        )}
        <div className="mt-6 flex justify-end gap-2">
          <Button type="button" tone="ghost" onClick={() => done(false)}>Cancel</Button>
          <Button tone={tone} disabled={!!req?.input && !text} autoFocus={!req?.input}>{req?.confirmLabel ?? 'Confirm'}</Button>
        </div>
      </form>
    </Modal>
  );
}

export function Confirm({ open, onClose, onConfirm, title, children, confirmLabel = 'Confirm', tone = 'primary', disabled, icon }: {
  open: boolean; onClose: () => void; onConfirm: () => Promise<void> | void; title: ReactNode; children?: ReactNode;
  confirmLabel?: ReactNode; tone?: 'primary' | 'danger'; disabled?: boolean; icon?: ReactNode;
}) {
  const [busy, setBusy] = useState(false);
  const run = async () => {
    setBusy(true);
    try { await onConfirm(); } catch (e: any) { toast(e.message, 'err'); } finally { setBusy(false); }
  };
  return (
    <Modal open={open} onClose={busy ? () => {} : onClose} title={
      <span className="flex items-center gap-3">
        <span className={cx('grid h-9 w-9 place-items-center rounded-xl ring-1', tone === 'danger' ? 'bg-rose-500/15 text-rose-300 ring-rose-400/30' : 'bg-amber-400/15 text-amber-300 ring-amber-400/30')}>
          {icon ?? <AlertTriangle size={18} />}
        </span>
        {title}
      </span>
    }>
      <div className="text-sm leading-relaxed text-slate-400">{children}</div>
      <div className="mt-6 flex justify-end gap-2">
        <Button tone="ghost" disabled={busy} onClick={onClose}>Cancel</Button>
        <Button tone={tone} disabled={busy || disabled} onClick={run}>{busy && <Loader2 size={14} className="animate-spin" />}{confirmLabel}</Button>
      </div>
    </Modal>
  );
}

export const flag = (cc?: string) =>
  cc && cc.length === 2 ? String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65)) : '🏳️';

const regionNames = new Intl.DisplayNames(['en'], { type: 'region' });
export const countryName = (cc?: string) => { try { return cc ? regionNames.of(cc) ?? cc : 'Unknown'; } catch { return cc ?? 'Unknown'; } };

export function ago(iso: string | number): string {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export const shortScenario = (s: string) => s.replace(/^crowdsecurity\//, '').replace(/^manual '(\w+)' from '([^']+)'.*$/, 'manual $1 · $2');

export function IpLink({ ip, cn }: { ip: string; cn?: string }) {
  return (
    <Link to={`/ip/${encodeURIComponent(ip)}`} className="inline-flex items-center gap-1.5 font-mono text-cyan-300 hover:text-cyan-200 hover:underline">
      <span className="font-sans">{flag(cn)}</span>{ip}
    </Link>
  );
}

// stale-while-revalidate
const asyncCache = new Map<string, unknown>();

export function useAsync<T>(fn: () => Promise<T>, deps: unknown[] = [], every?: number) {
  const key = fn.toString() + JSON.stringify(deps);
  const [data, setData] = useState<T | null>(() => (asyncCache.get(key) as T) ?? null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  const prevKey = useRef(key);
  useEffect(() => {
    let alive = true;
    setLoading(true);
    if (prevKey.current !== key) {
      prevKey.current = key;
      setData((asyncCache.get(key) as T) ?? null);
    }
    fn().then((d) => { asyncCache.set(key, d); if (alive) { setData(d); setError(null); } })
      .catch((e) => alive && setError(e.message))
      .finally(() => alive && setLoading(false));
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);
  useEffect(() => {
    if (!every) return;
    const t = setInterval(() => setTick((x) => x + 1), every);
    return () => clearInterval(t);
  }, [every]);
  return { data, error, loading, reload: () => setTick((x) => x + 1) };
}

export function ErrorBox({ error }: { error: string | null }) {
  if (!error) return null;
  return <div className="rounded-lg bg-rose-500/10 px-3 py-2 text-sm text-rose-300 ring-1 ring-rose-500/30">{error}</div>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="py-10 text-center text-sm text-slate-500">{children}</div>;
}

export const toast = (msg: string, tone: 'ok' | 'err' = 'ok') =>
  window.dispatchEvent(new CustomEvent('argos:toast', { detail: { msg, tone } }));
