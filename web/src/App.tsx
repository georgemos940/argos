import { useCallback, useEffect, useRef, useState } from 'react';
import { NavLink, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import {
  Activity, Ban, Bell, BookOpen, Download, ScanSearch, ExternalLink, EyeOff, Flame, Gavel, LayoutDashboard, LayoutGrid, ListChecks, ListX, LogOut, Menu, PanelLeftClose, PanelLeftOpen, ScrollText, Search, Server, Settings as Cog, ShieldCheck, Wrench,
} from 'lucide-react';
import { api, selectInstance, selectedInstance, type Me } from './api';
import { AskHost, cx, toast } from './ui';
import Login from './pages/Login';
import Overview from './pages/Overview';
import Alerts from './pages/Alerts';
import Decisions from './pages/Decisions';
import IpProfile from './pages/IpProfile';
import Allowlists from './pages/Allowlists';
import PolicyPage from './pages/Policy';
import IgnoreRules from './pages/IgnoreRules';
import FalsePositives from './pages/FalsePositives';
import Blocklists from './pages/Blocklists';
import Tools from './pages/Tools';
import Waf from './pages/Waf';
import Infra from './pages/Infra';
import Notifications from './pages/Notifications';
import Audit from './pages/Audit';
import Settings from './pages/Settings';

export type Role = 'admin' | 'operator' | 'viewer';
export const can = (role: Role | undefined, min: Role) =>
  ({ viewer: 0, operator: 1, admin: 2 })[role ?? 'viewer'] >= ({ viewer: 0, operator: 1, admin: 2 })[min];

type Counts = { alerts: number; bans: number; lapiUp: boolean };
type Item = { to: string; label: string; icon: typeof Activity; min: Role; count?: keyof Counts; tone?: string };

const NAV: { group: string; items: Item[] }[] = [
  { group: 'Monitor', items: [
    { to: '/', label: 'Overview', icon: LayoutDashboard, min: 'viewer' },
    { to: '/alerts', label: 'Alerts', icon: Activity, min: 'viewer', count: 'alerts', tone: 'bg-amber-400/15 text-amber-200 ring-amber-400/30' },
    { to: '/waf', label: 'Web firewall', icon: Flame, min: 'viewer' },
    { to: '/false-positives', label: 'False positives', icon: ScanSearch, min: 'viewer' },
  ] },
  { group: 'Respond', items: [
    { to: '/bans', label: 'Bans', icon: Ban, min: 'viewer', count: 'bans', tone: 'bg-rose-500/15 text-rose-200 ring-rose-400/30' },
    { to: '/blocklists', label: 'Blocklists', icon: ListX, min: 'viewer' },
    { to: '/allowlists', label: 'Allowlists', icon: ListChecks, min: 'viewer' },
    { to: '/ignore-rules', label: 'Ignore rules', icon: EyeOff, min: 'viewer' },
    { to: '/policy', label: 'Ban policy', icon: Gavel, min: 'viewer' },
  ] },
  { group: 'System', items: [
    { to: '/infra', label: 'Infrastructure', icon: Server, min: 'viewer' },
    { to: '/notifications', label: 'Notifications', icon: Bell, min: 'admin' },
    { to: '/tools', label: 'Tools', icon: Wrench, min: 'viewer' },
    { to: '/audit', label: 'Audit log', icon: ScrollText, min: 'admin' },
    { to: '/settings', label: 'Settings', icon: Cog, min: 'viewer' },
  ] },
];

const LINKS = [
  { label: 'Docs', href: 'https://docs.crowdsec.net/', icon: BookOpen, title: 'CrowdSec documentation: cscli, scenarios, bouncers, allowlists' },
  { label: 'Console', href: 'https://app.crowdsec.net/', icon: LayoutGrid, title: 'CrowdSec Console: hub, blocklists, CTI keys' },
];

// chrome/edge offer an install prompt for the pwa, we show it as a button
type InstallPrompt = Event & { prompt: () => Promise<void>; userChoice: Promise<{ outcome: string }> };
function useInstall() {
  const [ev, setEv] = useState<InstallPrompt | null>(null);
  useEffect(() => {
    const h = (e: Event) => { e.preventDefault(); setEv(e as InstallPrompt); };
    const done = () => setEv(null);
    window.addEventListener('beforeinstallprompt', h);
    window.addEventListener('appinstalled', done);
    return () => { window.removeEventListener('beforeinstallprompt', h); window.removeEventListener('appinstalled', done); };
  }, []);
  return ev && (async () => { await ev.prompt(); await ev.userChoice; setEv(null); });
}

const loadCollapsed = () => { try { return localStorage.getItem('argos.nav.collapsed') === '1'; } catch { return false; } };

function Sidebar({ me, open, onClose, onLogout }: { me: Me; open: boolean; onClose: () => void; onLogout: () => void }) {
  const [collapsed, setCollapsed] = useState(loadCollapsed);
  const [counts, setCounts] = useState<Counts | null>(null);
  const install = useInstall();
  const role = me.user!.role;
  const mini = collapsed && !open;

  // opening alerts/bans marks them read
  const { pathname } = useLocation();
  const seenKey = `argos.seen.${me.user!.username}`;
  const here = useRef(pathname);
  here.current = pathname;

  const refresh = useCallback(() => {
    let seen: Record<string, number> = {};
    try { seen = JSON.parse(localStorage.getItem(seenKey) ?? '{}'); } catch { /* ignore */ }
    for (const [path, k] of [['/alerts', 'alertsSeen'], ['/bans', 'bansSeen']] as const) if (here.current === path) seen[k] = Date.now();
    try { localStorage.setItem(seenKey, JSON.stringify(seen)); } catch { /* private mode */ }
    api<Counts>(`/nav?alertsSeen=${seen.alertsSeen ?? 0}&bansSeen=${seen.bansSeen ?? 0}`).then(setCounts).catch(() => {});
  }, [seenKey]);

  useEffect(() => { refresh(); }, [pathname, refresh]);
  useEffect(() => {
    const t = setInterval(refresh, 30_000);
    return () => clearInterval(t);
  }, [refresh]);

  const toggle = () => setCollapsed((c) => { try { localStorage.setItem('argos.nav.collapsed', c ? '0' : '1'); } catch { /* private mode */ } return !c; });
  let n = 0;

  return (
    <aside className={cx('fixed inset-y-0 left-0 z-40 flex flex-col border-r border-white/[0.06] bg-ink-900/85 backdrop-blur-2xl transition-[width,transform] duration-300 ease-[cubic-bezier(.2,.8,.2,1)] lg:sticky lg:top-0 lg:h-screen lg:translate-x-0',
      mini ? 'w-[78px]' : 'w-[264px]', open ? 'translate-x-0' : '-translate-x-full')}>
      <div className="pointer-events-none absolute inset-y-0 right-0 w-px bg-gradient-to-b from-transparent via-cyan-400/25 to-transparent" />

      <div className={cx('flex h-16 items-center', mini ? 'justify-center' : 'px-5')}>
        <Logo mini={mini} />
      </div>

      {/* no overflow when collapsed or the tooltips get clipped */}
      <nav className={cx('scroll-thin flex-1 px-3 pb-3', mini ? 'overflow-visible' : 'overflow-x-hidden overflow-y-auto')}>
        {NAV.map((g) => {
          const items = g.items.filter((i) => can(role, i.min));
          if (!items.length) return null;
          return (
            <div key={g.group} className="mt-4 first:mt-1">
              <div className={cx('mb-1.5 flex h-4 items-center text-[10px] font-semibold tracking-[0.22em] text-slate-600 uppercase transition-all', mini ? 'justify-center' : 'px-3')}>
                {mini ? <span className="h-px w-5 bg-white/10" /> : g.group}
              </div>
              <div className="space-y-0.5">
                {items.map((it) => {
                  const c = it.count && counts ? Number(counts[it.count]) : 0;
                  return (
                    <NavLink key={it.to} to={it.to} end={it.to === '/'} onClick={onClose} style={{ animationDelay: `${n++ * 35}ms` }}
                      className={({ isActive }) => cx('group relative flex h-10 items-center rounded-xl text-[13.5px] font-medium transition-all duration-200 animate-fade-up',
                        mini ? 'justify-center' : 'gap-3 px-3',
                        isActive ? 'bg-gradient-to-r from-cyan-400/[0.13] via-violet-500/[0.07] to-transparent text-white ring-1 ring-inset ring-white/[0.06]'
                          : 'text-slate-400 hover:bg-white/[0.04] hover:text-slate-100')}>
                      {({ isActive }) => (
                        <>
                          <span className={cx('absolute top-1/2 -left-3 w-[3px] -translate-y-1/2 rounded-r-full bg-gradient-to-b from-cyan-300 to-violet-400 shadow-[0_0_14px_rgba(34,211,238,.9)] transition-all duration-300', isActive ? 'h-6 opacity-100' : 'h-0 opacity-0')} />
                          <span className={cx('relative grid h-7 w-7 shrink-0 place-items-center rounded-lg transition-all duration-200',
                            isActive ? 'bg-gradient-to-br from-cyan-400/25 to-violet-500/25 text-cyan-200 ring-1 ring-white/10' : 'text-slate-500 group-hover:text-slate-200')}>
                            <it.icon size={16} />
                            {mini && c > 0 && <span className="absolute -top-0.5 -right-0.5 h-2 w-2 rounded-full bg-rose-400 shadow-[0_0_8px_rgba(251,113,133,.9)]" />}
                          </span>
                          {!mini && <span className="truncate">{it.label}</span>}
                          {!mini && c > 0 && (
                            <span key={c} title="New since you last opened this page" className={cx('slide-in ml-auto rounded-full px-2 py-px font-mono text-[10.5px] tabular ring-1 ring-inset', it.tone)}>{c > 999 ? '999+' : c}</span>
                          )}
                          {mini && (
                            <span className="pointer-events-none absolute left-full z-50 ml-3 -translate-x-1 rounded-lg bg-ink-800 px-2.5 py-1.5 text-xs whitespace-nowrap text-slate-100 opacity-0 shadow-xl ring-1 ring-white/10 transition-all duration-150 group-hover:translate-x-0 group-hover:opacity-100">
                              {it.label}{c > 0 && <span className="ml-2 text-slate-400">{c}</span>}
                            </span>
                          )}
                        </>
                      )}
                    </NavLink>
                  );
                })}
              </div>
            </div>
          );
        })}
      </nav>

      <div className="space-y-2 border-t border-white/[0.05] p-3">
        <div className={cx('grid gap-2', mini ? 'grid-cols-1' : 'grid-cols-2')}>
          {LINKS.map((l) => (
            <a key={l.href} href={l.href} target="_blank" rel="noreferrer" title={l.title}
              className="group flex h-9 items-center justify-center gap-1.5 rounded-lg bg-white/[0.03] text-xs font-medium text-slate-400 ring-1 ring-white/[0.06] transition hover:bg-cyan-400/10 hover:text-cyan-100 hover:ring-cyan-400/30">
              <l.icon size={14} className="transition group-hover:scale-110" />
              {!mini && <>{l.label}<ExternalLink size={10} className="opacity-40" /></>}
            </a>
          ))}
        </div>
        {install && (
          <button onClick={install} title="Install Argos as an app"
            className="group flex h-9 w-full items-center justify-center gap-1.5 rounded-lg bg-gradient-to-r from-cyan-400/10 to-violet-500/10 text-xs font-medium text-cyan-100 ring-1 ring-cyan-400/25 transition hover:ring-cyan-300/50">
            <Download size={14} className="transition group-hover:translate-y-0.5" />{!mini && 'Install app'}
          </button>
        )}
        <div className={cx('flex items-center rounded-xl bg-white/[0.025] ring-1 ring-white/[0.05]', mini ? 'flex-col gap-2 py-2' : 'gap-3 p-2.5')}>
          <div className="relative grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-gradient-to-br from-cyan-400/30 to-violet-500/30 font-display text-sm font-semibold text-white uppercase ring-1 ring-white/10"
            title={`${me.user!.username} · ${role}`}>
            {me.user!.username.slice(0, 2)}
            <span className={cx('absolute -right-0.5 -bottom-0.5 h-2.5 w-2.5 rounded-full ring-2 ring-ink-900', counts?.lapiUp === false ? 'bg-rose-400' : 'bg-emerald-400')}
              title={counts?.lapiUp === false ? 'CrowdSec API unreachable' : 'CrowdSec API up'} />
          </div>
          {!mini && (
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm font-medium text-white">{me.user!.username}</div>
              <div className="flex items-center gap-1 truncate text-[11px] text-slate-500">
                {role}{me.user!.totp && <ShieldCheck size={11} className="text-emerald-400" />}<span className="text-slate-700">·</span>{me.instance}
              </div>
            </div>
          )}
          <button onClick={onLogout} title="Sign out" className="rounded-lg p-2 text-slate-500 transition hover:bg-rose-500/10 hover:text-rose-300"><LogOut size={15} /></button>
        </div>
        <button onClick={toggle} className="hidden h-8 w-full items-center justify-center gap-2 rounded-lg text-xs text-slate-500 transition hover:bg-white/[0.04] hover:text-slate-200 lg:flex">
          {mini ? <PanelLeftOpen size={15} /> : <><PanelLeftClose size={15} /> Collapse</>}
        </button>
      </div>
    </aside>
  );
}

function Toasts() {
  const [items, setItems] = useState<{ id: number; msg: string; tone: 'ok' | 'err' }[]>([]);
  useEffect(() => {
    const h = (e: Event) => {
      const { msg, tone } = (e as CustomEvent).detail;
      const id = Date.now() + Math.random();
      setItems((x) => [...x, { id, msg, tone }]);
      setTimeout(() => setItems((x) => x.filter((i) => i.id !== id)), 4000);
    };
    window.addEventListener('argos:toast', h);
    return () => window.removeEventListener('argos:toast', h);
  }, []);
  return (
    <div className="fixed right-4 bottom-4 z-[60] space-y-2">
      {items.map((t) => (
        <div key={t.id} className={cx('glass slide-in px-4 py-3 text-sm', t.tone === 'err' ? 'text-rose-300' : 'text-emerald-300')}>{t.msg}</div>
      ))}
    </div>
  );
}

function Clock() {
  const [now, setNow] = useState(new Date());
  useEffect(() => { const t = setInterval(() => setNow(new Date()), 1000); return () => clearInterval(t); }, []);
  return (
    <div className="ml-auto hidden items-center gap-3 sm:flex">
      <span className="flex items-center gap-2 rounded-full bg-emerald-500/10 px-3 py-1 text-[11px] font-semibold tracking-wide text-emerald-300 ring-1 ring-emerald-400/20">
        <span className="relative flex h-2 w-2"><span className="absolute inline-flex h-full w-full rounded-full bg-emerald-400 ping-slow" /><span className="relative h-2 w-2 rounded-full bg-emerald-400" /></span>
        LIVE
      </span>
      <span className="font-mono text-sm text-slate-400 tabular">{now.toLocaleTimeString([], { hour12: false })}</span>
    </div>
  );
}

function Logo({ mini }: { mini?: boolean }) {
  return (
    <div className="flex items-center gap-3">
      <img src="/logo.png" className="h-11 w-11 shrink-0 drop-shadow-[0_0_14px_rgba(139,92,246,0.55)] transition-transform duration-500 hover:-rotate-6 hover:scale-110" alt="Argos" />
      {!mini && <div className="leading-tight whitespace-nowrap">
        <div className="font-display text-xl font-bold tracking-tight"><span className="text-gradient">Argos</span></div>
        <div className="text-[10px] tracking-[0.2em] text-slate-500 uppercase">for CrowdSec</div>
      </div>}
    </div>
  );
}

export default function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const nav = useNavigate();
  const location = useLocation();

  const load = useCallback(() => api<Me>('/auth/me').then(setMe).catch(() => setMe({ setup: false, user: null, needsTotp: false, instance: '' })), []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    const h = () => load();
    window.addEventListener('argos:signed-out', h);
    return () => window.removeEventListener('argos:signed-out', h);
  }, [load]);

  // a removed instance: back to the one the server answered for
  useEffect(() => {
    if (me?.instanceId && selectedInstance() && selectedInstance() !== me.instanceId) selectInstance(me.instanceId);
  }, [me?.instanceId]);

  // linking sso from settings comes back here when it fails
  const signedIn = !!me?.user;
  useEffect(() => {
    const err = new URLSearchParams(window.location.search).get('sso_error');
    if (signedIn && err) { toast(err, 'err'); window.history.replaceState(null, '', window.location.pathname); }
  }, [signedIn]);

  if (!me) return <div className="grid h-full place-items-center text-slate-500">Loading…</div>;
  if (!me.user || me.needsTotp || me.setup || me.mustEnroll) return <><Login me={me} onDone={load} /><Toasts /><AskHost /></>;

  const role = me.user.role;
  const logout = async () => { await api('/auth/logout', { method: 'POST' }); load(); };
  const go = (e: React.FormEvent) => { e.preventDefault(); if (search.trim()) { nav(`/ip/${encodeURIComponent(search.trim())}`); setSearch(''); } };

  return (
    <div className="flex h-full">
      <div className="backdrop"><div className="grid-lines" /></div>
      <Sidebar me={me} open={open} onClose={() => setOpen(false)} onLogout={logout} />
      {open && <div className="fixed inset-0 z-30 bg-black/50 backdrop-blur-sm lg:hidden" onClick={() => setOpen(false)} />}

      <main className="scroll-thin min-w-0 flex-1 overflow-y-auto">
        <div className="sticky top-0 z-20 flex items-center gap-3 border-b border-white/[0.05] bg-ink-950/60 px-4 py-3 backdrop-blur-2xl lg:px-10">
          <button className="rounded-lg p-2 text-slate-300 hover:bg-white/5 lg:hidden" onClick={() => setOpen(true)}><Menu size={20} /></button>
          <form onSubmit={go} className="group relative max-w-md flex-1">
            <Search size={16} className="pointer-events-none absolute top-1/2 left-3.5 -translate-y-1/2 text-slate-500 transition group-focus-within:text-cyan-300" />
            <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Look up an IP…"
              className="w-full rounded-xl bg-white/[0.04] py-2.5 pr-14 pl-10 text-sm text-slate-100 ring-1 ring-white/10 transition placeholder:text-slate-500 hover:ring-white/20 focus:bg-ink-900 focus:ring-2 focus:ring-cyan-400/50 focus:outline-none" />
            <kbd className="pointer-events-none absolute top-1/2 right-3 -translate-y-1/2 rounded-md bg-white/5 px-1.5 py-0.5 font-mono text-[10px] text-slate-500 ring-1 ring-white/10">Enter</kbd>
          </form>
          {(me.instances?.length ?? 0) > 1 && (
            <label className="relative ml-auto flex items-center" title="Which CrowdSec you are looking at">
              <Server size={14} className="pointer-events-none absolute left-3 text-cyan-300" />
              <select value={me.instanceId} onChange={(e) => { selectInstance(e.target.value); window.location.reload(); }}
                className="h-10 appearance-none rounded-xl bg-white/[0.04] pr-8 pl-9 text-sm font-medium text-slate-100 ring-1 ring-white/10 transition hover:ring-white/20 focus:ring-2 focus:ring-cyan-400/50 focus:outline-none">
                {me.instances!.map((i) => <option key={i.id} value={i.id}>{i.name}</option>)}
              </select>
              <span className="pointer-events-none absolute right-3 text-[10px] text-slate-500">▼</span>
            </label>
          )}
          {me.demo && (
            <span title="Generated data. Changes are disabled." className="ml-auto hidden rounded-full bg-violet-500/15 px-3 py-1 text-[11px] font-semibold tracking-wide text-violet-200 ring-1 ring-violet-400/30 sm:inline">DEMO · generated data</span>
          )}
          <Clock />
        </div>
        <div className="mx-auto max-w-[1600px] p-4 lg:p-10">
          <div key={location.pathname} className="animate-fade-up">
          <Routes>
            <Route path="/" element={<Overview home={me.home} />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/bans" element={<Decisions role={role} />} />
            <Route path="/ip/:ip" element={<IpProfile role={role} />} />
            <Route path="/blocklists" element={<Blocklists role={role} />} />
            <Route path="/waf" element={<Waf />} />
            <Route path="/tools" element={<Tools role={role} />} />
            <Route path="/allowlists" element={<Allowlists role={role} />} />
            <Route path="/ignore-rules" element={<IgnoreRules role={role} />} />
            <Route path="/false-positives" element={<FalsePositives role={role} />} />
            <Route path="/policy" element={<PolicyPage role={role} />} />
            <Route path="/infra" element={<Infra role={role} />} />
            <Route path="/notifications" element={<Notifications />} />
            <Route path="/audit" element={<Audit />} />
            <Route path="/settings" element={<Settings me={me} reload={load} />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
          </div>
        </div>
      </main>
      <Toasts /><AskHost />
    </div>
  );
}
