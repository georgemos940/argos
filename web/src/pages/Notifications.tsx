import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Activity, Bell, Copy, Braces, Filter, Palette, RotateCcw, Save, Send, Webhook } from 'lucide-react';
import { api } from '../api';
import { ChannelsCard, DigestCard } from './Channels';
import { Button, Card, ErrorBox, Field, Skeleton, SkeletonCard, Switch, ago, cx, inputCls, toast, useAsync } from '../ui';

const FIELDS = [
  { k: 'country', label: 'Country' }, { k: 'network', label: 'Network' }, { k: 'events', label: 'Events' },
  { k: 'decision', label: 'Decision' }, { k: 'site', label: 'Site hit' }, { k: 'range', label: 'IP range' },
] as const;
type FieldKey = (typeof FIELDS)[number]['k'];

interface Embed {
  username: string; avatarUrl: string; title: string; description: string; colorBan: string; colorAlert: string;
  fields: FieldKey[]; footer: string; linkBase: string; timestamp: boolean;
}
interface S {
  enabled: boolean; webhook: string; hasWebhook: boolean; minEvents: number; scenarioInclude: string; scenarioExclude: string;
  cooldownMinutes: number; maxPerHour: number; mention: string; embed: Embed; embedDefaults: Embed;
}
type Vars = Record<string, string>;

const VARS: { k: string; hint: string }[] = [
  { k: 'flag', hint: 'country flag' }, { k: 'ip', hint: 'attacker IP' }, { k: 'scenario', hint: 'what it did' },
  { k: 'events', hint: 'number of requests' }, { k: 'network', hint: 'ISP / AS name' }, { k: 'asn', hint: 'AS number' },
  { k: 'country', hint: 'country name' }, { k: 'site', hint: 'domain it hit' }, { k: 'duration', hint: 'ban length' },
  { k: 'decision', hint: '"Banned for 4h" or "No decision"' }, { k: 'range', hint: 'IP range' }, { k: 'scenario_full', hint: 'with author prefix' },
];

const fill = (tpl: string, v: Vars) => tpl.replace(/\{(\w+)\}/g, (m, k) => v[k] ?? m);

const FIELD_VALUE: Record<FieldKey, (v: Vars) => { name: string; value: string } | null> = {
  country: (v) => ({ name: 'Country', value: `${v.flag} ${v.country}` }),
  network: (v) => ({ name: 'Network', value: [v.network, v.asn].filter(Boolean).join(' · ') }),
  events: (v) => ({ name: 'Events', value: v.events }),
  decision: (v) => ({ name: 'Decision', value: v.duration ? `ban ${v.duration}` : 'none' }),
  site: (v) => (v.site ? { name: 'Site', value: v.site } : null),
  range: (v) => (v.range ? { name: 'Range', value: v.range } : null),
};

const FALLBACK_VARS: Vars = {
  ip: '203.0.113.42', flag: '🇳🇱', country: 'Netherlands', cc: 'NL', scenario: 'http-probing', scenario_full: 'crowdsecurity/http-probing',
  events: '57', network: 'Example Hosting B.V.', asn: 'AS64500', range: '203.0.113.0/24', site: 'panel.example.com', duration: '4h', decision: 'Banned for **4h**',
};

// minimal discord markdown
function Md({ text }: { text: string }) {
  const parts: ReactNode[] = [];
  const re = /(\*\*[^*]+\*\*|__[^_]+__|\*[^*]+\*|`[^`]+`|\[[^\]]+\]\([^)]+\)|<@&?\d+>|@here|@everyone)/g;
  let last = 0; let m: RegExpExecArray | null; let i = 0;
  while ((m = re.exec(text))) {
    if (m.index > last) parts.push(text.slice(last, m.index));
    const t = m[0];
    if (t.startsWith('**')) parts.push(<b key={i++} className="font-semibold text-white">{t.slice(2, -2)}</b>);
    else if (t.startsWith('__')) parts.push(<u key={i++}>{t.slice(2, -2)}</u>);
    else if (t.startsWith('*')) parts.push(<i key={i++}>{t.slice(1, -1)}</i>);
    else if (t.startsWith('`')) parts.push(<code key={i++} className="rounded bg-[#1e1f22] px-1 py-px font-mono text-[85%]">{t.slice(1, -1)}</code>);
    else if (t.startsWith('[')) { const [, a, h] = /\[([^\]]+)\]\(([^)]+)\)/.exec(t)!; parts.push(<span key={i++} className="text-[#00a8fc] hover:underline" title={h}>{a}</span>); }
    else parts.push(<span key={i++} className="rounded bg-[#5865f2]/30 px-0.5 font-medium text-[#c9cdfb]">{t.startsWith('<@&') ? '@role' : t.startsWith('<@') ? '@user' : t}</span>);
    last = m.index + t.length;
  }
  if (last < text.length) parts.push(text.slice(last));
  return <>{parts}</>;
}

function DiscordPreview({ s, v, banned, at }: { s: S; v: Vars; banned: boolean; at: string }) {
  const e = s.embed;
  const color = (banned ? e.colorBan : e.colorAlert) || '#ef4444';
  const fields = e.fields.map((f) => FIELD_VALUE[f](v)).filter(Boolean) as { name: string; value: string }[];
  const title = fill(e.title, v);
  const desc = fill(e.description, v);
  const time = new Date(at);
  return (
    <div className="overflow-hidden rounded-2xl bg-[#313338] font-[gg_sans,Inter_Variable,sans-serif] text-[15px] leading-[1.375] text-[#dbdee1] shadow-[0_30px_60px_-30px_rgba(0,0,0,.9)] ring-1 ring-black/40">
      <div className="flex items-center gap-2 border-b border-black/20 bg-[#2b2d31] px-4 py-2.5 text-[13px] text-[#949ba4]">
        <span className="text-lg leading-none text-[#80848e]">#</span><span className="font-semibold text-[#f2f3f5]">security-alerts</span>
      </div>
      <div className="flex gap-4 px-4 pt-4 pb-5 transition-colors hover:bg-[#2e3035]">
        {e.avatarUrl
          ? <img src={e.avatarUrl} alt="" className="h-10 w-10 shrink-0 rounded-full object-cover" />
          : <div className="grid h-10 w-10 shrink-0 place-items-center rounded-full bg-gradient-to-br from-cyan-400 to-violet-500"><img src="/logo.png" className="h-8 w-8" alt="" /></div>}
        <div className="min-w-0 flex-1">
          <div className="flex items-baseline gap-2">
            <span className="font-medium text-[#f2f3f5]">{e.username || 'Argos'}</span>
            <span className="rounded bg-[#5865f2] px-1 py-px text-[10px] font-semibold text-white">APP</span>
            <span className="text-xs text-[#949ba4]">Today at {time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
          </div>
          {s.mention && <div className="mt-0.5"><Md text={s.mention} /></div>}
          <div key={color} className="mt-1.5 grid max-w-[520px] rounded-[4px] bg-[#2b2d31] transition-all duration-300" style={{ borderLeft: `4px solid ${color}` }}>
            <div className="space-y-2 py-3 pr-4 pl-3">
              {title && <div className={cx('font-semibold break-words', e.linkBase ? 'text-[#00a8fc] hover:underline' : 'text-[#f2f3f5]')}><Md text={title} /></div>}
              {desc && <div className="text-sm break-words whitespace-pre-wrap"><Md text={desc} /></div>}
              {fields.length > 0 && (
                <div className="grid grid-cols-3 gap-x-4 gap-y-2 pt-1">
                  {fields.map((f) => (
                    <div key={f.name} className="min-w-0">
                      <div className="text-[13px] font-semibold text-[#f2f3f5]">{f.name}</div>
                      <div className="truncate text-sm">{f.value}</div>
                    </div>
                  ))}
                </div>
              )}
              {(e.footer || e.timestamp) && (
                <div className="flex items-center gap-1.5 pt-1 text-xs text-[#949ba4]">
                  {e.footer}{e.footer && e.timestamp && <span>•</span>}{e.timestamp && `Today at ${time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function GrafanaRelay() {
  const { data, reload } = useAsync(() => api<{ webhookSet: boolean; lastAt: number | null; lastStatus: string | null; sent: number; token: string; port: number }>('/grafana-relay'), [], 30_000);
  const [url, setUrl] = useState('');
  const save = async () => {
    try { await api('/grafana-relay', { method: 'PUT', json: { webhook: url } }); toast('Saved'); setUrl(''); reload(); }
    catch (e: any) { toast(e.message, 'err'); }
  };
  const test = async (resolved: boolean) => {
    try { await api('/grafana-relay/test', { method: 'POST', json: { resolved } }); toast('Test sent to Discord'); reload(); }
    catch (e: any) { toast(e.message, 'err'); }
  };
  return (
    <Card title="Grafana alerts" icon={<Activity size={15} />} hover={false}
      subtitle="Grafana sends its alerts here and they go to Discord as full embeds: colour by severity, value, labels, and links to the panel and to silence it.">
      <div className="space-y-4">
        <div className="grid grid-cols-3 gap-3 text-sm">
          <div className="rounded-xl bg-ink-950/50 px-3 py-2.5 ring-1 ring-white/5"><div className="text-[10px] font-semibold tracking-wider text-slate-500 uppercase">Webhook</div><div className={data?.webhookSet ? 'text-emerald-300' : 'text-amber-300'}>{data ? (data.webhookSet ? 'set' : 'missing') : '…'}</div></div>
          <div className="rounded-xl bg-ink-950/50 px-3 py-2.5 ring-1 ring-white/5"><div className="text-[10px] font-semibold tracking-wider text-slate-500 uppercase">Last alert</div><div className="text-slate-200">{data?.lastAt ? `${ago(data.lastAt)} · ${data.lastStatus}` : 'none yet'}</div></div>
          <div className="rounded-xl bg-ink-950/50 px-3 py-2.5 ring-1 ring-white/5"><div className="text-[10px] font-semibold tracking-wider text-slate-500 uppercase">Relayed</div><div className="font-mono text-slate-200">{data?.sent ?? 0}</div></div>
        </div>
        <div className="space-y-2 rounded-xl bg-ink-950/50 p-3 text-xs ring-1 ring-white/5">
          <div className="text-slate-400">In Grafana add a <b className="text-slate-200">webhook</b> contact point with:</div>
          {[['URL', `http://<this container>:${data?.port ?? 3000}/hooks/grafana`], ['Authorization', 'Bearer'], ['Credentials', data?.token ?? '…']].map(([k, v]) => (
            <div key={k} className="flex items-center gap-2">
              <span className="w-24 shrink-0 text-slate-500">{k}</span>
              <code className="min-w-0 flex-1 truncate rounded bg-black/30 px-2 py-1 font-mono text-cyan-200">{v}</code>
              <button type="button" onClick={() => navigator.clipboard.writeText(v).then(() => toast(`${k} copied`))} className="rounded p-1 text-slate-500 hover:bg-white/5 hover:text-white"><Copy size={13} /></button>
            </div>
          ))}
        </div>
        <Field label="Discord webhook for Grafana alerts" hint={data?.webhookSet ? 'A webhook is saved. Paste a new one to replace it.' : undefined}>
          <div className="flex gap-2">
            <input className={inputCls} value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://discord.com/api/webhooks/…" />
            <Button tone="primary" disabled={!url} onClick={save}>Save</Button>
          </div>
        </Field>
        <div className="flex justify-end gap-2">
          <Button disabled={!data?.webhookSet} onClick={() => test(false)}><Send size={14} /> Test firing</Button>
          <Button disabled={!data?.webhookSet} onClick={() => test(true)}><Send size={14} /> Test resolved</Button>
        </div>
      </div>
    </Card>
  );
}

function Label({ children, hint }: { children: ReactNode; hint?: string }) {
  return <div className="mb-1.5 flex items-baseline justify-between gap-3"><span className="text-xs font-medium text-slate-400">{children}</span>{hint && <span className="text-[11px] text-slate-600">{hint}</span>}</div>;
}

function Color({ value, onChange, label }: { value: string; onChange: (v: string) => void; label: string }) {
  return (
    <div>
      <Label>{label}</Label>
      <div className="flex items-center gap-2 rounded-xl bg-ink-950/70 p-1.5 ring-1 ring-white/10">
        <label className="relative h-8 w-8 shrink-0 cursor-pointer overflow-hidden rounded-lg ring-1 ring-white/20" style={{ background: value }}>
          <input type="color" value={value} onChange={(e) => onChange(e.target.value)} className="absolute inset-0 cursor-pointer opacity-0" />
        </label>
        <input className="w-full bg-transparent font-mono text-sm text-slate-200 uppercase focus:outline-none" value={value} onChange={(e) => onChange(e.target.value)} />
        <div className="flex gap-1 pr-1">
          {['#ef4444', '#f59e0b', '#22d3ee', '#a855f7', '#10b981'].map((c) => (
            <button key={c} type="button" onClick={() => onChange(c)} className={cx('h-4 w-4 rounded-full ring-2 transition hover:scale-110', value.toLowerCase() === c ? 'ring-white' : 'ring-transparent')} style={{ background: c }} />
          ))}
        </div>
      </div>
    </div>
  );
}

export default function Notifications() {
  const { data, error, reload } = useAsync(() => api<S>('/notifications'), []);
  const sample = useAsync(() => api<{ vars: Vars | null; banned?: boolean; at?: string }>('/notifications/sample'), []);
  const [s, setS] = useState<S | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [previewBan, setPreviewBan] = useState(true);
  const focused = useRef<'title' | 'description'>('description');
  const titleRef = useRef<HTMLInputElement>(null);
  const descRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => { if (data) setS(data); }, [data]);
  const dirty = useMemo(() => !!s && !!data && JSON.stringify(s) !== JSON.stringify(data), [s, data]);
  const vars = useMemo(() => {
    const v = sample.data?.vars ?? FALLBACK_VARS;
    return previewBan ? v : { ...v, duration: '', decision: 'No decision' };
  }, [sample.data, previewBan]);

  if (!s) return error ? <ErrorBox error={error} /> : (
    <div className="space-y-7">
      <div className="space-y-3"><Skeleton className="h-9 w-64" /><Skeleton className="h-4 w-96 max-w-full" /></div>
      <div className="grid items-start gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,500px)]">
        <div className="space-y-6"><SkeletonCard rows={2} /><SkeletonCard rows={6} /></div>
        <Skeleton className="h-80 rounded-2xl" />
      </div>
    </div>
  );
  const up = <K extends keyof S>(k: K, v: S[K]) => setS({ ...s, [k]: v });
  const ue = <K extends keyof Embed>(k: K, v: Embed[K]) => setS({ ...s, embed: { ...s.embed, [k]: v } });

  const insert = (name: string) => {
    const k = focused.current;
    const el = k === 'title' ? titleRef.current : descRef.current;
    const cur = s.embed[k];
    const at = el?.selectionStart ?? cur.length;
    const end = el?.selectionEnd ?? at;
    const token = `{${name}}`;
    ue(k, cur.slice(0, at) + token + cur.slice(end));
    requestAnimationFrame(() => { el?.focus(); el?.setSelectionRange(at + token.length, at + token.length); });
  };

  const save = async () => {
    setBusy(true);
    try { await api('/notifications', { method: 'PUT', json: s }); toast('Saved'); setErr(null); reload(); }
    catch (e: any) { setErr(e.message); }
    finally { setBusy(false); }
  };
  const test = async () => {
    try { await api('/notifications/test', { method: 'POST', json: { embed: s.embed, mention: s.mention } }); toast('Test sent to Discord'); }
    catch (e: any) { toast(e.message, 'err'); }
  };

  return (
    <div className="space-y-7 pb-24">
      <div>
        <h1 className="font-display text-3xl font-semibold text-white sm:text-[34px]">Notifications</h1>
        <p className="mt-2 max-w-2xl text-sm text-slate-400">Post new attacks to a Discord channel. Design the message on the left and watch it change on the right.</p>
        <div className="hairline mt-4 w-40" />
      </div>

      <div className="grid items-start gap-6 2xl:grid-cols-[minmax(0,1fr)_minmax(0,560px)] xl:grid-cols-[minmax(0,1fr)_minmax(0,500px)]">
        <div className="space-y-6">
          <Card title="Delivery" icon={<Webhook size={15} />} hover={false}
            actions={<div className="flex items-center gap-3 text-sm text-slate-300">{s.enabled ? 'On' : 'Off'}<Switch checked={s.enabled} onChange={(v) => up('enabled', v)} label="Send alerts to Discord" /></div>}>
            <div className="grid gap-5 lg:grid-cols-2">
              <Field label="Webhook URL" hint={s.hasWebhook ? 'A webhook is saved. Paste a new one to replace it.' : 'Discord channel → Edit → Integrations → Webhooks.'}>
                <input className={inputCls} value={s.webhook} onChange={(e) => up('webhook', e.target.value)} placeholder="https://discord.com/api/webhooks/…" />
              </Field>
              <Field label="Mention" hint="Optional. <@&ROLE_ID> pings a role, or @here."><input className={inputCls} value={s.mention} onChange={(e) => up('mention', e.target.value)} placeholder="@here" /></Field>
            </div>
          </Card>

          <Card title="Message design" icon={<Palette size={15} />} hover={false}
            actions={<Button tone="ghost" onClick={() => setS({ ...s, embed: s.embedDefaults })}><RotateCcw size={14} /> Default</Button>}>
            <div className="space-y-5">
              <div className="grid gap-5 sm:grid-cols-2">
                <Field label="Bot name"><input className={inputCls} value={s.embed.username} onChange={(e) => ue('username', e.target.value)} /></Field>
                <Field label="Avatar URL" hint="Optional. A square PNG."><input className={inputCls} value={s.embed.avatarUrl} onChange={(e) => ue('avatarUrl', e.target.value)} placeholder="https://…" /></Field>
              </div>

              <div>
                <Label hint="click to insert at the cursor"><span className="inline-flex items-center gap-1.5"><Braces size={12} /> Variables</span></Label>
                <div className="flex flex-wrap gap-1.5">
                  {VARS.map((x) => (
                    <button key={x.k} type="button" title={`${x.hint} → ${vars[x.k] || '(empty)'}`} onMouseDown={(e) => e.preventDefault()} onClick={() => insert(x.k)}
                      className="rounded-lg bg-cyan-400/[0.07] px-2 py-1 font-mono text-[11.5px] text-cyan-200 ring-1 ring-cyan-400/20 transition hover:-translate-y-px hover:bg-cyan-400/15 hover:ring-cyan-400/50">
                      {`{${x.k}}`}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <Label hint={`${s.embed.title.length}/256`}>Title</Label>
                <input ref={titleRef} onFocus={() => (focused.current = 'title')} className={cx(inputCls, 'font-mono text-[13px]')} value={s.embed.title} onChange={(e) => ue('title', e.target.value)} />
              </div>
              <div>
                <Label hint="**bold**  *italic*  `code`">Description</Label>
                <textarea ref={descRef} onFocus={() => (focused.current = 'description')} rows={4} className={cx(inputCls, 'resize-y font-mono text-[13px] leading-relaxed')} value={s.embed.description} onChange={(e) => ue('description', e.target.value)} />
              </div>

              <div>
                <Label hint="shown as columns under the description">Fields</Label>
                <div className="flex flex-wrap gap-2">
                  {FIELDS.map((f) => {
                    const on = s.embed.fields.includes(f.k);
                    return (
                      <button key={f.k} type="button" onClick={() => ue('fields', on ? s.embed.fields.filter((x) => x !== f.k) : [...s.embed.fields, f.k])}
                        className={cx('rounded-xl px-3 py-1.5 text-xs font-medium ring-1 transition-all duration-200',
                          on ? 'bg-gradient-to-r from-cyan-500/20 to-violet-500/20 text-white ring-cyan-400/40 shadow-[0_0_14px_-6px_rgba(34,211,238,.9)]' : 'text-slate-400 ring-white/10 hover:text-white hover:ring-white/25')}>
                        {on ? '✓ ' : '+ '}{f.label}
                      </button>
                    );
                  })}
                </div>
              </div>

              <div className="grid gap-5 sm:grid-cols-2">
                <Color label="Colour when banned" value={s.embed.colorBan} onChange={(v) => ue('colorBan', v)} />
                <Color label="Colour without a ban" value={s.embed.colorAlert} onChange={(v) => ue('colorAlert', v)} />
              </div>

              <div className="grid gap-5 sm:grid-cols-2">
                <Field label="Footer"><input className={inputCls} value={s.embed.footer} onChange={(e) => ue('footer', e.target.value)} /></Field>
                <Field label="Link the title to" hint="This UI's address. The title opens the IP's page.">
                  <input className={inputCls} value={s.embed.linkBase} onChange={(e) => ue('linkBase', e.target.value)} placeholder="https://crowdsec.example.com" />
                </Field>
              </div>
              <div className="flex items-center justify-between rounded-xl bg-white/[0.02] px-4 py-3 ring-1 ring-white/5">
                <span className="text-sm text-slate-300">Show the time of the attack</span>
                <Switch checked={s.embed.timestamp} onChange={(v) => ue('timestamp', v)} label="Timestamp" />
              </div>
            </div>
          </Card>

          <Card title="Filters and limits" icon={<Filter size={15} />} hover={false} subtitle="So the channel never gets spammed.">
            <div className="grid gap-5 lg:grid-cols-2">
              <Field label="Only scenarios matching (regex)" hint="Empty = all. e.g. http-.*|ssh-.*"><input className={inputCls} value={s.scenarioInclude} onChange={(e) => up('scenarioInclude', e.target.value)} /></Field>
              <Field label="Skip scenarios matching (regex)" hint="e.g. http-probing"><input className={inputCls} value={s.scenarioExclude} onChange={(e) => up('scenarioExclude', e.target.value)} /></Field>
              <Field label="Minimum events per alert"><input type="number" min={1} className={inputCls} value={s.minEvents} onChange={(e) => up('minEvents', Number(e.target.value))} /></Field>
              <Field label="Cooldown per IP (minutes)" hint="The same IP is reported at most once in this window."><input type="number" min={1} className={inputCls} value={s.cooldownMinutes} onChange={(e) => up('cooldownMinutes', Number(e.target.value))} /></Field>
              <Field label="Max messages per hour" hint="Hard cap; each message groups up to 10 alerts."><input type="number" min={1} max={120} className={inputCls} value={s.maxPerHour} onChange={(e) => up('maxPerHour', Number(e.target.value))} /></Field>
            </div>
          </Card>

          <ChannelsCard />
          <DigestCard />

          <GrafanaRelay />
        </div>

        <div className="space-y-4 xl:sticky xl:top-24">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-[11px] font-semibold tracking-[0.18em] text-cyan-300/80 uppercase">
              <span className="relative flex h-2 w-2"><span className="absolute inline-flex h-full w-full rounded-full bg-cyan-400 ping-slow" /><span className="relative h-2 w-2 rounded-full bg-cyan-400" /></span>
              Live preview
            </div>
            <div className="flex rounded-lg bg-ink-950/60 p-0.5 text-[11px] ring-1 ring-white/10">
              {[true, false].map((b) => (
                <button key={String(b)} onClick={() => setPreviewBan(b)} className={cx('rounded-md px-2.5 py-1 transition', previewBan === b ? 'bg-white/10 text-white' : 'text-slate-500 hover:text-slate-200')}>
                  {b ? 'Banned' : 'Alert only'}
                </button>
              ))}
            </div>
          </div>
          <DiscordPreview s={s} v={vars} banned={previewBan} at={sample.data?.at ?? new Date().toISOString()} />
          <p className="text-xs text-slate-500">
            {sample.data?.vars ? <>Uses a real alert from the last 7 days ({vars.ip}).</> : 'Uses example data until the first alert arrives.'}
          </p>
          <ErrorBox error={err} />
        </div>
      </div>

      <div className={cx('fixed right-6 bottom-6 z-30 flex items-center gap-3 rounded-2xl bg-ink-850/90 p-2 pl-4 shadow-2xl ring-1 backdrop-blur-xl transition-all duration-300',
        dirty ? 'ring-amber-400/40' : 'ring-white/10')}>
        <span className={cx('flex items-center gap-2 text-xs', dirty ? 'text-amber-200' : 'text-slate-500')}>
          <Bell size={13} />{dirty ? 'Unsaved changes' : 'All saved'}
        </span>
        <Button onClick={test} disabled={!s.hasWebhook}><Send size={14} /> Send test</Button>
        <Button tone="primary" disabled={!dirty || busy} onClick={save}><Save size={14} /> Save</Button>
      </div>
    </div>
  );
}
