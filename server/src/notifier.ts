import { getAlerts, type Alert } from './lapi.js';
import { MAIN, inInstance, listInstances, type Instance } from './instances.js';
import { getSetting, setSetting } from './db.js';
import { slim } from './stats.js';
import { alertMessage, broadcast, listChannels, type Message } from './channels.js';

export const EMBED_FIELDS = ['country', 'network', 'events', 'decision', 'site', 'range'] as const;
export type EmbedField = (typeof EMBED_FIELDS)[number];

export interface EmbedStyle {
  username: string;
  avatarUrl: string;
  title: string;             // see vars()
  description: string;
  colorBan: string;          // hex
  colorAlert: string;        // hex
  fields: EmbedField[];
  footer: string;
  linkBase: string;          // title links to <base>/ip/<ip>
  timestamp: boolean;
}

export interface NotifySettings {
  enabled: boolean;
  webhook: string;
  minEvents: number;
  scenarioInclude: string;   // regex, empty = all
  scenarioExclude: string;   // regex
  cooldownMinutes: number;   // per IP
  maxPerHour: number;          mention: string;             embed: EmbedStyle;
}

export const defaultEmbed: EmbedStyle = {
  username: 'Argos',
  avatarUrl: '',
  title: '{flag} {ip} · {scenario}',
  description: '**{events}** events from {network}\n{decision}',
  colorBan: '#ef4444',
  colorAlert: '#f59e0b',
  fields: ['country', 'site'],
  footer: 'Argos',
  linkBase: '',
  timestamp: true,
};

export const defaultNotify: NotifySettings = {
  enabled: false, webhook: '', minEvents: 1, scenarioInclude: '', scenarioExclude: '',
  cooldownMinutes: 60, maxPerHour: 20, mention: '', embed: defaultEmbed,
};

export const notifySettings = (): NotifySettings => {
  const s = getSetting<NotifySettings>('notify', defaultNotify);
  return { ...defaultNotify, ...s, embed: { ...defaultEmbed, ...s.embed } };
};

type Listener = (alert: ReturnType<typeof slim>, instance: string) => void;
const listeners = new Set<Listener>();
export const onAlert = (fn: Listener) => { listeners.add(fn); return () => listeners.delete(fn); };

const lastByIp = new Map<string, number>();
let sentThisHour: { hour: number; n: number } = { hour: 0, n: 0 };

const flag = (cc?: string) =>
  cc && cc.length === 2 ? String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65)) : '';

const regionNames = new Intl.DisplayNames(['en'], { type: 'region' });
const country = (cc?: string) => { try { return cc ? regionNames.of(cc) ?? cc : 'Unknown'; } catch { return cc ?? 'Unknown'; } };
const dur = (d?: string) => (d ?? '').replace(/\.\d+s$/, 's').replace(/(\d+h)\d+m\d+s$/, '$1');

// template vars, keep in sync with the web preview
export function vars(a: Alert): Record<string, string> {
  const d = a.decisions?.[0];
  const site = a.events?.flatMap((e) => e.meta).find((m) => m.key === 'target_fqdn')?.value;
  return {
    ip: a.source.value,
    flag: flag(a.source.cn),
    country: country(a.source.cn),
    cc: a.source.cn ?? '',
    scenario: a.scenario.replace(/^crowdsecurity\//, ''),
    scenario_full: a.scenario,
    events: String(a.events_count),
    network: a.source.as_name ?? 'unknown network',
    asn: a.source.as_number ? `AS${a.source.as_number}` : '',
    range: a.source.range ?? '',
    site: site ?? '',
    duration: dur(d?.duration),
    decision: d ? `Banned for **${dur(d.duration)}**` : 'No decision',
  };
}

export const fill = (tpl: string, v: Record<string, string>) => tpl.replace(/\{(\w+)\}/g, (m, k) => v[k] ?? m);
const hex = (c: string, fb: number) => (/^#?[0-9a-f]{6}$/i.test(c) ? parseInt(c.replace('#', ''), 16) : fb);

const FIELD: Record<EmbedField, (v: Record<string, string>) => { name: string; value: string } | null> = {
  country: (v) => ({ name: 'Country', value: `${v.flag} ${v.country}` }),
  network: (v) => ({ name: 'Network', value: [v.network, v.asn].filter(Boolean).join(' · ') }),
  events: (v) => ({ name: 'Events', value: v.events }),
  decision: (v) => ({ name: 'Decision', value: v.duration ? `ban ${v.duration}` : 'none' }),
  site: (v) => (v.site ? { name: 'Site', value: v.site } : null),
  range: (v) => (v.range ? { name: 'Range', value: v.range } : null),
};

export function buildEmbed(a: Alert, e: EmbedStyle) {
  const v = vars(a);
  const base = e.linkBase.replace(/\/+$/, '');
  return {
    title: fill(e.title, v).slice(0, 256),
    url: base ? `${base}/ip/${encodeURIComponent(v.ip)}` : undefined,
    color: a.decisions?.length ? hex(e.colorBan, 0xef4444) : hex(e.colorAlert, 0xf59e0b),
    description: fill(e.description, v).slice(0, 4000) || undefined,
    fields: e.fields.map((f) => FIELD[f]?.(v)).filter(Boolean).map((f) => ({ ...f!, inline: true })),
    timestamp: e.timestamp ? a.stop_at : undefined,
    footer: e.footer ? { text: e.footer.slice(0, 2048) } : undefined,
  };
}

export async function sendDiscord(s: NotifySettings, alerts: Alert[]): Promise<void> {
  const res = await fetch(s.webhook, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: s.embed.username || 'Argos',
      avatar_url: s.embed.avatarUrl || undefined,
      content: s.mention || undefined,
      embeds: alerts.slice(0, 10).map((a) => buildEmbed(a, s.embed)),
    }),
  });
  if (!res.ok) throw new Error(`discord ${res.status}: ${(await res.text()).slice(0, 200)}`);
}

const lastIds = new Map<string, number>();

async function poll(inst: Instance): Promise<void> {
  const key = inst.id === MAIN ? 'notify.lastId' : `notify.lastId@${inst.id}`;
  const lastId = lastIds.get(inst.id) ?? getSetting<number>(key, 0);
  const alerts = await getAlerts({ since: '5m', limit: 200 });
  const fresh = alerts.filter((a) => a.id > lastId).sort((a, b) => a.id - b.id);
  if (!fresh.length) { lastIds.set(inst.id, lastId); return; }
  lastIds.set(inst.id, fresh[fresh.length - 1].id);
  setSetting(key, fresh[fresh.length - 1].id);
  if (lastId === 0) return;

  for (const a of fresh) for (const l of listeners) l(slim(a), inst.id);

  const s = notifySettings();
  const discord = s.enabled && !!s.webhook;
  if (!discord && !listChannels().some((c) => c.enabled && c.alerts)) return;
  const inc = s.scenarioInclude ? new RegExp(s.scenarioInclude) : null;
  const exc = s.scenarioExclude ? new RegExp(s.scenarioExclude) : null;
  const now = Date.now();
  const hour = Math.floor(now / 3600_000);
  if (sentThisHour.hour !== hour) sentThisHour = { hour, n: 0 };

  const pick = fresh.filter((a) => {
    if (a.scenario.startsWith('manual ')) return false;
    if (a.events_count < s.minEvents) return false;
    if (inc && !inc.test(a.scenario)) return false;
    if (exc && exc.test(a.scenario)) return false;
    const last = lastByIp.get(`${inst.id}|${a.source.value}`) ?? 0;
    return now - last >= s.cooldownMinutes * 60_000;
  });
  if (!pick.length || sentThisHour.n >= s.maxPerHour) return;
  for (const a of pick) lastByIp.set(`${inst.id}|${a.source.value}`, now);
  sentThisHour.n++;
  // with more than one crowdsec, say which one
  const many = listInstances().length > 1;
  const style = many ? { ...s, embed: { ...s.embed, footer: [s.embed.footer, inst.name].filter(Boolean).join(' · ') } } : s;
  if (discord) await sendDiscord(style, pick).catch((e) => console.error('[notifier] discord', e.message));
  const msg = alertMessage(pick);
  await broadcast('alerts', many ? { ...msg, title: `${msg.title} · ${inst.name}` } : msg, pick.map((a) => ({ ...slim(a), instance: inst.name })));
}

export async function sendDiscordDigest(msg: Message): Promise<void> {
  const s = notifySettings();
  if (!s.webhook) return;
  const res = await fetch(s.webhook, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: s.embed.username || 'Argos', avatar_url: s.embed.avatarUrl || undefined,
      embeds: [{ title: msg.title, description: msg.lines.map((l) => `• ${l}`).join('\n'), color: 0x22d3ee,
        url: s.embed.linkBase || undefined, footer: { text: 'Argos' }, timestamp: new Date().toISOString() }],
      allowed_mentions: { parse: [] },
    }),
  });
  if (!res.ok) throw new Error(`discord ${res.status}`);
}

export function startNotifier(): void {
  const tick = async () => {
    for (const i of listInstances()) await inInstance(i, () => poll(i)).catch((e) => console.error('[notifier]', i.name, e.message));
  };
  tick();
  setInterval(tick, 10_000);
}
