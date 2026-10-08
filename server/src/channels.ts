import { createHmac, randomBytes } from 'node:crypto';
import nodemailer from 'nodemailer';
import { getSetting, setSetting } from './db.js';
import type { Alert } from './lapi.js';
import { publicFetch } from './blocklists.js';
import { recentAlerts, summarize } from './stats.js';
import { notifySettings, vars } from './notifier.js';

export type ChannelType = 'telegram' | 'slack' | 'ntfy' | 'webhook' | 'email';

export interface Channel {
  id: string;
  type: ChannelType;
  name: string;
  enabled: boolean;
  alerts: boolean;          // new attacks, same filters as discord
  digest: boolean;          // the daily / weekly summary
  config: Record<string, string>;
}

export interface DigestSettings {
  daily: boolean;
  weekly: boolean;
  hour: number;             // local hour (TZ of the container)
  weekday: number;          // 0 = sunday
  discord: boolean;         // also post it to the discord webhook
}

// which config keys hold secrets: never sent back to the browser
export const SECRET_KEYS: Record<ChannelType, string[]> = {
  telegram: ['token'], slack: ['url'], ntfy: ['token'], webhook: ['secret'], email: ['pass'],
};
const REQUIRED: Record<ChannelType, string[]> = {
  telegram: ['token', 'chatId'], slack: ['url'], ntfy: ['topic'], webhook: ['url'], email: ['host', 'from', 'to'],
};

export const defaultDigest: DigestSettings = { daily: false, weekly: true, hour: 9, weekday: 1, discord: true };
export const digestSettings = () => ({ ...defaultDigest, ...getSetting<Partial<DigestSettings>>('digest', {}) });

export const listChannels = () => getSetting<Channel[]>('channels', []);

// the browser sees which secrets are set, never the values
export function publicChannels() {
  return listChannels().map((c) => ({
    ...c,
    config: Object.fromEntries(Object.entries(c.config).map(([k, v]) => [k, SECRET_KEYS[c.type].includes(k) ? (v ? '••••••' : '') : v])),
  }));
}

export function saveChannel(input: Partial<Channel> & { type: ChannelType }): Channel {
  if (!(input.type in REQUIRED)) throw new Error('unknown channel type');
  const all = listChannels();
  const cur = all.find((c) => c.id === input.id);
  const config: Record<string, string> = { ...(cur?.config ?? {}) };
  for (const [k, v] of Object.entries(input.config ?? {})) {
    if (v === '••••••') continue;                       // untouched secret
    config[k] = String(v ?? '').trim().slice(0, 500);
  }
  for (const k of REQUIRED[input.type]) if (!config[k]) throw new Error(`${input.type}: ${k} is required`);
  if (input.type === 'slack' && !/^https:\/\/hooks\.slack\.com\/services\//.test(config.url)) throw new Error('not a Slack incoming webhook URL');
  if (input.type === 'telegram' && !/^\d+:[\w-]{30,}$/.test(config.token)) throw new Error('not a Telegram bot token');
  if (input.type === 'webhook' && !/^https?:\/\//.test(config.url)) throw new Error('webhook URL must be http(s)');
  if (input.type === 'ntfy' && config.server && !/^https?:\/\//.test(config.server)) throw new Error('ntfy server must be http(s)');
  const next: Channel = {
    id: cur?.id ?? randomBytes(6).toString('hex'),
    type: input.type,
    name: String(input.name || input.type).slice(0, 60),
    enabled: input.enabled ?? cur?.enabled ?? true,
    alerts: input.alerts ?? cur?.alerts ?? true,
    digest: input.digest ?? cur?.digest ?? true,
    config,
  };
  setSetting('channels', cur ? all.map((c) => (c.id === next.id ? next : c)) : [...all, next]);
  return next;
}

export const removeChannel = (id: string) => setSetting('channels', listChannels().filter((c) => c.id !== id));

// ---------------------------------------------------------------- messages

export interface Message { title: string; lines: string[]; link?: string; severity: 'high' | 'default' }

const linkFor = (ip: string) => {
  const base = notifySettings().embed.linkBase.replace(/\/+$/, '');
  return base ? `${base}/ip/${encodeURIComponent(ip)}` : undefined;
};

export function alertMessage(alerts: Alert[]): Message {
  const lines = alerts.slice(0, 10).map((a) => {
    const v = vars(a);
    return `${v.flag} ${v.ip} · ${v.scenario} · ${v.events} events from ${v.network}${v.site ? ` on ${v.site}` : ''}${v.duration ? ` · banned ${v.duration}` : ''}`;
  });
  if (alerts.length > 10) lines.push(`… and ${alerts.length - 10} more`);
  return {
    title: alerts.length === 1 ? `Attack from ${alerts[0].source.value}` : `${alerts.length} new attacks`,
    lines, link: alerts.length === 1 ? linkFor(alerts[0].source.value) : undefined,
    severity: alerts.some((a) => a.decisions?.length) ? 'high' : 'default',
  };
}

export async function digestMessage(window: '24h' | '7d'): Promise<{ msg: Message; stats: ReturnType<typeof summarize> }> {
  const alerts = await recentAlerts(window);
  const s = summarize(alerts, window);
  const bans = alerts.filter((a) => a.decisions?.length).length;
  const busiest = [...s.timeline].sort((a, b) => b.alerts - a.alerts)[0];
  const top = (list: { key: string; count: number }[], n = 3) => list.slice(0, n).map((x) => `${x.key} (${x.count})`).join(', ') || 'none';
  const regions = new Intl.DisplayNames(['en'], { type: 'region' });
  return {
    stats: s,
    msg: {
      title: `Argos ${window === '24h' ? 'daily' : 'weekly'} summary`,
      severity: 'default',
      lines: [
        `${s.totals.alerts} attacks from ${s.totals.uniqueIps} IPs, ${bans} led to a ban`,
        `Top countries: ${s.countries.slice(0, 3).map((x) => `${(() => { try { return regions.of(x.key); } catch { return x.key; } })()} (${x.count})`).join(', ') || 'none'}`,
        `Top attacks: ${top(s.scenarios.map((x) => ({ ...x, key: x.key.replace(/^crowdsecurity\//, '') })))}`,
        `Sites hit most: ${top(s.sites)}`,
        busiest && busiest.alerts ? `Busiest ${window === '24h' ? 'hour' : 'period'}: ${new Date(busiest.t).toLocaleString('en-GB', { weekday: 'short', hour: '2-digit', minute: '2-digit' })} with ${busiest.alerts}` : 'Quiet period',
      ],
    },
  };
}

// ---------------------------------------------------------------- senders

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

async function ok(res: Response, what: string) {
  if (!res.ok) throw new Error(`${what} ${res.status}: ${(await res.text()).slice(0, 160)}`);
}

export async function send(ch: Channel, msg: Message, payload: unknown): Promise<void> {
  const c = ch.config;
  const text = [msg.title, ...msg.lines, ...(msg.link ? [msg.link] : [])].join('\n');
  switch (ch.type) {
    case 'telegram': {
      const html = [`<b>${esc(msg.title)}</b>`, ...msg.lines.map(esc), ...(msg.link ? [`<a href="${esc(msg.link)}">open in Argos</a>`] : [])].join('\n');
      const res = await fetch(`https://api.telegram.org/bot${c.token}/sendMessage`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: c.chatId, text: html, parse_mode: 'HTML', disable_web_page_preview: true }),
      });
      return ok(res, 'telegram');
    }
    case 'slack': {
      const res = await fetch(c.url, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: [`*${esc(msg.title)}*`, ...msg.lines.map(esc), ...(msg.link ? [`<${msg.link}|open in Argos>`] : [])].join('\n') }),
      });
      return ok(res, 'slack');
    }
    case 'ntfy': {
      const server = (c.server || 'https://ntfy.sh').replace(/\/+$/, '');
      const headers: Record<string, string> = { Title: msg.title, Tags: 'shield', Priority: msg.severity === 'high' ? 'high' : 'default' };
      if (msg.link) headers.Click = msg.link;
      if (c.token) headers.Authorization = `Bearer ${c.token}`;
      const res = await publicFetch(`${server}/${encodeURIComponent(c.topic)}`, { method: 'POST', headers, body: msg.lines.join('\n') });
      return ok(res, 'ntfy');
    }
    case 'webhook': {
      const body = JSON.stringify({ source: 'argos', title: msg.title, lines: msg.lines, link: msg.link, data: payload, sentAt: new Date().toISOString() });
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      // receivers check the body with the shared secret: hex hmac-sha256
      if (c.secret) headers['X-Argos-Signature'] = `sha256=${createHmac('sha256', c.secret).update(body).digest('hex')}`;
      const res = await publicFetch(c.url, { method: 'POST', headers, body });
      return ok(res, 'webhook');
    }
    case 'email': {
      const transport = nodemailer.createTransport({
        host: c.host, port: Number(c.port || 587), secure: c.port === '465',
        auth: c.user ? { user: c.user, pass: c.pass } : undefined,
        disableFileAccess: true, disableUrlAccess: true,
      });
      await transport.sendMail({ from: c.from, to: c.to, subject: msg.title, text });
      return;
    }
  }
}

export async function broadcast(kind: 'alerts' | 'digest', msg: Message, payload: unknown): Promise<string[]> {
  const errors: string[] = [];
  for (const ch of listChannels().filter((x) => x.enabled && x[kind])) {
    await send(ch, msg, payload).catch((e) => { errors.push(`${ch.name}: ${e.message}`); console.error('[channels]', ch.name, e.message); });
  }
  return errors;
}

// ---------------------------------------------------------------- digest schedule

export async function sendDigest(window: '24h' | '7d', sendDiscordDigest: (m: Message, s: ReturnType<typeof summarize>) => Promise<void>): Promise<string[]> {
  const { msg, stats } = await digestMessage(window);
  const errors = await broadcast('digest', msg, { window, totals: stats.totals, countries: stats.countries.slice(0, 10), scenarios: stats.scenarios, sites: stats.sites });
  if (digestSettings().discord) await sendDiscordDigest(msg, stats).catch((e) => errors.push(`discord: ${e.message}`));
  return errors;
}

export function startDigest(sendDiscordDigest: (m: Message, s: ReturnType<typeof summarize>) => Promise<void>): void {
  const tick = async () => {
    const d = digestSettings();
    const now = new Date();
    if (now.getHours() !== d.hour) return;
    const day = now.toISOString().slice(0, 10);
    const sent = getSetting<{ daily?: string; weekly?: string }>('digest.sent', {});
    if (d.daily && sent.daily !== day) {
      setSetting('digest.sent', { ...sent, daily: day });
      await sendDigest('24h', sendDiscordDigest);
    } else if (d.weekly && now.getDay() === d.weekday && sent.weekly !== day) {
      setSetting('digest.sent', { ...sent, weekly: day });
      await sendDigest('7d', sendDiscordDigest);
    }
  };
  setInterval(() => tick().catch((e) => console.error('[digest]', e.message)), 5 * 60_000).unref();
}
