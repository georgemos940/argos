import { randomBytes, timingSafeEqual } from 'node:crypto';
import { getSetting, setSetting } from './db.js';

// grafana's discord integration only fills the embed title, so build the embeds here

export interface RelayState { webhook: string; token: string; lastAt: number | null; lastStatus: string | null; sent: number }

export function relayState(): RelayState {
  const s = getSetting<RelayState>('grafana.relay', { webhook: '', token: '', lastAt: null, lastStatus: null, sent: 0 });
  if (!s.token) { s.token = randomBytes(24).toString('hex'); setSetting('grafana.relay', s); }
  return s;
}

export function setRelayWebhook(url: string): void {
  if (url && !/^https:\/\/(discord|discordapp)\.com\/api\/webhooks\//.test(url)) throw new Error('not a Discord webhook URL');
  setSetting('grafana.relay', { ...relayState(), webhook: url });
}

export function checkToken(header: string | undefined): boolean {
  const want = Buffer.from(`Bearer ${relayState().token}`);
  const got = Buffer.from(header ?? '');
  return got.length === want.length && timingSafeEqual(got, want);
}

interface GrafanaAlert {
  status: 'firing' | 'resolved';
  labels: Record<string, string>;
  annotations: Record<string, string>;
  startsAt: string; endsAt: string;
  values?: Record<string, number> | null;
  valueString?: string;
  dashboardURL?: string; panelURL?: string; silenceURL?: string; generatorURL?: string;
}
export interface GrafanaPayload { status: string; alerts: GrafanaAlert[]; externalURL?: string }

const COLOR = { critical: 0xef4444, warning: 0xf59e0b, info: 0x3b82f6, resolved: 0x22c55e };
const HIDDEN = new Set(['alertname', 'grafana_folder', 'severity', 'team', '__alert_rule_uid__', '__name__']);
const ts = (iso: string) => Math.floor(new Date(iso).getTime() / 1000);
const real = (iso?: string) => !!iso && !iso.startsWith('0001');

function embed(a: GrafanaAlert) {
  const sev = (a.labels.severity ?? 'info') as keyof typeof COLOR;
  const resolved = a.status === 'resolved';
  const name = a.labels.alertname ?? 'Alert';
  const subject = Object.entries(a.labels).filter(([k]) => !HIDDEN.has(k)).map(([, v]) => v)[0];

  const fields: { name: string; value: string; inline?: boolean }[] = [
    { name: 'Status', value: resolved ? 'Resolved' : sev === 'critical' ? 'Critical' : sev === 'warning' ? 'Warning' : 'Firing', inline: true },
    { name: resolved ? 'Lasted' : 'Since', value: resolved && real(a.endsAt) ? `<t:${ts(a.startsAt)}:t> → <t:${ts(a.endsAt)}:t>` : `<t:${ts(a.startsAt)}:R>`, inline: true },
  ];
  const values = Object.entries(a.values ?? {});
  if (values.length && !resolved) {
    fields.push({ name: 'Value', value: values.map(([k, v]) => `\`${k}\` ${Number.isInteger(v) ? v : v.toFixed(2)}`).join('  '), inline: true });
  }
  const labels = Object.entries(a.labels).filter(([k]) => !HIDDEN.has(k));
  if (labels.length) fields.push({ name: 'Labels', value: labels.map(([k, v]) => `\`${k}\`  ${v}`).join('\n').slice(0, 1000) });
  const links = [
    a.panelURL && `[Panel](${a.panelURL})`, a.dashboardURL && `[Dashboard](${a.dashboardURL})`,
    !resolved && a.silenceURL && `[Silence](${a.silenceURL})`, a.generatorURL && `[Rule](${a.generatorURL})`,
  ].filter(Boolean);
  if (links.length) fields.push({ name: 'Open', value: links.join(' · ') });

  const summary = a.annotations.summary ?? '';
  const description = a.annotations.description ?? '';
  return {
    title: `${resolved ? 'RESOLVED' : sev.toUpperCase()} · ${name}${subject ? ` · ${subject}` : ''}`.slice(0, 256),
    url: a.panelURL || a.dashboardURL || a.generatorURL || undefined,
    color: resolved ? COLOR.resolved : COLOR[sev] ?? COLOR.info,
    description: [summary && `**${summary}**`, !resolved && description].filter(Boolean).join('\n\n').slice(0, 4000) || undefined,
    fields,
    footer: { text: `Grafana · ${a.labels.grafana_folder ?? 'alerts'}` },
    timestamp: resolved && real(a.endsAt) ? a.endsAt : a.startsAt,
  };
}

export async function relay(p: GrafanaPayload): Promise<number> {
  const s = relayState();
  if (!s.webhook) throw new Error('no Discord webhook set for Grafana alerts');
  // firing first, 10 embeds per message max
  const order = (a: GrafanaAlert) => (a.status === 'resolved' ? 3 : a.labels.severity === 'critical' ? 0 : a.labels.severity === 'warning' ? 1 : 2);
  const alerts = [...p.alerts].sort((a, b) => order(a) - order(b));
  for (let i = 0; i < alerts.length; i += 10) {
    const res = await fetch(s.webhook, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'Grafana Alerts', embeds: alerts.slice(i, i + 10).map(embed), allowed_mentions: { parse: [] } }),
    });
    if (!res.ok) throw new Error(`discord ${res.status}: ${(await res.text()).slice(0, 200)}`);
  }
  setSetting('grafana.relay', { ...relayState(), lastAt: Date.now(), lastStatus: p.status, sent: s.sent + alerts.length });
  return alerts.length;
}

export const SAMPLE: GrafanaPayload = {
  status: 'firing',
  alerts: [{
    status: 'firing',
    labels: { alertname: 'Container restarting', name: 'panel-api', severity: 'critical', team: 'ops', grafana_folder: 'Alerts' },
    annotations: { summary: 'Container panel-api restarted 4 times in 15 m', description: 'Crash loop. Check: docker logs panel-api' },
    startsAt: new Date(Date.now() - 6 * 60_000).toISOString(), endsAt: '0001-01-01T00:00:00Z',
    values: { A: 4 },
    dashboardURL: 'https://grafana.example.com/d/containers', panelURL: 'https://grafana.example.com/d/containers?viewPanel=21',
    silenceURL: 'https://grafana.example.com/alerting/silence/new',
  }],
};
