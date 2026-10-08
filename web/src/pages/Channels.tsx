import { useEffect, useState } from 'react';
import { CalendarClock, Loader2, Mail, MessageCircle, Plus, Radio, Send, Slack, Trash2, Webhook } from 'lucide-react';
import { api } from '../api';
import { Badge, Button, Card, Field, Modal, SkeletonList, Switch, ask, cx, inputCls, toast, useAsync } from '../ui';

type Type = 'telegram' | 'slack' | 'ntfy' | 'webhook' | 'email';
interface Channel { id: string; type: Type; name: string; enabled: boolean; alerts: boolean; digest: boolean; config: Record<string, string> }

const TYPES: Record<Type, { label: string; icon: typeof Send; fields: { k: string; label: string; hint?: string; secret?: boolean; placeholder?: string }[] }> = {
  telegram: { label: 'Telegram', icon: Send, fields: [
    { k: 'token', label: 'Bot token', secret: true, hint: 'From @BotFather.', placeholder: '123456:ABC…' },
    { k: 'chatId', label: 'Chat id', hint: 'Your user id, a group (-100…) or a channel. Send the bot a message first.', placeholder: '-1001234567890' }] },
  slack: { label: 'Slack', icon: Slack, fields: [
    { k: 'url', label: 'Incoming webhook URL', secret: true, placeholder: 'https://hooks.slack.com/services/…' }] },
  ntfy: { label: 'ntfy (phone push)', icon: Radio, fields: [
    { k: 'topic', label: 'Topic', hint: 'Subscribe to the same topic in the ntfy app. Pick something hard to guess.', placeholder: 'argos-7f3k2' },
    { k: 'server', label: 'Server', hint: 'Empty = ntfy.sh', placeholder: 'https://ntfy.sh' },
    { k: 'token', label: 'Access token', secret: true, hint: 'Only for a protected topic.' }] },
  webhook: { label: 'Webhook (JSON)', icon: Webhook, fields: [
    { k: 'url', label: 'URL', placeholder: 'https://example.com/hooks/argos' },
    { k: 'secret', label: 'Signing secret', secret: true, hint: 'Optional. Sent as X-Argos-Signature: sha256=<hmac of the body>.' }] },
  email: { label: 'Email (SMTP)', icon: Mail, fields: [
    { k: 'host', label: 'SMTP host', placeholder: 'smtp.example.com' }, { k: 'port', label: 'Port', placeholder: '587' },
    { k: 'user', label: 'User' }, { k: 'pass', label: 'Password', secret: true },
    { k: 'from', label: 'From', placeholder: 'argos@example.com' }, { k: 'to', label: 'To', hint: 'Comma separated.', placeholder: 'you@example.com' }] },
};

export function ChannelsCard() {
  const { data, reload } = useAsync(() => api<Channel[]>('/channels'), []);
  const [list, setList] = useState<Channel[] | null>(null);
  const [edit, setEdit] = useState<Partial<Channel> | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  useEffect(() => setList(null), [data]);
  const all = list ?? data;

  const save = async (ch: Partial<Channel>) => { setList(await api<Channel[]>('/channels', { method: 'PUT', json: ch })); };
  const toggle = async (ch: Channel, k: 'enabled' | 'alerts' | 'digest', v: boolean) => {
    try { await save({ ...ch, [k]: v }); } catch (e: any) { toast(e.message, 'err'); reload(); }
  };
  const test = async (ch: Channel) => {
    setBusy(ch.id);
    try { await api(`/channels/${ch.id}/test`, { method: 'POST' }); toast(`Test sent to ${ch.name}`); }
    catch (e: any) { toast(e.message, 'err'); }
    finally { setBusy(null); }
  };
  const del = async (ch: Channel) => {
    if (!await ask({ title: `Remove ${ch.name}?`, tone: 'danger', confirmLabel: 'Remove' })) return;
    setList(await api<Channel[]>(`/channels/${ch.id}`, { method: 'DELETE' }));
  };

  return (
    <Card title="Other channels" icon={<MessageCircle size={15} />} hover={false}
      subtitle="Telegram, Slack, ntfy, email or your own webhook. Alerts use the same filters and limits as Discord; the summary goes out on its schedule."
      actions={<Button onClick={() => setEdit({ type: 'telegram', enabled: true, alerts: true, digest: true, config: {} })}><Plus size={14} /> Add</Button>}>
      {!all && <SkeletonList rows={3} />}
      {all && !all.length && <div className="rounded-xl bg-white/[0.02] p-4 text-sm text-slate-500 ring-1 ring-white/5">No channels yet. Discord above always works on its own.</div>}
      <div className="space-y-2">
        {(all ?? []).map((ch) => {
          const T = TYPES[ch.type];
          return (
            <div key={ch.id} className={cx('flex flex-wrap items-center gap-3 rounded-xl p-3 ring-1 transition', ch.enabled ? 'bg-ink-950/50 ring-white/[0.07]' : 'opacity-60 ring-white/5')}>
              <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-gradient-to-br from-cyan-400/20 to-violet-500/20 text-cyan-200 ring-1 ring-white/10"><T.icon size={16} /></span>
              <div className="min-w-0 flex-1">
                <button className="truncate text-left text-sm font-medium text-white hover:underline" onClick={() => setEdit(ch)}>{ch.name}</button>
                <div className="text-xs text-slate-500">{T.label}</div>
              </div>
              <label className="flex items-center gap-1.5 text-[11px] text-slate-400">alerts <Switch checked={ch.alerts} onChange={(v) => toggle(ch, 'alerts', v)} label="Alerts" /></label>
              <label className="flex items-center gap-1.5 text-[11px] text-slate-400">summary <Switch checked={ch.digest} onChange={(v) => toggle(ch, 'digest', v)} label="Summary" /></label>
              <label className="flex items-center gap-1.5 text-[11px] text-slate-400">on <Switch checked={ch.enabled} onChange={(v) => toggle(ch, 'enabled', v)} label="Enabled" /></label>
              <div className="flex gap-1">
                <Button tone="ghost" disabled={busy === ch.id} onClick={() => test(ch)}>{busy === ch.id ? <Loader2 size={14} className="animate-spin" /> : <Send size={14} />}</Button>
                <Button tone="ghost" onClick={() => del(ch)}><Trash2 size={14} /></Button>
              </div>
            </div>
          );
        })}
      </div>
      <ChannelModal value={edit} onClose={() => setEdit(null)} onSave={async (ch) => { await save(ch); setEdit(null); toast('Channel saved'); }} />
    </Card>
  );
}

function ChannelModal({ value, onClose, onSave }: { value: Partial<Channel> | null; onClose: () => void; onSave: (c: Partial<Channel>) => Promise<void> }) {
  const [ch, setCh] = useState<Partial<Channel>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => { if (value) { setCh(value); setError(null); } }, [value]);
  if (!value) return null;
  const T = TYPES[(ch.type ?? 'telegram') as Type];
  const submit = async () => {
    setBusy(true); setError(null);
    try { await onSave(ch); } catch (e: any) { setError(e.message); } finally { setBusy(false); }
  };
  return (
    <Modal open={!!value} onClose={onClose} title={value.id ? `Edit ${value.name}` : 'Add a channel'}>
      <div className="space-y-4">
        {!value.id && (
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
            {(Object.keys(TYPES) as Type[]).map((t) => {
              const X = TYPES[t];
              return (
                <button key={t} type="button" onClick={() => setCh({ ...ch, type: t, config: {} })}
                  className={cx('flex items-center gap-2 rounded-xl px-3 py-2.5 text-xs font-medium ring-1 transition',
                    ch.type === t ? 'bg-cyan-400/10 text-white ring-cyan-400/50' : 'text-slate-400 ring-white/10 hover:text-white')}>
                  <X.icon size={14} />{X.label}
                </button>
              );
            })}
          </div>
        )}
        <Field label="Name"><input className={inputCls} value={ch.name ?? ''} onChange={(e) => setCh({ ...ch, name: e.target.value })} placeholder={T.label} /></Field>
        {T.fields.map((f) => (
          <Field key={f.k} label={f.label} hint={f.hint}>
            <input className={inputCls} type={f.secret ? 'password' : 'text'} placeholder={f.placeholder} value={ch.config?.[f.k] ?? ''}
              onChange={(e) => setCh({ ...ch, config: { ...(ch.config ?? {}), [f.k]: e.target.value } })} />
          </Field>
        ))}
        {error && <div className="rounded-lg bg-rose-500/10 px-3 py-2 text-sm text-rose-300 ring-1 ring-rose-500/30">{error}</div>}
        <div className="flex justify-end gap-2">
          <Button tone="ghost" onClick={onClose}>Cancel</Button>
          <Button tone="primary" disabled={busy} onClick={submit}>{busy && <Loader2 size={14} className="animate-spin" />} Save</Button>
        </div>
      </div>
    </Modal>
  );
}

const DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

export function DigestCard() {
  const [window, setWindow] = useState<'24h' | '7d'>('7d');
  const { data, reload } = useAsync(() => api<{ settings: { daily: boolean; weekly: boolean; hour: number; weekday: number; discord: boolean };
    preview: { title: string; lines: string[] } }>(`/digest?window=${window}`), [window]);
  const [sending, setSending] = useState(false);
  const s = data?.settings;
  const set = async (patch: object) => {
    try { await api('/digest', { method: 'PUT', json: patch }); reload(); } catch (e: any) { toast(e.message, 'err'); }
  };
  const sendNow = async () => {
    setSending(true);
    try {
      const r = await api<{ ok: boolean; errors: string[] }>('/digest/send', { method: 'POST', json: { window } });
      toast(r.ok ? 'Summary sent' : `Sent, with errors: ${r.errors.join('; ')}`, r.ok ? 'ok' : 'err');
    } catch (e: any) { toast(e.message, 'err'); }
    finally { setSending(false); }
  };

  return (
    <Card title="Summary" icon={<CalendarClock size={15} />} hover={false} subtitle="A short report of what happened: attacks, bans, top countries, attacks and sites.">
      {!s ? <SkeletonList rows={3} /> : (
        <div className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="flex items-center justify-between rounded-xl bg-white/[0.02] px-4 py-3 ring-1 ring-white/5">
              <span className="text-sm text-slate-200">Daily</span><Switch checked={s.daily} onChange={(v) => set({ daily: v })} label="Daily" />
            </div>
            <div className="flex items-center justify-between rounded-xl bg-white/[0.02] px-4 py-3 ring-1 ring-white/5">
              <span className="text-sm text-slate-200">Weekly</span><Switch checked={s.weekly} onChange={(v) => set({ weekly: v })} label="Weekly" />
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2 text-sm text-slate-400">
            at
            <div className="w-24"><select className={inputCls} value={s.hour} onChange={(e) => set({ hour: Number(e.target.value) })}>
              {Array.from({ length: 24 }, (_, h) => <option key={h} value={h}>{String(h).padStart(2, '0')}:00</option>)}
            </select></div>
            weekly on
            <div className="w-36"><select className={inputCls} value={s.weekday} onChange={(e) => set({ weekday: Number(e.target.value) })}>
              {DAYS.map((d, i) => <option key={d} value={i}>{d}</option>)}
            </select></div>
            <label className="ml-auto flex items-center gap-2">also to Discord <Switch checked={s.discord} onChange={(v) => set({ discord: v })} label="Discord" /></label>
          </div>
          <div className="rounded-xl bg-ink-950/60 p-4 ring-1 ring-white/5">
            <div className="mb-2 flex items-center justify-between">
              <span className="text-sm font-semibold text-white">{data.preview.title}</span>
              <div className="flex rounded-lg bg-white/5 p-0.5 text-[11px]">
                {(['24h', '7d'] as const).map((w) => (
                  <button key={w} onClick={() => setWindow(w)} className={cx('rounded-md px-2.5 py-1', window === w ? 'bg-white/10 text-white' : 'text-slate-500')}>{w === '24h' ? 'daily' : 'weekly'}</button>
                ))}
              </div>
            </div>
            <ul className="space-y-1 text-sm text-slate-300">{data.preview.lines.map((l, i) => <li key={i}>• {l}</li>)}</ul>
          </div>
          <div className="flex items-center justify-between gap-3">
            <Badge tone="violet">sent to Discord{s.discord ? '' : ' (off)'} and every channel with “summary” on</Badge>
            <Button onClick={sendNow} disabled={sending}>{sending ? <Loader2 size={14} className="animate-spin" /> : <Send size={14} />} Send now</Button>
          </div>
        </div>
      )}
    </Card>
  );
}
