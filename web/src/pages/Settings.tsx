import { useEffect, useState } from 'react';
import QRCode from 'qrcode';
import { Check, Copy, Fingerprint, KeyRound, KeySquare, LogIn, Plus, ShieldCheck, Trash2, UserPlus, Users } from 'lucide-react';
import { addPasskey, deviceName, passkeysSupported } from '../passkey';
import { api, type Me } from '../api';
import { can } from '../App';
import { Badge, Button, Card, Empty, ErrorBox, Field, Modal, SkeletonList, Switch, ago, ask, inputCls, toast, useAsync } from '../ui';

export default function Settings({ me, reload }: { me: Me; reload: () => void }) {
  const admin = can(me.user!.role, 'admin');
  return (
    <div className="space-y-7">
      <div>
        <h1 className="font-display text-3xl font-semibold text-white sm:text-[34px]">Settings</h1>
        <p className="mt-2 max-w-2xl text-sm text-slate-400">Your account, two-factor authentication{admin && ', users and integrations'}.</p>
          <div className="hairline mt-4 w-40" />
      </div>
      <div className="grid gap-6 xl:grid-cols-2">
        <Password />
        <TwoFactor enabled={me.user!.totp} reload={reload} />
        <Passkeys reload={reload} />
        {me.sso && <SsoLink me={me} reload={reload} />}
        {admin && <UsersCard me={me.user!.username} />}
        {admin && <Tokens />}
        {admin && <SsoSetup />}
        {admin && <Integrations />}
      </div>
    </div>
  );
}

function Password() {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [error, setError] = useState<string | null>(null);
  const save = async () => {
    try { await api('/auth/password', { method: 'POST', json: { current, next } }); toast('Password changed'); setCurrent(''); setNext(''); setError(null); }
    catch (e: any) { setError(e.message); }
  };
  return (
    <Card title="Password" icon={<KeyRound size={16} />}>
      <div className="space-y-4">
        <Field label="Current password"><input type="password" className={inputCls} value={current} onChange={(e) => setCurrent(e.target.value)} /></Field>
        <Field label="New password" hint="At least 10 characters."><input type="password" className={inputCls} value={next} onChange={(e) => setNext(e.target.value)} /></Field>
        <ErrorBox error={error} />
        <div className="flex justify-end"><Button tone="primary" onClick={save}>Change</Button></div>
      </div>
    </Card>
  );
}

function TwoFactor({ enabled, reload }: { enabled: boolean; reload: () => void }) {
  const [enroll, setEnroll] = useState<{ secret: string; uri: string } | null>(null);
  const [qr, setQr] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { if (enroll) QRCode.toDataURL(enroll.uri, { margin: 1, width: 220 }).then(setQr); }, [enroll]);

  const start = async () => setEnroll(await api('/auth/totp/enroll', { method: 'POST' }));
  const confirm2 = async () => {
    try { await api('/auth/totp/confirm', { method: 'POST', json: { secret: enroll!.secret, code } }); toast('2FA enabled'); setEnroll(null); setCode(''); reload(); }
    catch (e: any) { setError(e.message); }
  };
  const disable = async () => {
    const c = await ask({
      title: 'Turn off 2FA?', tone: 'danger', confirmLabel: 'Turn off',
      body: 'Signing in will only need your password. Confirm with a code from your authenticator app.',
      input: { label: 'Code from the app', placeholder: '123456', mono: true, maxLength: 6 },
    });
    if (!c) return;
    try { await api('/auth/totp/disable', { method: 'POST', json: { code: c } }); toast('2FA disabled'); reload(); }
    catch (e: any) { toast(e.message, 'err'); }
  };

  return (
    <Card title="Two-factor authentication" icon={<ShieldCheck size={16} />}>
      <p className="mb-4 text-sm text-slate-400">A code from an authenticator app (Google Authenticator, Authy, 1Password) on every sign-in.</p>
      {enabled ? (
        <div className="flex items-center justify-between"><Badge tone="emerald"><ShieldCheck size={12} /> enabled</Badge><Button tone="ghost" onClick={disable}>Turn off</Button></div>
      ) : !enroll ? (
        <Button tone="primary" onClick={start}>Set up 2FA</Button>
      ) : (
        <div className="space-y-4">
          <div className="flex items-start gap-5">
            {qr && <img src={qr} className="rounded-xl bg-white p-2" alt="QR code" />}
            <div className="text-sm text-slate-400">Scan the code, or enter this key by hand:<div className="mt-2 font-mono text-xs break-all text-cyan-200">{enroll.secret}</div></div>
          </div>
          <Field label="Code from the app">
            <input className={`${inputCls} font-mono tracking-[0.4em]`} maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} />
          </Field>
          <ErrorBox error={error} />
          <div className="flex justify-end"><Button tone="primary" onClick={confirm2}>Enable</Button></div>
        </div>
      )}
    </Card>
  );
}

function Passkeys({ reload: reloadMe }: { reload: () => void }) {
  const { data, reload } = useAsync(() => api<{ id: string; name: string; created_at: number; last_used_at: number | null }[]>('/auth/passkeys'), []);
  const [busy, setBusy] = useState(false);
  const add = async () => {
    setBusy(true);
    try { await addPasskey(deviceName()); toast('Passkey added'); reload(); reloadMe(); }
    catch (e: any) { toast(e.message, 'err'); }
    finally { setBusy(false); }
  };
  const remove = async (p: { id: string; name: string }) => {
    if (!await ask({ title: `Remove ${p.name}?`, body: 'You can no longer sign in with it. Remove it from the device too.', tone: 'danger', confirmLabel: 'Remove' })) return;
    await api(`/auth/passkeys/${encodeURIComponent(p.id)}`, { method: 'DELETE' });
    toast('Passkey removed');
    reload();
  };
  return (
    <Card title="Passkeys" icon={<Fingerprint size={16} />} actions={passkeysSupported() && <Button disabled={busy} onClick={add}><Plus size={14} /> Add</Button>}>
      <p className="mb-3 text-sm text-slate-400">Sign in with your fingerprint, face or device PIN instead of a password and code. Phishing can't steal one.</p>
      {!passkeysSupported() && <p className="text-xs text-amber-300">This browser does not support passkeys.</p>}
      {!data && <SkeletonList rows={1} />}
      {data && !data.length && <Empty>No passkeys yet</Empty>}
      <ul className="divide-y divide-white/5">
        {(data ?? []).map((p) => (
          <li key={p.id} className="flex items-center justify-between gap-3 py-2.5">
            <div>
              <div className="text-sm text-white">{p.name}</div>
              <div className="text-xs text-slate-500">added {ago(p.created_at)} · {p.last_used_at ? `used ${ago(p.last_used_at)}` : 'not used yet'}</div>
            </div>
            <Button tone="ghost" onClick={() => remove(p)}><Trash2 size={14} /></Button>
          </li>
        ))}
      </ul>
    </Card>
  );
}

function UsersCard({ me }: { me: string }) {
  const { data, reload } = useAsync(() => api<{ id: number; username: string; role: string; totp: number; passkeys: number; sso: number; email: string | null; created_at: number }[]>('/users'), []);
  const sec = useAsync(() => api<{ require2fa: boolean }>('/settings'), []);
  const setRequire2fa = async (v: boolean) => {
    try { await api('/settings', { method: 'PUT', json: { require2fa: v } }); toast(v ? '2FA is now required for everyone' : '2FA is optional again'); sec.reload(); }
    catch (e: any) { toast(e.message, 'err'); }
  };
  const [open, setOpen] = useState(false);
  const patch = async (id: number, body: object) => { await api(`/users/${id}`, { method: 'PATCH', json: body }); toast('Updated'); reload(); };
  const del = async (id: number, name: string) => {
    if (!await ask({ title: `Delete ${name}?`, body: 'The account is removed and can no longer sign in.', tone: 'danger', confirmLabel: 'Delete user' })) return;
    await api(`/users/${id}`, { method: 'DELETE' });
    toast('Deleted');
    reload();
  };
  return (
    <Card title="Users" icon={<Users size={16} />} actions={<Button onClick={() => setOpen(true)}><UserPlus size={14} /> Add</Button>}>
      <p className="mb-3 text-xs text-slate-500">viewer: read only · operator: ban, unban, allowlists, Cloudflare · admin: everything</p>
      <div className="mb-4 flex items-center justify-between gap-4 rounded-xl bg-white/[0.02] px-4 py-3 ring-1 ring-white/5">
        <div>
          <div className="text-sm text-slate-100">Require 2FA for everyone</div>
          <div className="text-xs text-slate-500">Accounts without it must set it up at their next sign-in before they can see anything.</div>
        </div>
        <Switch checked={!!sec.data?.require2fa} onChange={setRequire2fa} label="Require 2FA" />
      </div>
      {!data && <SkeletonList rows={3} avatar />}
      <ul className="divide-y divide-white/5">
        {(data ?? []).map((u) => (
          <li key={u.id} className="flex items-center justify-between gap-3 py-2.5">
            <div>
              <div className="flex items-center gap-2 text-sm text-white">{u.username}{u.totp ? <ShieldCheck size={13} className="text-emerald-400" /> : null}
                {u.passkeys ? <span title={`${u.passkeys} passkey${u.passkeys > 1 ? 's' : ''}`}><Fingerprint size={13} className="text-cyan-300" /></span> : null}
                {u.sso ? <span title={`SSO${u.email ? ` · ${u.email}` : ''}`}><LogIn size={13} className="text-violet-300" /></span> : null}</div>
              <div className="text-xs text-slate-500">added {ago(u.created_at)}</div>
            </div>
            <div className="flex items-center gap-2">
              <select className={`${inputCls} w-28`} value={u.role} disabled={u.username === me} onChange={(e) => patch(u.id, { role: e.target.value })}>
                <option value="viewer">viewer</option><option value="operator">operator</option><option value="admin">admin</option>
              </select>
              {!!u.totp && u.username !== me && <Button tone="ghost" onClick={() => patch(u.id, { resetTotp: true })}>Reset 2FA</Button>}
              {!!u.sso && u.username !== me && <Button tone="ghost" onClick={() => patch(u.id, { unlinkSso: true })}>Unlink SSO</Button>}
              {u.username !== me && <Button tone="ghost" onClick={() => del(u.id, u.username)}><Trash2 size={14} /></Button>}
            </div>
          </li>
        ))}
      </ul>
      <NewUser open={open} onClose={() => setOpen(false)} onDone={reload} />
    </Card>
  );
}

function NewUser({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: () => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('viewer');
  const [error, setError] = useState<string | null>(null);
  const save = async () => {
    try { await api('/users', { method: 'POST', json: { username, password, role } }); toast(`Added ${username}`); setUsername(''); setPassword(''); onClose(); onDone(); }
    catch (e: any) { setError(e.message); }
  };
  return (
    <Modal open={open} onClose={onClose} title="Add user">
      <div className="space-y-4">
        <Field label="Username"><input className={inputCls} value={username} onChange={(e) => setUsername(e.target.value)} /></Field>
        <Field label="Password" hint="At least 10 characters. They can change it after signing in."><input type="password" className={inputCls} value={password} onChange={(e) => setPassword(e.target.value)} /></Field>
        <Field label="Role">
          <select className={inputCls} value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="viewer">viewer</option><option value="operator">operator</option><option value="admin">admin</option>
          </select>
        </Field>
        <ErrorBox error={error} />
        <div className="flex justify-end"><Button tone="primary" onClick={save}>Add</Button></div>
      </div>
    </Modal>
  );
}

function Integrations() {
  const { data, reload } = useAsync(() => api<{ ctiKeySet: boolean; abuseKeySet: boolean; repMode: string }>('/settings'), []);
  const [cti, setCti] = useState('');
  const [abuse, setAbuse] = useState('');
  const save = async (json: object) => { await api('/settings', { method: 'PUT', json }); toast('Saved'); setCti(''); setAbuse(''); reload(); };
  const modes = [
    { v: 'auto', label: 'Auto', hint: 'CrowdSec CTI first, AbuseIPDB when CTI hits its limit' },
    { v: 'cti', label: 'CrowdSec CTI only', hint: '' },
    { v: 'abuseipdb', label: 'AbuseIPDB only', hint: '' },
  ];
  return (
    <Card title="IP reputation" subtitle="Shown on every IP page. Results are cached for 24 hours to save quota." className="xl:col-span-2">
      <div className="grid gap-6 lg:grid-cols-3">
        <Field label="Source">
          <div className="space-y-2">
            {modes.map((m) => (
              <label key={m.v} className={`flex cursor-pointer items-start gap-3 rounded-xl p-3 ring-1 transition ${data?.repMode === m.v ? 'bg-cyan-500/10 ring-cyan-400/40' : 'ring-white/10 hover:ring-white/20'}`}>
                <input type="radio" name="repmode" className="mt-1" checked={data?.repMode === m.v} onChange={() => save({ repMode: m.v })} />
                <span><span className="text-sm text-slate-100">{m.label}</span>{m.hint && <span className="block text-xs text-slate-500">{m.hint}</span>}</span>
              </label>
            ))}
          </div>
        </Field>
        <Field label="CrowdSec CTI key" hint="Free at app.crowdsec.net → Settings → CTI API keys. Behaviours and history from the whole CrowdSec network.">
          <div className="flex gap-2">
            <input className={inputCls} type="password" value={cti} onChange={(e) => setCti(e.target.value)} placeholder={data?.ctiKeySet ? '•••••• saved' : 'CTI API key'} />
            <Button tone="primary" disabled={!cti} onClick={() => save({ ctiKey: cti })}>Save</Button>
          </div>
        </Field>
        <Field label="AbuseIPDB key" hint="Free at abuseipdb.com → Account → API (1,000 checks/day). Abuse score, reports, ISP, usage type, Tor.">
          <div className="flex gap-2">
            <input className={inputCls} type="password" value={abuse} onChange={(e) => setAbuse(e.target.value)} placeholder={data?.abuseKeySet ? '•••••• saved' : 'AbuseIPDB API key'} />
            <Button tone="primary" disabled={!abuse} onClick={() => save({ abuseKey: abuse })}>Save</Button>
          </div>
        </Field>
      </div>
    </Card>
  );
}

interface Token { id: number; name: string; prefix: string; role: string; created_by: string; created_at: number; expires_at: number | null; last_used_at: number | null; last_ip: string | null }

function Tokens() {
  const { data, reload } = useAsync(() => api<Token[]>('/tokens'), []);
  const [open, setOpen] = useState(false);
  const revoke = async (t: Token) => {
    if (!await ask({ title: `Revoke ${t.name}?`, body: 'Anything still using this token gets a 401 from now on.', tone: 'danger', confirmLabel: 'Revoke' })) return;
    await api(`/tokens/${t.id}`, { method: 'DELETE' });
    toast(`${t.name} revoked`);
    reload();
  };
  return (
    <Card title="API tokens" icon={<KeySquare size={16} />} actions={<Button onClick={() => setOpen(true)}><Plus size={14} /> New token</Button>}>
      <p className="mb-3 text-xs text-slate-500">For scripts and other tools: <code className="text-slate-300">Authorization: Bearer argos_…</code> on any <code className="text-slate-300">/api</code> route. Viewer or operator, never admin.</p>
      {!data && <SkeletonList rows={2} />}
      {data && !data.length && <Empty>No tokens yet</Empty>}
      <ul className="divide-y divide-white/5">
        {(data ?? []).map((t) => {
          const expired = !!t.expires_at && t.expires_at < Date.now();
          return (
            <li key={t.id} className="flex items-center justify-between gap-3 py-2.5">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2 text-sm text-white">
                  {t.name}<Badge tone={t.role === 'operator' ? 'violet' : 'slate'}>{t.role}</Badge>{expired && <Badge tone="rose">expired</Badge>}
                </div>
                <div className="truncate text-xs text-slate-500">
                  <span className="font-mono">{t.prefix}…</span> · {t.last_used_at ? `used ${ago(t.last_used_at)} from ${t.last_ip}` : 'never used'}
                  {t.expires_at && !expired && ` · expires in ${Math.ceil((t.expires_at - Date.now()) / 86400_000)}d`}
                </div>
              </div>
              <Button tone="ghost" onClick={() => revoke(t)}><Trash2 size={14} /></Button>
            </li>
          );
        })}
      </ul>
      <NewToken open={open} onClose={() => setOpen(false)} onDone={reload} />
    </Card>
  );
}

function NewToken({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState('');
  const [role, setRole] = useState('viewer');
  const [days, setDays] = useState('90');
  const [token, setToken] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const close = () => { setToken(null); setName(''); setError(null); setCopied(false); onClose(); };
  const create = async () => {
    try { const r = await api<{ token: string }>('/tokens', { method: 'POST', json: { name, role, days: Number(days) } }); setToken(r.token); onDone(); }
    catch (e: any) { setError(e.message); }
  };
  const copy = () => { navigator.clipboard?.writeText(token!).then(() => setCopied(true)).catch(() => {}); };
  return (
    <Modal open={open} onClose={close} title={token ? 'Copy your token' : 'New API token'}>
      {token ? (
        <div className="space-y-4">
          <p className="text-sm text-slate-400">This is the only time it is shown. Argos keeps a hash, not the token.</p>
          <div className="flex gap-2">
            <code className="min-w-0 flex-1 rounded-xl bg-ink-950/70 px-3.5 py-2.5 font-mono text-xs break-all text-cyan-200 ring-1 ring-white/10">{token}</code>
            <Button onClick={copy}>{copied ? <Check size={14} /> : <Copy size={14} />}</Button>
          </div>
          <pre className="scroll-thin overflow-x-auto rounded-xl bg-ink-950/70 p-3 font-mono text-[11px] leading-relaxed text-slate-400 ring-1 ring-white/[0.06]">{`curl -H "Authorization: Bearer ${token}" \\
  ${location.origin}/api/decisions`}</pre>
          <div className="flex justify-end"><Button tone="primary" onClick={close}>Done</Button></div>
        </div>
      ) : (
        <div className="space-y-4">
          <Field label="Name" hint="What uses it, e.g. home-assistant or nightly-report."><input className={inputCls} value={name} onChange={(e) => setName(e.target.value)} /></Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Role">
              <select className={inputCls} value={role} onChange={(e) => setRole(e.target.value)}>
                <option value="viewer">viewer (read only)</option><option value="operator">operator (ban, unban)</option>
              </select>
            </Field>
            <Field label="Expires">
              <select className={inputCls} value={days} onChange={(e) => setDays(e.target.value)}>
                <option value="30">in 30 days</option><option value="90">in 90 days</option><option value="365">in a year</option><option value="0">never</option>
              </select>
            </Field>
          </div>
          <ErrorBox error={error} />
          <div className="flex justify-end"><Button tone="primary" disabled={!name.trim()} onClick={create}>Create</Button></div>
        </div>
      )}
    </Modal>
  );
}

interface Sso {
  enabled: boolean; issuer: string; clientId: string; clientSecret: string; label: string; allowedDomains: string; autoCreate: boolean;
  defaultRole: string; groupsClaim: string; adminGroup: string; operatorGroup: string; viewerGroup: string; redirectUri: string;
}

function SsoLink({ me, reload }: { me: Me; reload: () => void }) {
  const unlink = async () => {
    if (!await ask({ title: 'Unlink SSO?', body: `You will sign in with your password${me.passkeys ? ' or a passkey' : ''} only.`, tone: 'danger', confirmLabel: 'Unlink' })) return;
    await api('/auth/sso/unlink', { method: 'POST' });
    toast('SSO unlinked');
    reload();
  };
  return (
    <Card title="Single sign-on" icon={<LogIn size={16} />}>
      <p className="mb-4 text-sm text-slate-400">Sign in through {me.sso!.label} instead of a password.</p>
      {me.ssoLinked
        ? <div className="flex items-center justify-between"><Badge tone="emerald"><Check size={12} /> linked to {me.sso!.label}</Badge><Button tone="ghost" onClick={unlink}>Unlink</Button></div>
        : <a href="/api/auth/sso/start?link=1" className="inline-flex items-center gap-2 rounded-xl bg-white/[0.05] px-3.5 py-2 text-sm font-medium text-slate-100 ring-1 ring-white/10 transition hover:bg-white/[0.09]"><LogIn size={15} /> Link my {me.sso!.label} account</a>}
    </Card>
  );
}

function SsoSetup() {
  const { data, reload } = useAsync(() => api<Sso>('/sso'), []);
  const [f, setF] = useState<Sso | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  useEffect(() => { if (data) setF(data); }, [data]);
  const set = (patch: Partial<Sso>) => setF((x) => (x ? { ...x, ...patch } : x));
  const save = async () => {
    setBusy(true); setError(null);
    try { await api('/sso', { method: 'PUT', json: f }); toast(f!.enabled ? 'SSO is on' : 'SSO saved'); reload(); }
    catch (e: any) { setError(e.message); }
    finally { setBusy(false); }
  };
  const test = async () => {
    setBusy(true); setError(null);
    try { const r = await api<{ issuer: string }>('/sso/test', { method: 'POST', json: { issuer: f!.issuer } }); toast(`Found ${r.issuer}`); }
    catch (e: any) { setError(e.message); }
    finally { setBusy(false); }
  };
  if (!f) return <Card title="Single sign-on (OpenID Connect)" icon={<LogIn size={16} />} className="xl:col-span-2"><SkeletonList rows={3} /></Card>;
  const input = (k: keyof Sso, label: string, hint?: string, ph?: string, type = 'text') => (
    <Field label={label} hint={hint}><input type={type} className={inputCls} value={String(f[k] ?? '')} placeholder={ph} onChange={(e) => set({ [k]: e.target.value } as Partial<Sso>)} /></Field>
  );
  return (
    <Card title="Single sign-on (OpenID Connect)" icon={<LogIn size={16} />} className="xl:col-span-2"
      subtitle="Authentik, Keycloak, Authelia, Pocket ID, Google, Entra ID, Okta… anything with OpenID discovery."
      actions={<Switch checked={f.enabled} onChange={(v) => set({ enabled: v })} label="SSO" />}>
      <div className="mb-5 flex flex-wrap items-center gap-2 rounded-xl bg-ink-950/50 px-4 py-3 text-xs text-slate-400 ring-1 ring-white/[0.05]">
        Redirect URI to register at the provider:
        <code className="font-mono text-cyan-200">{f.redirectUri}</code>
        <button onClick={() => navigator.clipboard?.writeText(f.redirectUri).then(() => setCopied(true))} className="rounded-md p-1 text-slate-500 hover:text-white">{copied ? <Check size={13} /> : <Copy size={13} />}</button>
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        {input('issuer', 'Issuer URL', 'Where /.well-known/openid-configuration lives.', 'https://auth.example.com/application/o/argos/')}
        {input('clientId', 'Client ID')}
        {input('clientSecret', 'Client secret', undefined, undefined, 'password')}
        {input('label', 'Button label', 'Sign in with …', 'Authentik')}
        {input('allowedDomains', 'Allowed email domains', 'Comma separated. Empty lets anyone the provider signs in.', 'example.com')}
        <Field label="People without an account here">
          <select className={inputCls} value={f.autoCreate ? f.defaultRole : 'none'} onChange={(e) => set(e.target.value === 'none' ? { autoCreate: false } : { autoCreate: true, defaultRole: e.target.value })}>
            <option value="none">are refused (link accounts in Settings)</option>
            <option value="viewer">get an account as viewer</option>
            <option value="operator">get an account as operator</option>
          </select>
        </Field>
        {input('groupsClaim', 'Groups claim', 'Optional. When set, the provider decides the role on every sign-in.', 'groups')}
        {input('adminGroup', 'Admin group', undefined, 'argos-admins')}
        {input('operatorGroup', 'Operator group', undefined, 'argos-operators')}
        {input('viewerGroup', 'Viewer group', 'Empty: anyone else in is a viewer. Set: only this group.', 'argos-viewers')}
      </div>
      <p className="mt-4 text-xs text-slate-500">An SSO sign-in counts as two-factor here; enforce MFA at the provider.</p>
      <ErrorBox error={error} />
      <div className="mt-4 flex justify-end gap-2">
        <Button tone="ghost" disabled={busy || !f.issuer} onClick={test}>Test discovery</Button>
        <Button tone="primary" disabled={busy} onClick={save}>Save</Button>
      </div>
    </Card>
  );
}
