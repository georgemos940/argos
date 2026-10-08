import { useEffect, useState } from 'react';
import QRCode from 'qrcode';
import { KeyRound, ShieldCheck, Trash2, UserPlus, Users } from 'lucide-react';
import { api, type Me } from '../api';
import { can } from '../App';
import { Badge, Button, Card, ErrorBox, Field, Modal, SkeletonList, ago, ask, inputCls, toast, useAsync } from '../ui';

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
        {admin && <UsersCard me={me.user!.username} />}
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

function UsersCard({ me }: { me: string }) {
  const { data, reload } = useAsync(() => api<{ id: number; username: string; role: string; totp: number; created_at: number }[]>('/users'), []);
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
      {!data && <SkeletonList rows={3} avatar />}
      <ul className="divide-y divide-white/5">
        {(data ?? []).map((u) => (
          <li key={u.id} className="flex items-center justify-between gap-3 py-2.5">
            <div>
              <div className="flex items-center gap-2 text-sm text-white">{u.username}{u.totp ? <ShieldCheck size={13} className="text-emerald-400" /> : null}</div>
              <div className="text-xs text-slate-500">added {ago(u.created_at)}</div>
            </div>
            <div className="flex items-center gap-2">
              <select className={`${inputCls} w-28`} value={u.role} disabled={u.username === me} onChange={(e) => patch(u.id, { role: e.target.value })}>
                <option value="viewer">viewer</option><option value="operator">operator</option><option value="admin">admin</option>
              </select>
              {!!u.totp && u.username !== me && <Button tone="ghost" onClick={() => patch(u.id, { resetTotp: true })}>Reset 2FA</Button>}
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
