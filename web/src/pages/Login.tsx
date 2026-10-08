import { useEffect, useState } from 'react';
import QRCode from 'qrcode';
import { Fingerprint, KeyRound, LogIn, ShieldCheck } from 'lucide-react';
import { api, type Me } from '../api';
import { Button, ErrorBox, Field, inputCls } from '../ui';
import { addPasskey, deviceName, passkeysSupported, signInWithPasskey } from '../passkey';

export default function Login({ me, onDone }: { me: Me; onDone: () => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [token, setToken] = useState('');
  const [code, setCode] = useState('');
  // a failed sso sign-in comes back as ?sso_error=
  const [error, setError] = useState<string | null>(() => new URLSearchParams(location.search).get('sso_error'));
  const [busy, setBusy] = useState(false);
  useEffect(() => { if (location.search.includes('sso_error')) history.replaceState(null, '', location.pathname); }, []);
  const mode = me.setup ? 'setup' : me.needsTotp ? 'totp' : me.mustEnroll ? 'enroll' : 'login';
  const [enroll, setEnroll] = useState<{ secret: string; uri: string } | null>(null);
  const [qr, setQr] = useState('');
  useEffect(() => {
    if (mode !== 'enroll' || enroll) return;
    api<{ secret: string; uri: string }>('/auth/totp/enroll', { method: 'POST' }).then(setEnroll).catch((e) => setError(e.message));
  }, [mode, enroll]);
  useEffect(() => { if (enroll) QRCode.toDataURL(enroll.uri, { margin: 1, width: 200 }).then(setQr); }, [enroll]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (mode === 'setup') await api('/auth/setup', { method: 'POST', json: { token, username, password } });
      else if (mode === 'login') await api('/auth/login', { method: 'POST', json: { username, password } });
      else if (mode === 'enroll') await api('/auth/totp/confirm', { method: 'POST', json: { secret: enroll?.secret, code } });
      else await api('/auth/totp', { method: 'POST', json: { code } });
      onDone();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const passkey = async () => {
    setBusy(true);
    setError(null);
    try {
      // enrolling: a passkey counts as the second factor too
      if (mode === 'enroll') await addPasskey(deviceName());
      else await signInWithPasskey();
      onDone();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };
  const showPasskey = passkeysSupported() && mode !== 'setup';
  const showSso = !!me.sso && mode === 'login';

  return (
    <div className="grid min-h-full place-items-center p-6">
      <div className="backdrop"><div className="grid-lines" /></div>
      <div className="w-full max-w-sm animate-fade-up">
        <div className="mb-8 flex flex-col items-center text-center">
          <div className="relative">
            <div className="absolute inset-0 -m-6 rounded-full bg-gradient-to-br from-cyan-400/30 to-violet-500/30 blur-2xl glow-pulse" />
            <img src="/logo.png" className="relative h-24 w-24 drop-shadow-[0_0_28px_rgba(139,92,246,0.6)]" alt="Argos" />
          </div>
          <h1 className="mt-6 font-display text-3xl font-semibold text-white"><span className="text-gradient">Argos</span></h1>
          <p className="mt-1 text-sm text-slate-500">
            {mode === 'setup' ? 'Create the first admin account' : mode === 'totp' ? 'Two-factor authentication'
              : mode === 'enroll' ? 'This panel requires two-factor authentication' : 'Sign in to continue'}
          </p>
        </div>
        <form onSubmit={submit} className="glass space-y-4 p-6">
          {mode === 'setup' && (
            <Field label="Setup token" hint="Printed in the container log on first start (docker logs argos).">
              <input className={inputCls} value={token} onChange={(e) => setToken(e.target.value)} autoFocus />
            </Field>
          )}
          {mode === 'enroll' && (
            <div className="flex items-start gap-4">
              {qr ? <img src={qr} className="h-32 w-32 shrink-0 rounded-xl bg-white p-1.5" alt="QR code" /> : <div className="h-32 w-32 shrink-0 rounded-xl skeleton" />}
              <div className="min-w-0 text-xs text-slate-400">Scan it with an authenticator app (Google Authenticator, Authy, 1Password), or enter the key:
                <div className="mt-2 font-mono break-all text-cyan-200">{enroll?.secret ?? '…'}</div>
              </div>
            </div>
          )}
          {mode !== 'totp' && mode !== 'enroll' ? (
            <>
              <Field label="Username"><input className={inputCls} value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoFocus={mode === 'login'} /></Field>
              <Field label="Password" hint={mode === 'setup' ? 'At least 10 characters.' : undefined}>
                <input className={inputCls} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete={mode === 'setup' ? 'new-password' : 'current-password'} />
              </Field>
            </>
          ) : (
            <Field label="6-digit code from your authenticator app">
              <input className={`${inputCls} text-center font-mono text-xl tracking-[0.5em]`} value={code} inputMode="numeric" maxLength={6}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} autoFocus />
            </Field>
          )}
          <ErrorBox error={error} />
          <Button tone="primary" className="w-full" disabled={busy}>
            {mode === 'totp' || mode === 'enroll' ? <ShieldCheck size={16} /> : <KeyRound size={16} />}
            {mode === 'setup' ? 'Create admin' : mode === 'totp' ? 'Verify' : mode === 'enroll' ? 'Turn on 2FA' : 'Sign in'}
          </Button>
        </form>
        {(showPasskey || showSso) && (
          <div className="mt-4 space-y-3">
            <div className="flex items-center gap-3 text-[11px] tracking-[0.2em] text-slate-600 uppercase"><span className="h-px flex-1 bg-white/10" />or<span className="h-px flex-1 bg-white/10" /></div>
            {showSso && (
              <a href="/api/auth/sso/start" className="flex h-10 w-full items-center justify-center gap-2 rounded-xl bg-white/[0.05] text-sm font-medium text-slate-100 ring-1 ring-white/10 transition hover:bg-white/[0.09] hover:ring-white/20">
                <LogIn size={16} /> Sign in with {me.sso!.label}
              </a>
            )}
            {showPasskey && (
              <Button className="w-full" disabled={busy} onClick={passkey}>
                <Fingerprint size={16} /> {mode === 'enroll' ? 'Add a passkey instead' : mode === 'totp' ? 'Use a passkey instead' : 'Sign in with a passkey'}
              </Button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
