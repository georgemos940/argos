import { useState } from 'react';
import { KeyRound, ShieldCheck } from 'lucide-react';
import { api, type Me } from '../api';
import { Button, ErrorBox, Field, inputCls } from '../ui';

export default function Login({ me, onDone }: { me: Me; onDone: () => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [token, setToken] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const mode = me.setup ? 'setup' : me.needsTotp ? 'totp' : 'login';

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (mode === 'setup') await api('/auth/setup', { method: 'POST', json: { token, username, password } });
      else if (mode === 'login') await api('/auth/login', { method: 'POST', json: { username, password } });
      else await api('/auth/totp', { method: 'POST', json: { code } });
      onDone();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

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
            {mode === 'setup' ? 'Create the first admin account' : mode === 'totp' ? 'Two-factor authentication' : 'Sign in to continue'}
          </p>
        </div>
        <form onSubmit={submit} className="glass space-y-4 p-6">
          {mode === 'setup' && (
            <Field label="Setup token" hint="Printed in the container log on first start (docker logs argos).">
              <input className={inputCls} value={token} onChange={(e) => setToken(e.target.value)} autoFocus />
            </Field>
          )}
          {mode !== 'totp' ? (
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
            {mode === 'totp' ? <ShieldCheck size={16} /> : <KeyRound size={16} />}
            {mode === 'setup' ? 'Create admin' : mode === 'totp' ? 'Verify' : 'Sign in'}
          </Button>
        </form>
      </div>
    </div>
  );
}
