import { api } from './api';

const b64 = (b: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const bytes = (s: string) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));

export const passkeysSupported = () => typeof window !== 'undefined' && !!window.PublicKeyCredential;

// the browser says NotAllowedError for a cancel, a timeout or no matching key
const human = (e: any) => (e?.name === 'NotAllowedError' ? new Error('Cancelled, or no passkey for this site on this device') : e);

export async function addPasskey(name: string): Promise<void> {
  const o = await api<any>('/auth/passkey/register/options', { method: 'POST' });
  let cred: PublicKeyCredential;
  try {
    cred = (await navigator.credentials.create({
      publicKey: {
        ...o, challenge: bytes(o.challenge), user: { ...o.user, id: bytes(o.user.id) },
        excludeCredentials: o.excludeCredentials.map((x: any) => ({ ...x, id: bytes(x.id) })),
      },
    })) as PublicKeyCredential;
  } catch (e) { throw human(e); }
  const r = cred.response as AuthenticatorAttestationResponse;
  await api('/auth/passkey/register', { method: 'POST', json: { name, response: { clientDataJSON: b64(r.clientDataJSON), attestationObject: b64(r.attestationObject) } } });
}

export async function signInWithPasskey(): Promise<void> {
  const o = await api<any>('/auth/passkey/login/options', { method: 'POST' });
  let cred: PublicKeyCredential;
  try {
    cred = (await navigator.credentials.get({
      publicKey: { challenge: bytes(o.challenge), rpId: o.rpId, userVerification: 'required', timeout: o.timeout, allowCredentials: [] },
    })) as PublicKeyCredential;
  } catch (e) { throw human(e); }
  const r = cred.response as AuthenticatorAssertionResponse;
  await api('/auth/passkey/login', {
    method: 'POST',
    json: { id: cred.id, response: { clientDataJSON: b64(r.clientDataJSON), authenticatorData: b64(r.authenticatorData), signature: b64(r.signature) } },
  });
}

// a name for the new passkey from the device it is made on
export function deviceName(): string {
  const ua = navigator.userAgent;
  const os = /iPhone|iPad/.test(ua) ? 'iPhone' : /Android/.test(ua) ? 'Android' : /Mac OS X/.test(ua) ? 'Mac' : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : 'Device';
  const br = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : '';
  return br ? `${os} · ${br}` : os;
}
