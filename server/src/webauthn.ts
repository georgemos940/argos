import { createHash, createPublicKey, verify, type KeyObject } from 'node:crypto';

// passkeys without a library: the cbor subset webauthn uses, cose keys, and the two ceremonies.
// attestation is not checked (we ask for none), what matters is the key, the challenge, the origin and user verification

class Cbor {
  constructor(private b: Buffer, public pos = 0) {}
  private len(info: number): number {
    if (info < 24) return info;
    const p = this.pos;
    if (info === 24) { this.pos += 1; return this.b[p]; }
    if (info === 25) { this.pos += 2; return this.b.readUInt16BE(p); }
    if (info === 26) { this.pos += 4; return this.b.readUInt32BE(p); }
    if (info === 27) { this.pos += 8; return Number(this.b.readBigUInt64BE(p)); }
    throw new Error('cbor: indefinite length');
  }
  read(): any {
    if (this.pos >= this.b.length) throw new Error('cbor: truncated');
    const ib = this.b[this.pos++];
    const major = ib >> 5;
    const info = ib & 31;
    switch (major) {
      case 0: return this.len(info);
      case 1: return -1 - this.len(info);
      case 2: { const n = this.len(info); const v = this.b.subarray(this.pos, this.pos + n); this.pos += n; return Buffer.from(v); }
      case 3: { const n = this.len(info); const v = this.b.toString('utf8', this.pos, this.pos + n); this.pos += n; return v; }
      case 4: { const n = this.len(info); return Array.from({ length: n }, () => this.read()); }
      case 5: { const n = this.len(info); const m = new Map(); for (let i = 0; i < n; i++) { const k = this.read(); m.set(k, this.read()); } return m; }
      case 6: this.len(info); return this.read();
      default:
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22 || info === 23) return null;
        if (info === 26) { this.pos += 4; return this.b.readFloatBE(this.pos - 4); }
        if (info === 27) { this.pos += 8; return this.b.readDoubleBE(this.pos - 8); }
        throw new Error('cbor: unsupported value');
    }
  }
}
export const cborDecode = (b: Buffer, pos = 0) => { const r = new Cbor(b, pos); return { value: r.read(), end: r.pos }; };

const sha256 = (b: Buffer | string) => createHash('sha256').update(b).digest();
const b64u = (s: unknown, what: string) => {
  if (typeof s !== 'string' || !/^[\w-]*={0,2}$/.test(s)) throw new Error(`passkey: bad ${what}`);
  return Buffer.from(s, 'base64url');
};

// cose_key -> node key. es256, eddsa, rs256 cover every authenticator out there
export function coseToKey(m: Map<number, any>): { key: KeyObject; alg: number } {
  const kty = m.get(1);
  const alg = m.get(3);
  const enc = (b: Buffer) => b.toString('base64url');
  if (kty === 2 && alg === -7 && m.get(-1) === 1) return { alg, key: createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: enc(m.get(-2)), y: enc(m.get(-3)) }, format: 'jwk' }) };
  if (kty === 1 && alg === -8 && m.get(-1) === 6) return { alg, key: createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: enc(m.get(-2)) }, format: 'jwk' }) };
  if (kty === 3 && alg === -257) return { alg, key: createPublicKey({ key: { kty: 'RSA', n: enc(m.get(-1)), e: enc(m.get(-2)) }, format: 'jwk' }) };
  throw new Error(`passkey: unsupported key (kty ${kty}, alg ${alg})`);
}

interface AuthData { rpIdHash: Buffer; up: boolean; uv: boolean; counter: number; credId?: Buffer; cose?: Map<number, any> }
export function parseAuthData(a: Buffer): AuthData {
  if (a.length < 37) throw new Error('passkey: short authenticator data');
  const flags = a[32];
  const out: AuthData = { rpIdHash: a.subarray(0, 32), up: !!(flags & 0x01), uv: !!(flags & 0x04), counter: a.readUInt32BE(33) };
  if (flags & 0x40) {
    const n = a.readUInt16BE(53);
    out.credId = a.subarray(55, 55 + n);
    out.cose = cborDecode(a, 55 + n).value;
  }
  return out;
}

export interface Expect { challenge: string; origin: string; rpId: string }

function checkClient(raw: Buffer, type: string, exp: Expect) {
  const cd = JSON.parse(raw.toString('utf8'));
  if (cd.type !== type) throw new Error('passkey: wrong ceremony');
  if (cd.challenge !== exp.challenge) throw new Error('passkey: challenge mismatch');
  if (cd.origin !== exp.origin) throw new Error(`passkey: made for ${cd.origin}, this is ${exp.origin}`);
}

function checkAuth(ad: AuthData, exp: Expect) {
  if (!ad.rpIdHash.equals(sha256(exp.rpId))) throw new Error('passkey: made for another site');
  if (!ad.up || !ad.uv) throw new Error('passkey: the authenticator did not verify you (PIN or biometrics)');
}

export function verifyRegistration(r: { clientDataJSON: unknown; attestationObject: unknown }, exp: Expect) {
  checkClient(b64u(r.clientDataJSON, 'client data'), 'webauthn.create', exp);
  const att = cborDecode(b64u(r.attestationObject, 'attestation')).value as Map<string, any>;
  const ad = parseAuthData(att.get('authData'));
  checkAuth(ad, exp);
  if (!ad.credId || !ad.cose) throw new Error('passkey: no credential in the response');
  const { key, alg } = coseToKey(ad.cose);
  return { id: ad.credId.toString('base64url'), publicKey: (key.export({ type: 'spki', format: 'der' }) as Buffer).toString('base64'), alg, counter: ad.counter };
}

export function verifyAssertion(
  r: { clientDataJSON: unknown; authenticatorData: unknown; signature: unknown },
  cred: { publicKey: string; alg: number; counter: number }, exp: Expect,
): { counter: number } {
  const client = b64u(r.clientDataJSON, 'client data');
  checkClient(client, 'webauthn.get', exp);
  const raw = b64u(r.authenticatorData, 'authenticator data');
  const ad = parseAuthData(raw);
  checkAuth(ad, exp);
  const key = createPublicKey({ key: Buffer.from(cred.publicKey, 'base64'), format: 'der', type: 'spki' });
  const data = Buffer.concat([raw, sha256(client)]);
  const sig = b64u(r.signature, 'signature');
  const ok = cred.alg === -8 ? verify(null, data, key, sig) : verify('sha256', data, key, sig);
  if (!ok) throw new Error('passkey: bad signature');
  // both zero means the authenticator does not count; otherwise it only goes up, or the key was cloned
  if ((ad.counter || cred.counter) && ad.counter <= cred.counter) throw new Error('passkey: counter went back, possible cloned key');
  return { counter: ad.counter };
}
