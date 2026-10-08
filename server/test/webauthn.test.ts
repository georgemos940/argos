import './setup.js';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { cborDecode, verifyAssertion, verifyRegistration } from '../src/webauthn.js';

// a software authenticator: just enough cbor to write what a real one sends
function cbor(v: any): Buffer {
  const head = (major: number, n: number) => n < 24 ? Buffer.from([major << 5 | n])
    : n < 256 ? Buffer.from([major << 5 | 24, n]) : Buffer.from([major << 5 | 25, n >> 8, n & 255]);
  if (typeof v === 'number') return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (Buffer.isBuffer(v)) return Buffer.concat([head(2, v.length), v]);
  if (typeof v === 'string') return Buffer.concat([head(3, Buffer.byteLength(v)), Buffer.from(v)]);
  if (v instanceof Map) return Buffer.concat([head(5, v.size), ...[...v].flatMap(([k, x]) => [cbor(k), cbor(x)])]);
  throw new Error('cbor: type');
}
const sha = (b: Buffer | string) => createHash('sha256').update(b).digest();
const RP = 'argos.example.com';
const ORIGIN = 'https://argos.example.com';
const b64 = (b: Buffer) => b.toString('base64url');

function authenticator(kind: 'ec' | 'ed25519' = 'ec') {
  const { publicKey, privateKey } = kind === 'ec' ? generateKeyPairSync('ec', { namedCurve: 'P-256' }) : generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' }) as any;
  const cose = kind === 'ec'
    ? new Map<number, any>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]])
    : new Map<number, any>([[1, 1], [3, -8], [-1, 6], [-2, Buffer.from(jwk.x, 'base64url')]]);
  const credId = Buffer.from('cred-' + kind);
  let counter = 0;
  const data = (flags: number, extra = Buffer.alloc(0), rp = RP) => {
    const c = Buffer.alloc(4); c.writeUInt32BE(counter);
    return Buffer.concat([sha(rp), Buffer.from([flags]), c, extra]);
  };
  const client = (type: string, challenge: string, origin = ORIGIN) => Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
  return {
    credId,
    create(challenge: string, o: { flags?: number; origin?: string } = {}) {
      const len = Buffer.alloc(2); len.writeUInt16BE(credId.length);
      const att = cbor(new Map<string, any>([['fmt', 'none'], ['attStmt', new Map()], ['authData', data(o.flags ?? 0x45, Buffer.concat([Buffer.alloc(16), len, credId, cbor(cose)]))]]));
      return { clientDataJSON: b64(client('webauthn.create', challenge, o.origin)), attestationObject: b64(att) };
    },
    get(challenge: string, o: { flags?: number; bump?: number; key?: KeyObject; rp?: string } = {}) {
      counter += o.bump ?? 1;
      const ad = data(o.flags ?? 0x05, undefined, o.rp);
      const cd = client('webauthn.get', challenge);
      const msg = Buffer.concat([ad, sha(cd)]);
      const sig = kind === 'ec' ? sign('sha256', msg, o.key ?? privateKey) : sign(null, msg, o.key ?? privateKey);
      return { clientDataJSON: b64(cd), authenticatorData: b64(ad), signature: b64(sig) };
    },
  };
}

const exp = (challenge: string) => ({ challenge, origin: ORIGIN, rpId: RP });

test('cbor: the subset passkeys use', () => {
  assert.deepEqual(cborDecode(cbor(new Map<any, any>([[1, -7], ['a', Buffer.from('x')]]))).value, new Map<any, any>([[1, -7], ['a', Buffer.from('x')]]));
  assert.equal(cborDecode(cbor(-257)).value, -257);
});

for (const kind of ['ec', 'ed25519'] as const) {
  test(`passkey ${kind}: register then sign in`, () => {
    const a = authenticator(kind);
    const cred = verifyRegistration(a.create('c1'), exp('c1'));
    assert.equal(cred.id, b64(a.credId));
    const r1 = verifyAssertion(a.get('c2'), cred, exp('c2'));
    assert.equal(r1.counter, 1);
    const r2 = verifyAssertion(a.get('c3'), { ...cred, counter: r1.counter }, exp('c3'));
    assert.equal(r2.counter, 2);
  });
}

test('passkey: refused when anything is off', () => {
  const a = authenticator();
  assert.throws(() => verifyRegistration(a.create('c1', { origin: 'https://evil.example' }), exp('c1')), /made for https:\/\/evil/);
  assert.throws(() => verifyRegistration(a.create('c1'), exp('other')), /challenge/);
  assert.throws(() => verifyRegistration(a.create('c1', { flags: 0x41 }), exp('c1')), /did not verify you/);
  const cred = verifyRegistration(a.create('c1'), exp('c1'));
  assert.throws(() => verifyAssertion(a.get('c2', { rp: 'evil.example' }), cred, exp('c2')), /another site/);
  assert.throws(() => verifyAssertion(a.get('c2', { key: generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey }), cred, exp('c2')), /bad signature/);
  assert.throws(() => verifyAssertion(a.get('c2', { flags: 0x01 }), cred, exp('c2')), /did not verify you/);
  // a clone shows up as a counter that does not go up
  assert.throws(() => verifyAssertion(a.get('c2', { bump: 0 }), { ...cred, counter: 9 }, exp('c2')), /counter/);
});
