import './setup.js';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isLocal, parse, publicFetch } from '../src/blocklists.js';

const cf = { v4: [[0x68100000, 0x6817ffff]] as [number, number][], v6: ['2400:cb00::/32'] }; // 104.16.0.0/13

test('parse keeps public entries and drops comments', () => {
  const r = parse('# list\n1.2.3.4\n5.6.7.0/24 ; SBL1\n\n2001:db8::1\n', cf);
  assert.deepEqual(r.values.sort(), ['1.2.3.4', '2001:db8::1', '5.6.7.0/24'].sort());
});

test('parse never keeps private, reserved or cloudflare ranges', () => {
  const r = parse('10.0.0.0/8\n192.168.1.1\n172.20.0.5\n100.64.1.1\n127.0.0.1\n169.254.1.1\n104.16.5.5\nfe80::1\nfd00::1\n2400:cb00::1\n0.0.0.0/0\n', cf);
  assert.deepEqual(r.values, []);
  assert.equal(r.skipped, 11);
});

test('parse refuses ranges wider than /8', () => {
  assert.deepEqual(parse('1.0.0.0/7\n', cf).values, []);
});

test('isLocal spots internal addresses', () => {
  for (const a of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.0.1', '169.254.169.254', '100.82.31.61', '::1', 'fd12::1', 'fe80::1', '::ffff:10.0.0.1'])
    assert.equal(isLocal(a), true, a);
  for (const a of ['1.1.1.1', '8.8.8.8', '2606:4700::1111'])
    assert.equal(isLocal(a), false, a);
});

test('publicFetch refuses internal targets before connecting', async () => {
  for (const url of ['http://127.0.0.1/', 'http://169.254.169.254/latest/meta-data/', 'http://localhost:8080/', 'http://[::1]/', 'http://10.0.0.1/'])
    await assert.rejects(publicFetch(url), /private address/, url);
  await assert.rejects(publicFetch('file:///etc/passwd'), /http\(s\)/);
});
