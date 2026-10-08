import './setup.js';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isAllowed, parsePlan } from '../src/cscli.js';

test('allow-list lets the panel commands through', () => {
  for (const line of ['bouncers list', 'machines list', 'hub list', 'hub list -a', 'hub upgrade --dry-run', 'collections install crowdsecurity/nginx',
    'scenarios remove crowdsecurity/ssh-bf', 'simulation enable crowdsecurity/http-probing', 'simulation disable --global', 'metrics',
    'allowlists add trusted 1.2.3.4 --comment office', 'console enable custom'])
    assert.equal(isAllowed(line), true, line);
});

test('allow-list refuses everything else', () => {
  for (const line of ['machines add evil --password x', 'machines delete localhost', 'bouncers add evil', 'bouncers delete traefik',
    'decisions delete --all', 'decisions import -i /tmp/x', 'lapi register', 'capi register', 'config show', 'hub list; rm -rf /',
    'collections install ../../etc', 'console enroll short --name x', 'explain --file /etc/shadow'])
    assert.equal(isAllowed(line), false, line);
});

test('parsePlan reads the upgrade plan', () => {
  const out = 'level=info msg=x\nAction plan:\n📥 download\n parsers: crowdsecurity/nginx-logs (1.5 -> 1.6), crowdsecurity/sshd-logs (2.0 -> 2.1)\n scenarios: crowdsecurity/http-probing (0.4 -> 0.5)\n🔄 check & update data files\n\nDry run, no action taken.\n';
  const p = parsePlan(out);
  assert.equal(p.dataFiles, true);
  assert.equal(p.steps.length, 1);
  assert.deepEqual(p.steps[0].items.map((i) => `${i.type}:${i.name}:${i.from}->${i.to}`), [
    'parsers:crowdsecurity/nginx-logs:1.5->1.6', 'parsers:crowdsecurity/sshd-logs:2.0->2.1', 'scenarios:crowdsecurity/http-probing:0.4->0.5',
  ]);
});

test('parsePlan with nothing to do', () => {
  assert.deepEqual(parsePlan('Action plan:\n🔄 check & update data files\n\nDry run, no action taken.').steps, []);
  assert.deepEqual(parsePlan('').steps, []);
});
