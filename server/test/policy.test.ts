import './setup.js';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULT_POLICY, EMPTY_RULES, POLICY_MARK, cleanPolicy, cleanRules, guessPolicy, renderPolicy, renderRules, ruleExpr } from '../src/policy.js';

test('policy: flat ban like the stock file', () => {
  const y = renderPolicy(DEFAULT_POLICY);
  assert.ok(y.startsWith(POLICY_MARK));
  assert.match(y, /name: argos_ip_ban\nfilters:\n - Alert.Remediation == true && Alert.GetScope\(\) == "Ip"\ndecisions:\n - type: ban\n   duration: 4h\non_success: break/);
  assert.match(y, /name: argos_range_ban/);
  assert.doesNotMatch(y, /captcha|duration_expr/);
});

test('policy: escalation and captcha', () => {
  const y = renderPolicy(cleanPolicy({ banHours: 6, escalate: true, maxHours: 72, captcha: true, captchaHours: 2, captchaMax: 3 }));
  assert.match(y, /duration_expr: "Sprintf\('%dh', \(GetDecisionsCount\(Alert.GetValue\(\)\) \+ 1\) \* 6 > 72 \? 72 : \(GetDecisionsCount\(Alert.GetValue\(\)\) \+ 1\) \* 6\)"/);
  assert.match(y, /Alert.GetScenario\(\) contains "http" && GetDecisionsSinceCount\(Alert.GetValue\(\), "24h"\) < 3\ndecisions:\n - type: captcha\n   duration: 2h/);
  // captcha comes first, profiles stop at the first match
  assert.ok(y.indexOf('argos_http_captcha') < y.indexOf('argos_ip_ban'));
});

test('policy: numbers are clamped, never text', () => {
  const p = cleanPolicy({ banHours: '4h; rm -rf', maxHours: 1, captchaMax: 999 });
  assert.equal(p.banHours, 4);
  assert.equal(p.maxHours, 4);
  assert.equal(p.captchaMax, 50);
  assert.equal(guessPolicy('decisions:\n - type: ban\n   duration: 12h\n').banHours, 12);
});

test('ignore rules: quotes cannot break out of the expression or the yaml', () => {
  const [r] = cleanRules([{ name: 'x', conditions: [{ field: 'user_agent', op: 'contains', value: `it's "bad" \\ ok` }] }]);
  assert.equal(ruleExpr(r), 'evt.Meta.http_user_agent contains "it\'s \\"bad\\" \\\\ ok"');
  const y = renderRules([r]);
  assert.ok(y.includes(`    - 'evt.Meta.http_user_agent contains "it''s \\"bad\\" \\\\ ok"'  # x`));
});

test('ignore rules: and-ed conditions, disabled rules left out', () => {
  const rules = cleanRules([
    { name: 'api', conditions: [{ field: 'host', op: 'equals', value: 'app.example.com' }, { field: 'path', op: 'startsWith', value: '/api/' }] },
    { name: 'off', enabled: false, conditions: [{ field: 'status', op: 'equals', value: '404' }] },
  ]);
  const y = renderRules(rules);
  assert.match(y, /evt.Meta.target_fqdn == "app.example.com" && evt.Meta.http_path startsWith "\/api\/"/);
  assert.doesNotMatch(y, /http_status/);
  assert.match(y, /filter: "evt.Meta.service == 'http'"/);
  assert.match(EMPTY_RULES, /- 'false'/);
});

test('ignore rules: bad input refused', () => {
  assert.throws(() => cleanRules([{ name: 'a', conditions: [{ field: 'ip', op: 'equals', value: '1.2.3.4' }] }]), /unknown field/);
  assert.throws(() => cleanRules([{ name: 'a', conditions: [{ field: 'path', op: 'exec', value: '/' }] }]), /unknown match/);
  assert.throws(() => cleanRules([{ name: 'a', conditions: [{ field: 'path', op: 'equals', value: '/a\n- true' }] }]), /control/);
  assert.throws(() => cleanRules([{ name: 'a', conditions: [] }]), /1 to 8/);
  assert.throws(() => cleanRules([{ name: 'a', conditions: [{ field: 'path', op: 'equals', value: '' }] }]), /empty/);
});
