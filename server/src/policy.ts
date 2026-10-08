import { randomBytes } from 'node:crypto';
import { getSetting, setSetting } from './db.js';
import { scoped } from './instances.js';
import { readCrowdsecFile, restartCrowdsec, testConfig, writeCrowdsecFile } from './cscli.js';
import { lapiHealth } from './lapi.js';
import type { FileKind } from './docker.js';

export async function restartAndWait(): Promise<{ back: boolean; seconds: number }> {
  const t0 = Date.now();
  await restartCrowdsec();
  while (Date.now() - t0 < 90_000) {
    await new Promise((r) => setTimeout(r, 2000));
    if (await lapiHealth()) return { back: true, seconds: Math.round((Date.now() - t0) / 1000) };
  }
  return { back: false, seconds: 90 };
}

// crowdsec logs `level=fatal msg="..."`, the msg is the useful part
const fatal = (out: string) => /msg="((?:[^"\\]|\\.)*)"/.exec(out)?.[1].replace(/\\n.*$/, '').replace(/\\"/g, '"') ?? out;

let busy = false;

/**
 * Write one of argos' files, check it with crowdsec -t and restart into it. A file crowdsec refuses,
 * or one it does not come back up with, is swapped back for the old one.
 */
export async function applyFile(kind: FileKind, content: string, empty: string): Promise<{ changed: boolean; back: boolean; seconds: number }> {
  if (busy) throw new Error('another change is being applied, try again in a minute');
  busy = true;
  try {
    const old = await readCrowdsecFile(kind);
    if (old === content) return { changed: false, back: true, seconds: 0 };
    await writeCrowdsecFile(kind, content);
    try {
      await testConfig();
    } catch (e: any) {
      await writeCrowdsecFile(kind, old ?? empty);
      throw new Error(`crowdsec refused it, nothing changed: ${fatal(e.message)}`);
    }
    if (old !== null) setSetting(scoped(`backup.${kind}`), { content: old, at: Date.now() });
    const r = await restartAndWait();
    if (!r.back) {
      await writeCrowdsecFile(kind, old ?? empty);
      await restartAndWait();
      throw new Error('crowdsec did not come back up with it, the previous file is back in place');
    }
    return { changed: true, ...r };
  } finally {
    busy = false;
  }
}

export const backupOf = (kind: FileKind) => getSetting<{ content: string; at: number } | null>(scoped(`backup.${kind}`), null);

// ---------------------------------------------------------------- ban policy (profiles.yaml)

export const POLICY_MARK = '# managed by argos, edit it from the ban policy page';

export interface Policy {
  banHours: number;
  // repeat offenders: banHours x (previous bans + 1), up to maxHours
  escalate: boolean;
  maxHours: number;
  // http scenarios get a captcha first, a ban once they had captchaMax decisions in 24h
  captcha: boolean;
  captchaHours: number;
  captchaMax: number;
}

export const DEFAULT_POLICY: Policy = { banHours: 4, escalate: false, maxHours: 168, captcha: false, captchaHours: 4, captchaMax: 3 };

const int = (v: unknown, min: number, max: number, def: number) => {
  const n = Math.round(Number(v));
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : def;
};

export function cleanPolicy(p: any): Policy {
  const banHours = int(p?.banHours, 1, 8760, DEFAULT_POLICY.banHours);
  return {
    banHours,
    escalate: !!p?.escalate,
    maxHours: int(p?.maxHours, banHours, 8760, Math.max(banHours, DEFAULT_POLICY.maxHours)),
    captcha: !!p?.captcha,
    captchaHours: int(p?.captchaHours, 1, 720, DEFAULT_POLICY.captchaHours),
    captchaMax: int(p?.captchaMax, 1, 50, DEFAULT_POLICY.captchaMax),
  };
}

const IP = 'Alert.Remediation == true && Alert.GetScope() == "Ip"';

function profile(name: string, filter: string, type: string, hours: number, durationExpr?: string): string {
  return [
    `name: ${name}`,
    'filters:',
    ` - ${filter}`,
    'decisions:',
    ` - type: ${type}`,
    `   duration: ${hours}h`,
    ...(durationExpr ? [`duration_expr: "${durationExpr}"`] : []),
    'on_success: break',
  ].join('\n');
}

export function renderPolicy(p: Policy): string {
  const out: string[] = [];
  if (p.captcha) {
    out.push(profile('argos_http_captcha',
      `${IP} && Alert.GetScenario() contains "http" && GetDecisionsSinceCount(Alert.GetValue(), "24h") < ${p.captchaMax}`,
      'captcha', p.captchaHours));
  }
  const n = `(GetDecisionsCount(Alert.GetValue()) + 1) * ${p.banHours}`;
  out.push(profile('argos_ip_ban', IP, 'ban', p.banHours,
    p.escalate ? `Sprintf('%dh', ${n} > ${p.maxHours} ? ${p.maxHours} : ${n})` : undefined));
  out.push(profile('argos_range_ban', 'Alert.Remediation == true && Alert.GetScope() == "Range"', 'ban', p.banHours));
  return `${POLICY_MARK}\n${out.join('\n---\n')}\n`;
}

// a stock profiles.yaml still says how long a ban is
export function guessPolicy(live: string | null): Policy {
  const h = /^\s*-?\s*duration:\s*(\d+)h\s*$/m.exec(live ?? '');
  return cleanPolicy({ ...DEFAULT_POLICY, banHours: h ? Number(h[1]) : DEFAULT_POLICY.banHours });
}

// ---------------------------------------------------------------- ignore rules (whitelist parser)

export const RULES_MARK = '# managed by argos, edit it from the ignore rules page';

export const FIELDS = {
  path: 'evt.Meta.http_path',
  host: 'evt.Meta.target_fqdn',
  user_agent: 'evt.Meta.http_user_agent',
  method: 'evt.Meta.http_verb',
  status: 'evt.Meta.http_status',
} as const;

export const OPS = {
  equals: '==',
  startsWith: 'startsWith',
  endsWith: 'endsWith',
  contains: 'contains',
  regex: 'matches',
} as const;

export type Field = keyof typeof FIELDS;
export type Op = keyof typeof OPS;
export interface Condition { field: Field; op: Op; value: string }
export interface IgnoreRule { id: string; name: string; enabled: boolean; conditions: Condition[] }

export function cleanRules(input: unknown): IgnoreRule[] {
  if (!Array.isArray(input)) throw new Error('rules must be a list');
  if (input.length > 100) throw new Error('100 rules at most');
  return input.map((r: any, i) => {
    const name = String(r?.name ?? '').trim().slice(0, 80) || `rule ${i + 1}`;
    const conds = Array.isArray(r?.conditions) ? r.conditions : [];
    if (!conds.length || conds.length > 8) throw new Error(`${name}: 1 to 8 conditions`);
    const conditions = conds.map((c: any): Condition => {
      if (!(c?.field in FIELDS)) throw new Error(`${name}: unknown field ${c?.field}`);
      if (!(c?.op in OPS)) throw new Error(`${name}: unknown match ${c?.op}`);
      const value = String(c?.value ?? '');
      if (!value || value.length > 300 || /[\x00-\x1f\x7f]/.test(value)) throw new Error(`${name}: value empty, too long or has control characters`);
      // regexes are go (re2), crowdsec -t is what checks them
      return { field: c.field, op: c.op, value };
    });
    const id = /^[\w-]{1,40}$/.test(r?.id) ? r.id : randomBytes(6).toString('hex');
    return { id, name, enabled: r?.enabled !== false, conditions };
  });
}

// an expr string literal; json escapes are ones expr reads too
const lit = (v: string) => JSON.stringify(v);
// a yaml single-quoted scalar
const sq = (v: string) => `'${v.replace(/'/g, "''")}'`;

export function ruleExpr(r: IgnoreRule): string {
  return r.conditions.map((c) => `${FIELDS[c.field]} ${OPS[c.op]} ${lit(c.value)}`).join(' && ');
}

export function renderRules(rules: IgnoreRule[]): string {
  const on = rules.filter((r) => r.enabled);
  const lines = on.length ? on.map((r) => `    - ${sq(ruleExpr(r))}  # ${r.name.replace(/[\r\n]/g, ' ')}`) : ["    - 'false'"];
  return [
    RULES_MARK,
    'name: argos/ignore-rules',
    'description: "requests matching an argos ignore rule never count toward a scenario"',
    `filter: "evt.Meta.service == 'http'"`,
    'whitelist:',
    '  reason: "argos ignore rule"',
    '  expression:',
    ...lines,
    '',
  ].join('\n');
}

export const EMPTY_RULES = renderRules([]);
