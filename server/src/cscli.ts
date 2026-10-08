import { request } from 'node:http';
import { config } from './config.js';

function docker(method: string, path: string, body?: unknown): Promise<{ status: number; data: Buffer }> {
  return new Promise((resolve, reject) => {
    const req = request(
      { socketPath: config.dockerSocket, method, path, headers: { 'Content-Type': 'application/json' } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (d) => chunks.push(d));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, data: Buffer.concat(chunks) }));
      },
    );
    req.on('error', reject);
    req.setTimeout(60_000, () => req.destroy(new Error('docker timeout')));
    if (body !== undefined) req.write(JSON.stringify(body));
    req.end();
  });
}

// the docker socket is root, so only these commands go through
// hub items are author/name, nothing that looks like a path
const ITEM = String.raw`[A-Za-z0-9][\w.-]*\/[A-Za-z0-9][\w-]*(?:\.[\w-]+)*`;

const ALLOWED: RegExp[] = [
  /^(bouncers|machines) list$/,
  /^(hub) (list|update|upgrade)( --dry-run| -a)?$/,
  new RegExp(`^simulation (status|enable|disable)( ${ITEM}| --global)?$`),
  /^console (status|enable|disable)( [\w-]+)?$/,
  /^console enroll [\w-]{10,64} --name [\w.-]{1,64}$/,
  /^metrics show appsec$/,
  new RegExp(`^(scenarios|collections|parsers|postoverflows|contexts|appsec-rules|appsec-configs) (list|inspect|install|remove)( ${ITEM})?$`),
  /^allowlists (list|inspect|create|add|remove|delete)( [\w.:/-]+)*( --(description|expiration|comment) .+)?$/,
  /^metrics( show [\w,-]+)?$/,
  /^decisions list$/,
];

export const isAllowed = (line: string) => ALLOWED.some((re) => re.test(line));

export async function restartCrowdsec(): Promise<void> {
  const r = await docker('POST', `/containers/${config.crowdsecContainer}/restart?t=20`);
  if (r.status !== 204) throw new Error(`docker restart ${r.status}: ${r.data}`);
}

export interface HubPlanItem { type: string; name: string; from?: string; to?: string }

// parses the "Action plan:" block of `hub upgrade --dry-run`
export function parsePlan(out: string): { steps: { action: string; items: HubPlanItem[] }[]; dataFiles: boolean } {
  const lines = out.replace(/\r/g, '').split('\n');
  const start = lines.findIndex((l) => l.startsWith('Action plan'));
  const steps: { action: string; items: HubPlanItem[] }[] = [];
  let dataFiles = false;
  if (start < 0) return { steps, dataFiles };
  for (const l of lines.slice(start + 1)) {
    if (!l.trim() || l.startsWith('Dry run')) continue;
    const item = /^\s+([a-z-]+):\s+(.+)$/.exec(l);
    if (item && steps.length) {
      for (const part of item[2].split(/,\s+(?=[\w.-]+\/)/)) {
        const m = /^(\S+)(?:\s+\((\S*)\s*->\s*(\S+)\))?/.exec(part.trim());
        if (m) steps[steps.length - 1].items.push({ type: item[1], name: m[1], from: m[2] || undefined, to: m[3] });
      }
    } else if (!l.startsWith(' ')) {
      const action = l.replace(/^[^\p{L}]+/u, '').trim();
      if (/data files/.test(action)) dataFiles = true;
      else steps.push({ action, items: [] });
    }
  }
  return { steps: steps.filter((s) => s.items.length), dataFiles };
}

export async function cscli(args: string[], json = true): Promise<any> {
  const line = args.join(' ');
  if (!isAllowed(line)) throw new Error(`cscli command not allowed: ${line}`);
  return exec(['cscli', ...args, ...(json ? ['-o', 'json'] : []), '--color', 'no'], json);
}

// log line goes in as one argv entry, no shell
export async function explain(log: string, type: string): Promise<string> {
  if (!/^[\w-]{1,40}$/.test(type)) throw new Error('bad log type');
  if (!log.trim() || log.length > 8000 || /[\r\n]/.test(log)) throw new Error('paste a single log line (max 8000 chars)');
  const out = String(await exec(['cscli', 'explain', '--log', log, '--type', type, '--color', 'no'], false));
  // ignores --color no
  return out.replace(/\u001b\[[0-9;]*m/g, '');
}

// first start: add our own lapi machine. -f /dev/null keeps cscli off crowdsec's own credentials file
export async function registerMachine(user: string, password: string): Promise<void> {
  if (!/^[\w.-]{1,64}$/.test(user) || !/^[!-~]{16,128}$/.test(password)) throw new Error('LAPI_USER or LAPI_PASSWORD not usable for auto registration (password 16+ chars)');
  await exec(['cscli', 'machines', 'add', user, '--password', password, '-f', '/dev/null', '--force', '--color', 'no'], false);
}

export interface Simulation { global: boolean; scenarios: string[] }

export async function simulationStatus(): Promise<Simulation> {
  const out = String(await cscli(['simulation', 'status'], false));
  return {
    global: /global simulation:\s*enabled/i.test(out),
    scenarios: [...out.matchAll(/^\s*-\s*(\S+)/gm)].map((m) => m[1]),
  };
}

async function exec(cmd: string[], json: boolean): Promise<any> {
  const created = await docker('POST', `/containers/${config.crowdsecContainer}/exec`, {
    AttachStdout: true, AttachStderr: true, Tty: true, Cmd: cmd,
  });
  if (created.status !== 201) throw new Error(`docker exec create ${created.status}: ${created.data}`);
  const { Id } = JSON.parse(created.data.toString());
  const run = await docker('POST', `/exec/${Id}/start`, { Detach: false, Tty: true });
  const out = run.data.toString();
  const info = JSON.parse((await docker('GET', `/exec/${Id}/json`)).data.toString());
  if (info.ExitCode !== 0) throw new Error(out.trim().split('\n').slice(-3).join(' ') || `cscli exit ${info.ExitCode}`);
  if (!json) return out;
  const start = out.search(/[[{]/);
  return start < 0 ? null : JSON.parse(out.slice(start));
}
