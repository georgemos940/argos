import { current } from './instances.js';
import { CONFIG_TEST, isAllowed } from './argv.js';
import { dockerRequest, readContainerFile, writeContainerFile, type DockerTarget, type FileKind } from './docker.js';

export { isAllowed } from './argv.js';

// the current instance's argos docker proxy, or the socket for main when it has no proxy
function target(): DockerTarget {
  const i = current();
  if (i.dockerProxyUrl) return { url: i.dockerProxyUrl, token: i.dockerProxyToken };
  if (i.socket) return { socketPath: i.socket };
  throw new Error(`${i.name} has no docker proxy set, so cscli, the hub and config files are off for it`);
}
const docker = (method: string, path: string, body?: unknown) => dockerRequest(target(), method, path, body);
const container = () => current().container;

export async function restartCrowdsec(): Promise<void> {
  const r = await docker('POST', `/containers/${container()}/restart?t=20`);
  if (r.status !== 204) throw new Error(`docker restart ${r.status}: ${r.data}`);
}

const why = (r: { status: number; data: Buffer }) => {
  try { return JSON.parse(r.data.toString()).message ?? r.status; } catch { return r.status; }
};

// argos' own files in the crowdsec config: profiles.yaml and its whitelist parser
export async function readCrowdsecFile(kind: FileKind): Promise<string | null> {
  const t = target();
  if ('socketPath' in t) return readContainerFile(t, container(), kind);
  const r = await docker('GET', `/argos/files/${kind}`);
  if (r.status === 404) return null;
  if (r.status !== 200) throw new Error(`read ${kind}: ${why(r)}`);
  return JSON.parse(r.data.toString()).content;
}

export async function writeCrowdsecFile(kind: FileKind, content: string): Promise<void> {
  const t = target();
  if ('socketPath' in t) return writeContainerFile(t, container(), kind, content);
  const r = await docker('PUT', `/argos/files/${kind}`, { content });
  if (r.status !== 200) throw new Error(`write ${kind}: ${why(r)}`);
}

// crowdsec -t, throws with crowdsec's own complaint
export const testConfig = () => exec(CONFIG_TEST, false);

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
  const created = await docker('POST', `/containers/${container()}/exec`, {
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
