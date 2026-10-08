import { AsyncLocalStorage } from 'node:async_hooks';
import type { MiddlewareHandler } from 'hono';
import { config } from './config.js';
import { getSetting, setAuditInstance, setSetting } from './db.js';

// several crowdsec servers behind one argos. "main" comes from the env, the rest from settings.
// every api request runs inside one instance; lapi, cscli and prometheus calls read it from here

export interface Instance {
  id: string;
  name: string;
  lapiUrl: string;
  lapiUser: string;
  lapiPassword: string;
  // cscli, hub, policy files: through that server's argos-docker-proxy. empty turns those features off
  dockerProxyUrl: string;
  dockerProxyToken: string;
  container: string;
  promUrl: string;
  autoRegister?: boolean;
  socket?: string;
}

export const MAIN = 'main';

const main = (): Instance => ({
  id: MAIN, name: config.instanceName, lapiUrl: config.lapiUrl, lapiUser: config.lapiUser, lapiPassword: config.lapiPassword,
  dockerProxyUrl: config.dockerProxyUrl, dockerProxyToken: config.dockerProxyToken, container: config.crowdsecContainer, promUrl: config.promUrl,
  socket: config.dockerProxyUrl ? undefined : config.dockerSocket, autoRegister: config.lapiAutoRegister,
});

export const extraInstances = () => getSetting<Instance[]>('instances', []);
export const listInstances = (): Instance[] => [main(), ...extraInstances()];
export const instanceById = (id: string) => listInstances().find((i) => i.id === id);

const als = new AsyncLocalStorage<Instance>();
export const current = () => als.getStore() ?? main();
export const isMain = () => current().id === MAIN;
export const inInstance = <T>(i: Instance, fn: () => T): T => als.run(i, fn);
// host-wide things (cloudflare, the zone chart) stay on main
export const onMain = <T>(fn: () => T): T => als.run(main(), fn);

// which crowdsec a request is about. an unknown id falls back to main, /auth/me tells the browser which one it got
export const pickInstance: MiddlewareHandler = (c, next) => {
  const inst = instanceById(c.req.header('x-argos-instance') || c.req.query('instance') || MAIN) ?? main();
  return als.run(inst, () => next());
};

// settings that belong to one crowdsec: main keeps the old keys
export const scoped = (key: string) => (isMain() ? key : `${key}@${current().id}`);

setAuditInstance(() => (isMain() ? null : current().name));

export function saveInstance(i: Instance): void {
  const all = extraInstances();
  const at = all.findIndex((x) => x.id === i.id);
  if (at >= 0) all[at] = i; else all.push(i);
  setSetting('instances', all);
}
export const removeInstance = (id: string) => setSetting('instances', extraInstances().filter((i) => i.id !== id));
