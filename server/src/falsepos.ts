import { meta, type Alert } from './lapi.js';

// heuristics for bans that hit a real visitor or the app itself instead of an attacker.
// every signal is a reason a human can read, the score is just their sum

const HOSTING = /cloud|hosting|host\b|server|data ?cent|datacamp|digitalocean|ovh|hetzner|amazon|\baws\b|google|microsoft|azure|m247|scaleway|contabo|linode|akamai|vultr|choopa|leaseweb|colocation|\bvps\b|dedicated|oracle|alibaba|tencent|huawei|ionos|hostinger|netcup|frantech|psychz|quadranet|zenlayer|g-?core|stark industries|aeza|railnet|bucklog|pfcloud|constant ?company|tor exit/i;
const ISP = /telecom|telekom|mobile|cable|broadband|fib(er|re)|vodafone|cosmote|\bote\b|wind hellas|nova|forthnet|inalan|hellas online|orange|comcast|verizon|at&t|charter|spectrum|cox comm|british telecom|\bsky\b|virgin media|telefonica|movistar|telecom italia|fastweb|iliad|free sas|bouygues|\bsfr\b|swisscom|\bkpn\b|ziggo|proximus|telia|telenor|rogers|bell canada|optus|telstra|reliance jio|airtel|deutsche telekom|liberty global|\bdsl\b|residential/i;
// googlebot and bingbot come from these exact networks, not from their clouds
const SEARCH_BOTS = /^(GOOGLE|MICROSOFT-CORP-MSN-AS-BLOCK|YANDEX.*|APPLE-ENGINEERING|Apple Inc\.)$/i;
const PROBE = /\/\.(env|git|aws|ssh|svn|htpasswd|ds_store)|wp-(login|admin|includes|content)|xmlrpc|phpinfo|phpmyadmin|\/vendor\/phpunit|\/cgi-bin|\/actuator|\/boaform|server-status|\/\.well-known\/security|eval-stdin|\/shell|\/etc\/passwd|\.\.\/|%2e%2e|\/(admin|administrator|manager)\/?$|\.(sql|bak|old|zip|tar|gz)$|\/config\.(json|php|yml)|\/owa\/|\/solr|\/hnap1|setup\.cgi|\/console\/?$/i;
// behaviour scenarios a busy real user can trip; the rest match exploit payloads
const SOFT = /http-(probing|crawl-non_statics|generic-40[13]-bf|bad-user-agent|backdoors-attempts)|http-dos|http-bf|-bf$|-slow-bf/;
const HARD = /cve|vpatch|sensitive-files|path-traversal|wordpress-scan|admin-interface-probing|technology-probing|sqli|xss|log4j|appsec/i;

export interface Reason { text: string; weight: number }
export interface Suspect {
  key: string; ip: string; cn?: string; as_name?: string; score: number; reasons: Reason[];
  scenarios: string[]; alerts: number; events: number; lastAt: string;
  sites: string[]; requests: { host: string; path: string; status: string }[];
  decision?: { id: number; type: string; duration: string };
  // a ready ignore rule for the requests that tripped it
  rule?: { name: string; conditions: { field: 'host' | 'path'; op: 'equals' | 'startsWith' | 'contains'; value: string }[] };
}
export interface NoiseGroup { key: string; host: string; prefix: string; ips: number; events: number; statuses: Record<string, number> }

const prefixOf = (path: string) => {
  const seg = path.split('?')[0].split('/')[1] ?? '';
  return seg ? `/${seg}/` : '/';
};
const network = (as?: string) => (!as ? 'unknown' : SEARCH_BOTS.test(as) ? 'bot' : HOSTING.test(as) ? 'hosting' : ISP.test(as) ? 'isp' : 'unknown');

export function findSuspects(all: Alert[], opts: { unbanned?: Set<string>; dismissed?: Set<string>; active?: Map<string, Suspect['decision']> } = {}) {
  const alerts = all.filter((a) => a.source.scope === 'Ip' && !a.scenario.startsWith('manual '));
  const byIp = new Map<string, Alert[]>();
  for (const a of alerts) byIp.set(a.source.value, [...(byIp.get(a.source.value) ?? []), a]);

  // (host, first path segment) hit by several isp visitors, with no probe paths there, is likely the app itself
  const spots = new Map<string, { host: string; prefix: string; ips: Set<string>; events: number; statuses: Record<string, number>; probe: boolean }>();
  for (const a of alerts) {
    const isp = network(a.source.as_name) === 'isp';
    for (let i = 0; i < (a.events?.length ?? 0); i++) {
      const host = meta(a, i, 'target_fqdn') ?? '';
      const path = meta(a, i, 'http_path') ?? '';
      if (!path) continue;
      const k = `${host} ${prefixOf(path)}`;
      const s = spots.get(k) ?? { host, prefix: prefixOf(path), ips: new Set(), events: 0, statuses: {}, probe: false };
      if (PROBE.test(path)) s.probe = true;
      if (isp) {
        s.ips.add(a.source.value);
        s.events++;
        const st = meta(a, i, 'http_status') ?? '?';
        s.statuses[st] = (s.statuses[st] ?? 0) + 1;
      }
      spots.set(k, s);
    }
  }
  const noisy = new Map([...spots].filter(([, s]) => s.ips.size >= 3 && !s.probe && s.prefix !== '/'));

  const suspects: Suspect[] = [];
  for (const [ip, list] of byIp) {
    const key = `ip:${ip}`;
    if (opts.dismissed?.has(key)) continue;
    const src = list[0].source;
    const reasons: Reason[] = [];
    const add = (weight: number, text: string) => reasons.push({ weight, text });

    const net = network(src.as_name);
    if (net === 'isp') add(2, `Home or mobile network (${src.as_name})`);
    if (net === 'hosting') add(-2, `Hosting network (${src.as_name}), where scanners live`);
    if (net === 'bot') add(1, `${src.as_name} network, where search engine crawlers come from`);

    const requests: Suspect['requests'] = [];
    let ok = 0;
    let probes = 0;
    const appSpots = new Set<string>();
    for (const a of list) for (let i = 0; i < (a.events?.length ?? 0); i++) {
      const host = meta(a, i, 'target_fqdn') ?? '';
      const path = meta(a, i, 'http_path') ?? '';
      const status = meta(a, i, 'http_status') ?? '';
      requests.push({ host, path, status });
      if (/^[23]\d\d$/.test(status)) ok++;
      if (PROBE.test(path)) probes++;
      const k = `${host} ${prefixOf(path)}`;
      if (noisy.has(k) && noisy.get(k)!.ips.size - (noisy.get(k)!.ips.has(ip) ? 1 : 0) >= 2) appSpots.add(k);
    }
    // next.js router prefetches 404 on pages it does not know yet, a browser does that, not a scanner
    const rsc = requests.find((r) => /[?&]_rsc=|\/_next\/data\//.test(r.path));
    if (rsc) add(2, `Next.js page prefetches (${rsc.path.slice(0, 50)}), what a browser on your app sends`);
    const ua = list.map((a) => meta(a, 0, 'http_user_agent')).find(Boolean);
    if (ua && /googlebot|bingbot|applebot|duckduckbot|yandexbot|uptimerobot|pingdom|statuscake|betteruptime|uptime-kuma/i.test(ua)) add(3, `Identifies as a known crawler or monitor (${ua.slice(0, 60)})`);

    if (requests.length && ok / requests.length >= 0.5) add(3, `${ok} of ${requests.length} requests succeeded (2xx/3xx), attackers mostly get errors`);
    if (probes) add(-3, `Asked for ${probes === 1 ? 'a classic probe path' : `${probes} classic probe paths`} (${requests.find((r) => PROBE.test(r.path))!.path.slice(0, 60)})`);
    if (appSpots.size) {
      const [first] = appSpots;
      const s = noisy.get(first)!;
      add(2, `${s.ips.size - (s.ips.has(ip) ? 1 : 0)} other home-network visitors tripped CrowdSec on ${s.prefix} at ${s.host || 'the same site'} too`);
    }

    const scenarios = [...new Set(list.map((a) => a.scenario))];
    if (scenarios.every((s) => SOFT.test(s))) add(1, 'Only behaviour scenarios, which a busy real user can trip');
    if (scenarios.some((s) => HARD.test(s))) add(-3, `Matched an exploit pattern (${scenarios.find((s) => HARD.test(s))!.replace(/^crowdsecurity\//, '')})`);
    if (opts.unbanned?.has(ip)) add(3, 'Someone already unbanned this IP once and it got banned again');

    const score = reasons.reduce((n, r) => n + r.weight, 0);
    if (score < 3) continue;

    const spot = appSpots.size ? noisy.get([...appSpots][0])! : undefined;
    const ruleHost = spot?.host || rsc?.host;
    const rule: Suspect['rule'] = spot
      ? { name: `App traffic on ${spot.prefix}`, conditions: [{ field: 'path', op: 'startsWith', value: spot.prefix }] }
      : rsc ? { name: 'Next.js prefetches', conditions: [{ field: 'path', op: 'contains', value: '_rsc=' }] } : undefined;
    if (rule && ruleHost) rule.conditions.unshift({ field: 'host', op: 'equals', value: ruleHost });
    suspects.push({
      key, ip, cn: src.cn, as_name: src.as_name, score, reasons: reasons.sort((a, b) => b.weight - a.weight),
      scenarios, alerts: list.length, events: list.reduce((n, a) => n + a.events_count, 0),
      lastAt: list.map((a) => a.start_at).sort().at(-1)!,
      sites: [...new Set(requests.map((r) => r.host).filter(Boolean))],
      requests: requests.slice(0, 8),
      decision: opts.active?.get(ip),
      rule,
    });
  }

  const groups: NoiseGroup[] = [...noisy].filter(([k]) => !opts.dismissed?.has(`spot:${k}`))
    .map(([k, s]) => ({ key: `spot:${k}`, host: s.host, prefix: s.prefix, ips: s.ips.size, events: s.events, statuses: s.statuses }))
    .sort((a, b) => b.ips - a.ips);
  return { suspects: suspects.sort((a, b) => b.score - a.score || b.lastAt.localeCompare(a.lastAt)), groups, scanned: alerts.length };
}
