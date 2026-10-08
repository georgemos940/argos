const env = (name: string, fallback?: string): string => {
  const v = process.env[name] ?? fallback;
  if (v === undefined) throw new Error(`missing env ${name}`);
  return v;
};

export const config = {
  port: Number(env('PORT', '3000')),
  dataDir: env('DATA_DIR', './data'),
  sessionSecret: env('SESSION_SECRET'),
  lapiUrl: env('LAPI_URL', 'http://crowdsec:8080'),
  lapiUser: env('LAPI_USER', 'argos'),
  lapiPassword: env('LAPI_PASSWORD'),
  promUrl: env('PROM_URL', 'http://prometheus:9090'),
  crowdsecContainer: env('CROWDSEC_CONTAINER', 'crowdsec'),
  dockerSocket: env('DOCKER_SOCKET', '/var/run/docker.sock'),
  // cloudflare: env, or a bash file with CF_API_TOKEN="..." CF_ZONE_IDS=( "id" ... )
  cfToken: env('CF_API_TOKEN', ''),
  cfZones: env('CF_ZONE_IDS', '').split(/[\s,]+/).filter(Boolean),
  cfEnvFile: env('CF_ENV_FILE', ''),
  // optional, external rate guard state (rps/uam_<zone id>)
  cfStateDir: env('CF_STATE_DIR', ''),
  // optional, req/s per zone, needs a `zone` label
  zoneRpsQuery: env('ZONE_RPS_QUERY', ''),
  // attack map
  homeLat: Number(env('HOME_LAT', '50.11')),
  homeLon: Number(env('HOME_LON', '8.68')),
  // never banned by blocklists
  selfIps: env('SELF_IPS', '').split(/[\s,]+/).filter(Boolean),
  instanceName: env('INSTANCE_NAME', 'crowdsec'),
  // behind a reverse proxy: take the client ip from X-Real-IP / X-Forwarded-For, never otherwise
  trustProxy: env('TRUST_PROXY', 'false') === 'true',
  // false only for plain http
  cookieSecure: env('COOKIE_SECURE', 'true') !== 'false',
};
