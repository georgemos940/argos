# Changelog

Versions follow [semver](https://semver.org). Docker images are tagged with the version (`1.1.0`, `1.1`) and `latest` follows `main`.

## 1.1.0

### New

- **False positives**: bans that look like a real visitor or your own app (home network, mostly 2xx answers, Next.js prefetches, the same app path from several users, unbanned before), each with its reasons and allow / unban / ignore rule in one click
- **Ban policy**: ban length, longer bans for repeat offenders, captcha first for web attacks, or `profiles.yaml` by hand. Checked with `crowdsec -t` before CrowdSec restarts into it, and put back if it refuses it or does not come back up
- **Ignore rules**: requests by path, host, user agent, method or status that never count toward a ban
- **Several CrowdSec servers** in one Argos: instance switcher, cscli through each server's docker proxy, alerts from all of them to the channels, blocklists to all of them, the audit log says where
- **Single sign-on** over OpenID Connect: link accounts or create them on first sign-in, email domain limits, roles from a groups claim
- **Passkeys**: sign in with a fingerprint, face or device PIN; they satisfy Require 2FA
- **API tokens** (viewer or operator, with an expiry) for scripts: `Authorization: Bearer argos_…`
- **Notification channels**: Telegram, Slack, ntfy, email, JSON webhook with an HMAC signature, and a daily / weekly summary
- **Bouncer usage**: dropped packets and bytes per bouncer and decision source
- Installable as an app (PWA), opens offline to the last shell

### Security

- Argos no longer holds the Docker socket: `argos-docker-proxy` does and only lets allowed `cscli` execs, a CrowdSec restart, `crowdsec -t` and Argos' own two config files through

### Upgrading from 1.0

- Nothing breaks, the database updates itself on start
- Recommended: add the `argos-docker-proxy` service from `docker-compose.yml`, put `DOCKER_PROXY_TOKEN` (`openssl rand -hex 32`) in `.env` and drop the `docker.sock` mount from `argos`. Without it Argos keeps using the socket as before
- Using passkeys or SSO: set `PUBLIC_URL` to the address people open

## 1.0.0

First release.

- Live overview: attacks, attacking IPs, bans, the community blocklist, a world map with an arc per attacker and a live feed
- Alerts with the requests behind them; IP profiles with history and CrowdSec CTI / AbuseIPDB reputation
- Bans for IPs, ranges, countries and AS numbers, bulk ban, captcha; allowlists
- Blocklists: Spamhaus DROP, FireHOL level 1, Tor exits, AbuseIPDB and custom URLs on a schedule, never touching private, own or Cloudflare ranges
- Web firewall page for CrowdSec AppSec
- Hub store with install, upgrade preview and automatic restart; per-scenario simulation mode
- Tools: `cscli explain` log tester, CrowdSec Console enrollment
- Cloudflare Under Attack switch per zone with a req/s chart
- Discord alerts with an embed designer and live preview; Grafana alert relay to Discord
- Users with admin / operator / viewer roles, TOTP 2FA (optionally required for everyone), audit log
- Hardened for exposure: real client IP behind a proxy, per-IP and per-username login limits, CSRF checks, CSP/HSTS, SSRF guard on list URLs
- `DEMO=1` mode, an all-in-one compose example and `LAPI_AUTO_REGISTER` for one-command setups
