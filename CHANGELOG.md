# Changelog

Versions follow [semver](https://semver.org). Docker images are tagged with the version (`1.0.0`, `1.0`) and `latest` follows `main`.

## Unreleased

- Argos no longer holds the Docker socket: `argos-docker-proxy` does and only lets allowed `cscli` execs and a CrowdSec restart through
- Notification channels: Telegram, Slack, ntfy, email, JSON webhook with an HMAC signature
- Daily / weekly summary to Discord and any channel
- Ban policy page: ban length, escalation for repeat offenders, captcha first for web attacks, raw `profiles.yaml`; checked with `crowdsec -t` and rolled back if CrowdSec refuses it
- Ignore rules: requests by path, host, user agent, method or status that never count toward a ban
- Bouncer usage: dropped packets and bytes per bouncer and decision source
- Installable as an app (PWA), opens offline to the last shell
- False positives page: bans that look like real visitors or the app itself, with the reasons and allow / unban / ignore rule in one click
- Several CrowdSec servers in one Argos: instance switcher, per-instance cscli through each server's docker proxy, alerts from all of them to the channels, blocklists to all of them, audit log says where
- Single sign-on over OpenID Connect: account linking or creation on first sign-in, email domain limits, roles from a groups claim
- Passkeys (WebAuthn): add them in Settings, sign in without a password; they satisfy Require 2FA. `PUBLIC_URL` pins the origin they are bound to
- API tokens (viewer or operator, with expiry) for scripts: `Authorization: Bearer argos_…`

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
