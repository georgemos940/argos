# Security

Argos holds the keys to your CrowdSec: it can ban and unban, change detection rules and restart the engine through the Docker socket. Reports are taken seriously.

## Reporting a vulnerability

Please do **not** open a public issue.

Use GitHub's private reporting: **Security → Report a vulnerability** on this repository. Include what you found, how to reproduce it and which version you run. You will get an answer within a few days, and credit in the release notes if you want it.

## Supported versions

Only the latest release gets fixes. Pin a version tag in production and update when a release mentions security.

## Running it safely

- Keep it off the open internet if you can (VPN, Tailscale, an IP allow-list or an SSO proxy in front).
- If it is public: HTTPS only, `TRUST_PROXY=true` behind your reverse proxy, and **Settings → Users → Require 2FA for everyone**.
- The Docker socket is root on the host. Argos only runs an allow-list of `cscli` commands and never a shell, but whoever is admin in Argos can run those.
- Give people the lowest role that works: viewer, then operator, admin only for the few who manage the engine.
