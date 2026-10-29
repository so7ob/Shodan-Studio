# VPN discovery and architecture — 2026-10-24

Read-only inventory before implementation, from `/root/So7ob/Shodan-Studio`,
origin `https://github.com/so7ob/Shodan-Studio.git`, base `b3344de`.
No AGENTS.md or CONTRIBUTING file was found. Untracked user ZIP is preserved.

- Debian 12, kernel 6.1.0-42-amd64. Python stdlib WSGI/SQLite; buildless Arabic RTL frontend.
- Live service `shodan-studio`, unprivileged `shodan-studio` account;
  `/opt/shodan-studio/current`, `/var/lib/shodan-studio`, port 8787.
- SQLite WAL, user_version=0, jobs/events/users/sessions/settings/login_limits/job_ips.
  Three existing jobs (two waiting_input, one cancelled); none running at inspection.
- One process worker, queue ownership lock; JSON stdin/stdout; API keys only in memory/stdin.
  Checkpoints use fsync/atomic replace and locks. Results are deduplicated in SQLite.
  Startup interrupts active work and reconciles saved results. Polling every two seconds.
- Both curl and urllib transports retain TLS verification; typed DNS/TLS/timeout/HTTP errors.
  Session auth, Host/Origin/CSRF validation already protect mutation routes.
- Existing unittest suites plus Node progress tests and Playwright/axe acceptance harness.
- Installed **AmneziaVPN client 5.0.3.0**, root AmneziaVPN.service;
  `/opt/AmneziaVPN/bin/amneziawg-go --version`: 0.0.20250522.
  OpenVPN and tun2socks binaries also bundled. No awg/wg/quick tools in PATH.
- Active `amn0` is a userspace TUN. Host has 0.0.0.0/1 and 128.0.0.0/1 via amn0;
  default gateway still on ens37. Existing host egress therefore already uses Amnezia.
  `Direct` means the existing host route, not a promise to bypass that VPN.
- One candidate `/etc/amnezia/amneziawg/orbitvpn.conf`, root:0600, one peer;
  only section/field names inspected for inventory; keys never reported.
  Includes AWG3 HeaderProtectionKey/S1-S4 etc. Country and real usability unknown.
  GUI settings were not read. No evidence of multiple countries.
- systemd-resolved stub resolver. Existing nftables tables include Docker/system rules.
  No host routing/firewall/DNS changes are planned.

## Design decision

Use a dedicated network namespace with only loopback and one WG/AWG tunnel.
The encrypted UDP socket is created in the host namespace, with the tunnel moved
into the worker namespace. There is no veth, NAT, host default-route change, or
fallback route. Namespace-local nftables permits only the tunnel and loopback.
Namespace-local resolv.conf points at explicit profile DNS addresses.

A root-owned helper exposes fixed operations over a 0660 Unix socket, authenticates
SO_PEERCRED, strictly parses approved profiles (no hooks), and drops privileges
before running the fixed installed worker. No web-supplied executable or path.
It never exposes profile secrets. One worker lease prevents switch races.
All changes affect owned `ssvpn-*` namespaces and `ssv*` interfaces only.

Userspace AmneziaWG namespace behavior and supported parameters must be verified
before acceptance. Official awg tooling is the configuration adapter; no GUI
automation or invented client CLI. Unsupported profiles remain visibly unsupported.

Transport errors remain distinct from HTTP auth/quota errors. Fresh HTTP 429
responses can request enabled failover after preserving their retry deadline.
Bounded worker retries count against request budgets. The worker saves and exits
before the parent verifies health and selects another allowed, enabled profile.
Persistent Shodan destination failures qualify even when the tunnel is healthy.
Switch limits survive restart; failures receive cooldowns and an audit record.
An unsuccessful switch attempts restoration and pauses safely. Management remains
in the host namespace; the old host Amnezia connection is never switched.

## Sources

- https://www.wireguard.com/netns/ — namespace/socket routing model.
- https://github.com/amnezia-vpn/amneziawg-go — foreground daemon and tooling interface.
- https://github.com/amnezia-vpn/amneziawg-tools — supported setconf/show commands.

Live evidence and limitations belong in VPN_VALIDATION.md after implementation.

## Premium correction from user — original 1.2 scope

The user confirms an active Premium subscription and country switching in the
installed GUI. The single exported `.conf` is **not** a count of subscription
locations. GUI QSettings field names show Premium service configuration; values
and subscription tokens were not printed. Official Premium documentation supports
per-location AWG3.1 exports from the personal dashboard. This integration accepts
those exports. It does not drive the host GUI, scrape account credentials, or claim
that every subscribed country already has an imported, verified worker profile.

Official source: https://docs.amnezia.org/documentation/instructions/personal_dashboard/

Official amneziawg-tools was built from
`ee0f0a9aa34ff0a0da4b3433b9512781cfe02843` and installed under
`/usr/local/libexec/shodan-studio/awg`. The bundled userspace daemon accepted
AWG3 HeaderProtectionKey/S1-S4 in the independent local namespace lab. This is
protocol support evidence, not verification of the Premium candidate's endpoint.

## Authorized 1.3 follow-up

The user explicitly requested dynamic subscription switching and freed account
capacity. Root-only inspection subsequently verified Premium credentials and the
HTTPS gateway cache without printing secrets or changing the GUI. The gateway
returned 55 locations. The new independent worker identity uses one device slot;
actual account counts and live tunnel evidence are in `VPN_VALIDATION.md`.
The original static-export limitation above is superseded by the source-pinned
adapter documented in `VPN_PREMIUM_DESIGN.md`.
