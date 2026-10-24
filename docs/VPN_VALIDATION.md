# VPN Manager / Premium validation — 2026-10-24

## Delivered on Debian 12

Version **1.3.0** is installed in the existing Shodan Studio service. The original
Python/SQLite/buildless Arabic RTL application, queue, checkpoints and results
remain. Premium support targets the installed AmneziaVPN **5.0.3.0** protocol;
it is source-compatible integration, not a public vendor SDK.

The gateway returned **55 real account locations**. A persistent independent worker
identity occupies one device slot. After the user freed capacity, the account used
5 of 7 slots, including 2 exported files; those counts remained unchanged across
Germany → USA East. No native-export or revoke API was called. The host GUI's
identity, settings file and tunnel were not changed.

## Live acceptance

| Check | Actual result / evidence |
|---|---|
| Authenticated dashboard API: Germany | `135.136.45.186`; DNS/TCP/TLS/HTTPS/handshake/route/leak checks passed |
| Same API: USA East | `38.132.96.202`; all checks passed; different egress |
| Dashboard responsiveness during connection | 92 management checks, each dashboard poll under 2 seconds |
| SSH/dashboard availability | localhost TCP listeners remained reachable throughout the switch |
| Host state | identical IPv4/IPv6 routes, rules, stateless nft rules, DNS, GUI-settings hash and SSH/Amnezia PIDs before/after |
| Controlled tunnel loss | actual managed tunnel disconnected; Python and curl could not reach direct internet |
| Actual failover engine | selected allowed Germany from USA East with one persisted attempt; verified real egress before returning resume state |
| Restart bound | a fresh manager using the test DB could not exceed its persisted one-switch limit |

Evidence: [`premium-live.json`](vpn-evidence/premium-live.json) and
[`premium-live-failover.json`](vpn-evidence/premium-live-failover.json).
The controlled-loss job metadata was synthetic in a temporary database. No live
Shodan search or production job was used to force failures. Actual worker,
checkpoint and extraction behavior is covered by the independent local AWG lab
and automated scenarios below, rather than claimed from that synthetic job.

Both selected countries were verified through the subscription catalog and actual
exit IP. No GeoIP provider is configured: this does not independently prove the
physical location of those IPs or test all 55 locations.

## Automated / browser / local-lab acceptance

| Check | Evidence |
|---|---|
| Full Python suite | **156 passed**, `vpn-evidence/premium-python-tests.txt` |
| Existing JavaScript progress suite | **11 passed**, `vpn-evidence/premium-js-tests.txt` |
| Premium browser on real HTTP app with simulated provider | enrollment, masked/cleared key, 55-location filter, immutable country, verified connection |
| Arabic RTL at 375 and 1280 | no horizontal page overflow, zero axe violations in tested Premium regions/dialog; `premium-browser.json` and `premium-rtl-*.png` |
| Installed service with real subscription catalog | `premium-live-ui.json`, screenshots; RTL/axe at 375/1280 |
| Original VPN/job/diagnostics browser | `vpn-evidence/browser.json`; zero axe violations in tested regions |
| Actual local AWG3 handshake and Python/curl TLS | `vpn-evidence/isolation-lab.json` |
| Actual dropped-UID worker, checkpoint, 292 synthetic IPs | same local lab; no external Shodan searches |
| Same lab under helper systemd sandbox | `vpn-evidence/systemd-isolation-lab.txt` |
| Separate application survives service restarts, preserves partial output and resumes | `vpn-evidence/service-restart-tests.txt` |
| Real pre-VPN DB copy migration | `vpn-evidence/migration-rehearsal.json` |

The suite covers strict profiles and command rejection; bounded TLS/DNS retry;
checkpoint recovery without repeating completed pages; no switching for HTTP
quota/auth or a destination-only fault on a healthy tunnel; all profiles failing;
allowlists/cooldowns; persistent attempt counts; atomic checkpoint replacement;
cancel during diagnosis; legacy Direct jobs; restart invalidation; helper leases;
auth/CSRF and redaction. Premium adds encrypted transport, TLS and endpoint
restrictions, persistent independent identity, country/config/key matching,
account-limit/expiry/captcha/rate-limit handling, root-private files, independent
gateway UID, supported AWG template bounds, and responsive polling during monitoring.

Reproduce the Premium browser fixture with Playwright and @axe-core/playwright
installed in your test tooling (not production dependencies):

```bash
python3 tests/serve_vpn_fixture.py --premium
# In another terminal, with those Node packages available:
node tests/browser_premium.cjs http://127.0.0.1:8792
```

Restart the fixture before each run; it uses a fresh temporary database and
loopback-only synthetic credentials. This test never contacts Premium.

## Deployment and data preservation

`/health` returns `{"ok":true,"version":"1.3.0"}`. The upgrade retained **4 jobs,
750 per-job IP records, 1 user and 2,689 events**, with byte-identical job files.
The schema remains at version 1; Premium requires no extra migration. The initial
VPN schema migration and original 1.2 deployment are recorded separately in
`deployment.json` / `deployment-initial.json`.

The latest release and private backup paths are recorded in
[`premium-deployment.json`](vpn-evidence/premium-deployment.json). Backups include
root-private subscription state, preserving the independent device identity.
The final service restart retained the same profile ID and account counts; a new
verified Germany connection kept all 55 locations. See `premium-post-restart.json`.
The service web UID cannot read this file; the separate unprivileged gateway UID
also cannot read it. The root helper passes only the bounded request over private
pipes. No secrets are stored in the public registry, SQLite, API or test evidence.

Failed intermediate attempts are not acceptance results. Live testing exposed
trailing whitespace in the config envelope, a longer AWG packet template, startup
DNS/handshake delay, a polling wait behind the health monitor, and an older
54-country list embedded in tunnel templates. Only account_info now replaces
the authoritative catalog, so connecting cannot shrink the 55-country list. All received
regression coverage before the passing live run. A manual diagnostic left an
empty test namespace outside the systemd mount namespace; deployment refused to
reuse it and rolled back. The empty owned namespace was removed while the helper
was stopped, then normal deployment and the sandboxed live test passed.

## Remaining limits

- Only Germany and USA East were live-tested, not every Premium location.
- No host reboot or new remote authenticated SSH session was performed. Evidence
  covers unchanged routes/PIDs and listener reachability, plus service restarts.
- Kernel WireGuard, other Amnezia versions and other operating systems were not
  live-tested. Static imported `orbitvpn.conf` remains disabled and untested.
- Protocol compatibility is pinned to the upstream client source. Incompatible
  gateway responses stop protected work; they may require an adapter update.
- The trusted-LAN/SSH-tunnel stdlib WSGI deployment boundary remains. This is not
  a public multi-tenant hosting certification or an external security audit.
- No production Shodan queries were consumed to simulate failure cases.

Operational instructions: [Premium](VPN_PREMIUM_AR.md),
[VPN usage](VPN_MANAGER_AR.md), [upgrade and rollback](VPN_DEPLOYMENT_AR.md).
