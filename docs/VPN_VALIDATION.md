# VPN Manager validation — 2026-10-24

## Evidence boundaries

- The installed Amnezia client is 5.0.3.0. The user confirms Premium country selection.
- Existing exported candidate: `orbitvpn.conf`; its secrets were never printed.
- **No live Premium country connection or cross-country switch is claimed.**
  Per-location independent exported profiles are required for that acceptance.
- The real namespace lab uses generated ephemeral AWG3 keys, local peers, and
  local HTTPS. It makes no Shodan search and never reuses the user's tunnel key.
- Browser acceptance uses the real HTTP application with a simulated VPN provider.

## Checks

| Check | Evidence |
|---|---|
| Pre-change Python baseline | 108 tests passed |
| Current Python suite | 135 tests; `vpn-evidence/python-tests.txt` |
| Existing JS IP progress | 11 tests; `vpn-evidence/js-tests.txt` |
| Arabic RTL 375/1280, keyboard entry, profile validation, network policy | `vpn-evidence/browser.json`, screenshots |
| axe: VPN, diagnostics, job network, policy controls | zero violations in the tested regions |
| Actual AWG3 handshake and TLS via Python/curl inside namespace | `vpn-evidence/isolation-lab.json` |
| Actual broker launches dropped-UID worker, checkpoint and 292 synthetic IPs | same lab evidence |
| Tunnel removal blocks Python/curl direct egress | same lab evidence |
| SSH/dashboard TCP listeners reachable before/during/after tunnel | same lab evidence |
| Host route/rule/stateless-firewall/DNS snapshots identical after lab | same lab evidence |
| Real DB copy migration preserves jobs/IPs/users/events | `vpn-evidence/migration-rehearsal.json` |

The automated suite covers profile parsing/command rejection, connect/failed-connect
cooldown/audit, TLS retry recovery, DNS outage/checkpoint resume without refetching
completed pages, health-confirmed failover, all profiles failing, persistent switch
limits, legacy direct jobs, restart health invalidation, protected rollback, helper
leases, restoring the previous profile, auth/CSRF, and secret omission.

The lab initially caught an nft syntax error, corrected before deployment. Its
first host-state comparison also counted changing packet counters; the final
comparison uses nft's stateless rule output, retaining the rules while excluding
unrelated live traffic counters. A full-suite run found a direct-mode resume race
introduced by the network guard; the guard was narrowed and the original job
regression suite rerun. Failed intermediate runs are not acceptance evidence.

## Remaining acceptance limits

- Real Premium egress/country failover needs independent location `.conf` files;
  the implementation neither exports subscription assets nor modifies Premium account state.
- Handshake/isolated HTTPS were exercised with the bundled userspace AWG3 daemon;
  kernel WireGuard and other versions/platforms were not live-tested.
- No host reboot was performed. Interrupted-job recovery is automated; service
  restarts and on-host installation are recorded separately below when performed.
- SSH evidence is TCP listener reachability plus unchanged routing; no new remote
  SSH authentication session was created by the test.
- GeoIP coordinates are unavailable; countries are explicitly user-defined.
- The existing stdlib WSGI/trusted-LAN/SSH-tunnel deployment boundary remains.
  This is not public multi-tenant hosting certification or an external security audit.

## On-host delivery

The application and helper were installed on Debian 12. `/health` returned
`{"ok":true,"version":"1.2.0"}`. The migration retained 4 jobs, 750 per-job IP
records, 1 user and 2,608 events; job files remained byte-identical. The existing
AmneziaVPN and SSH service PIDs were unchanged. A full private data/config backup
and the automatic pre-migration SQLite backup are retained. See
`vpn-evidence/deployment.json` for release and backup paths.

The first rollout verifier used the wrong health URL; its rollback restored the
old code. The corrected verifier uses the existing `/health` endpoint. This was a
verification-script error, not a claim that `/api/health` exists.

The root-only `orbitvpn.conf` candidate was imported as **disabled, untested, country
unknown**. No Premium tunnel was started. The unprivileged service account can use
the constrained socket but cannot read profile secrets; an unrelated UID cannot
connect to the socket. The helper is available with AmneziaWG; system WireGuard
CLI is absent and is reported unavailable.

The local AWG3/real-worker/checkpoint lab also passed under a systemd sandbox with
the helper's capability bounding, namespace restrictions, read-only filesystem,
no-new-privs and unprivileged worker. See `vpn-evidence/systemd-isolation-lab.txt`.
A separate application service survived two restarts, retained partial output and
resumed to 292 synthetic IPs without touching the production service; evidence is
in `vpn-evidence/service-restart-tests.txt`.

Health probes now test the independent egress even when destination TLS fails.
An otherwise healthy tunnel is not switched for a destination-only error.
Dashboard reads remain responsive while a connect/probe is pending; the queue
waits until that manual network operation releases its reservation.

Installed Python/static files were SHA-256 compared with the final workspace and
matched exactly. Final local suite: **135 Python tests and 11 JavaScript tests,
all passing**. The additional coverage includes interrupted checkpoint replacement
preserving the previous file and cancellation during network diagnosis never
reviving a cancelled job. The baseline release for a pre-VPN rollback is recorded
in `deployment-initial.json`; the most recent deployment record points to the
immediately preceding validated 1.2 candidate.
