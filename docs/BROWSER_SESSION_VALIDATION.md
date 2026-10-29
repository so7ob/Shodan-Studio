# Browser session acceptance

## Login redirect correction — 1.4.1 (2026-10-25 Asia/Aden)

The old verification required the exact facet URL but provided no way back after
login redirected to a home/account page. The new explicit return button keeps
the current tab, profile and VPN, navigates only to the server-owned pending
facet, and requires a separate successful page check before resume. Ordinary
verification still never navigates. Equivalent query encoding/order is accepted
without accepting a different query, facet, host or endpoint.

| Evidence | Result |
| --- | --- |
| [Automated checks](vpn-evidence/browser-login-return-tests.txt) | **192 Python tests** passed in 69.290 s; **11 JS tests** passed; JS syntax and installer checks passed |
| [Native browser](vpn-evidence/browser-login-return-native.json) | Real Chromium followed synthetic HTTPS login redirects, kept a synthetic HttpOnly session cookie, rejected the landing page and parsed the pending facet after explicit return; no Shodan requests; sandbox and disconnected-network checks passed |
| [UI acceptance](vpn-evidence/browser-login-return-ui.json) | Landing-page rejection, explicit keyboard return, separate verification, private input clearing, 375/1280 RTL, zero axe violations; all four footer controls fit inside the dialog |
| [Deployment](vpn-evidence/browser-login-return-deployment.json) | 1.4.1 healthy; **4 jobs / 823 IPs / 1 user** retained at update, unchanged job files and schema 1; restored backup SQLite checked; helper not restarted and host network/SSH unchanged |
| [Live observation](vpn-evidence/browser-login-return-live.json) | User invoked return at **21:55:46 UTC**, then successful verification at **21:55:50 UTC**; extraction running with **94 real task IPs**, up from 73 at maintenance; existing worker profile and helper PID retained; checked runtime source matches checkout |

The agent did not enter credentials, solve challenges or resume the live job.
The attempted separate live probe stopped at its busy-worker guard; the user had
already resumed. The subsequent evidence is read-only status/audit/SQLite data.
This proves a live return/verify/resume sequence, not a finished extraction or
immunity from future HTTP 403/429 responses.

For this fix, code rollback targets the pre-fix 1.4.0 release
`/opt/shodan-studio/releases/release-72lQCVjt`. Pause at a checkpoint, close the
browser to flush its private profile, stop only the web service, take a fresh
data/profile backup, point `current` to that release and start the web service.
Keep the existing data: there is no schema change and later results must not be
overwritten by an older backup. The pre-fix private backup is
`/var/backups/shodan-studio/pre-login-return-20261024-215407.tar.gz`; the final
maintenance backup is recorded in the deployment evidence. The helper/tunnel
does not need restarting for this code rollback.

## Original feature acceptance — 1.4.0

Tested on Debian 12 / Python 3.11.2 / Chromium 156.0.8078.47, on 2026-10-25
(Asia/Aden; deployment timestamps are UTC). This extends Issue #4 / the VPN
branch. It proves partial live HTML reading after manual verification, not a
stable unrestricted session or a completed Shodan IP export.

| Evidence | Result |
| --- | --- |
| [Python suite](vpn-evidence/browser-python-tests.txt) | 185 tests, 65.567 seconds, no failures/skips |
| [JavaScript suite](vpn-evidence/browser-js-tests.txt) | 11 tests, no failures/skips |
| [Interactive UI](vpn-evidence/browser-interactive-ui.json) | Authenticated fixture, delayed first frame, text clearing, verified resume, keyboard; RTL 375/1280, zero axe violations in the dialog, no JS errors |
| [Native browser lab](vpn-evidence/browser-native.json) | Real headed Chromium/Xvfb; actual input and image; namespace and Seccomp sandbox enabled, UID 995, zero capabilities, no new privileges; isolated network with direct egress unavailable; nft rules parsed in a disposable namespace |
| [Production browser](vpn-evidence/browser-live.json) | Authenticated dashboard API returns the real Shodan page; browser and worker share the VPN namespace, no TCP control listener, private-destination guard installed, browser profile unreadable by web UID, host network/SSH unchanged |
| [Live extraction round](vpn-evidence/browser-live-extraction.json) | After the user's manual verification: three new parsed facet pages saved, 12 cached pages reused, fourth request HTTP 429; checkpoint retained, zero IPs extracted in this round |
| [Final live state](vpn-evidence/browser-final-state.json) | After further user resumes: **28 real IPs** agree in SQLite, report and checkpoint; 21 cached facets; task waiting for rate-limit input, browser closed; complete job still unfinished |
| [Deployment](vpn-evidence/browser-deployment.json) | 1.4.0 active; four jobs, **778 saved IPs**, one user retained at final update (750 existing + 28 new); job files unchanged at upgrade; schema remains 1; backup SQLite restored to a temporary file and checked; final correction restarted only web, preserving the helper/tunnel |

The 20 browser-specific Python tests cover input/URL allowlists, authentication
and CSRF, fixed CDP operations, main-frame HTTP verification plus actual facet
parsing, source rejection without challenge solving/country rotation, worker
lease ownership, manual-input/switch exclusion, loss of isolation, broken pipe
versus HTTP denial, delayed first paint, reservation persistence after a web
restart, and checkpoint continuation without a curl/API fallback. The worker
fixture injects a third-request 403, resumes to 292 **synthetic** IPs, and proves
the first two saved requests are not repeated. These 292 addresses are not live
Shodan results. Separate tests preserve numeric/unbounded Retry-After metadata,
prevent early retry after a one-hour server wait, and prove six verification
actions only read the document without reloading it.

The initial production attempt exposed invalid nft statement separation, which
blocked the browser before launch. The corrected rules were checked by the real
nft parser in a disposable namespace. A subsequent browser startup check exposed
an initial-frame failure; initial navigation now returns separately and frame
polling retries briefly without destroying the session. Both boundaries are
covered by the native check or regression suite. Intermittent real DNS/egress
probe failures correctly refused protected startup, without direct fallback.

The initial production observation was **HTTP 403 / browser_challenge**, with
real VPN egress `135.136.11.182`. The live browser evidence measures reopening the
existing session, not cold-start latency. The user then completed verification
and resumed; the checkpoint's cached facets increased from 12 to 15, and the
fourth request paused on **HTTP 429**. Subsequent attempts encountered repeated
interactive challenges (the user reported six repetitions), with further manual
resumes. The [later observation](vpn-evidence/browser-repeated-challenge.json)
found the worker running after acceptance; it does not prove that every challenge
is accepted or that a whole extraction can finish. By the final safe maintenance
point, the job had saved 28 real IPs (demo=false, source=website-html), and its
SQLite/result report/checkpoint counts matched. The full query is unfinished.

No automated challenge click/solver or clearance transfer was used. Cloudflare
[documents challenge loops and unsupported automation environments](https://developers.cloudflare.com/cloudflare-challenges/troubleshooting/challenge-solve-issues/).
The exact cause of each repeated challenge was not proven. Studio's verification
button performs a fixed DOM read and does not reload the page. The final UI
distinguishes HTTP 429 from a verification request, and the browser transport
preserves Retry-After for the existing checkpoint scheduler. A stable complete
live IP extraction remains unverified. The maintenance update stops at a saved
checkpoint and leaves the task paused, rather than repeatedly contacting Shodan.

No full host reboot, live kill of the user's production VPN, or actual Shodan
credential login was performed. Disconnected-network behavior was verified in
the separate native lab; existing VPN isolation tests and fixtures remain in the
suite. The screenshot-based remote page is keyboard-operable but is not a remote
DOM accessibility bridge; axe applies to Studio's dialog, not the third-party
page's accessibility. Multiple concurrent browser sessions and Direct-mode
interactive browsing are not supported.

Reproduce offline and local checks:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
node --test tests/test_ip_progress.mjs
node --check studio/static/browser.js
bash install-debian.sh --check
bash tools/install_vpn_helper.sh --check
bash tools/install_browser.sh --check
sudo python3 tools/verify_browser_session.py --run-root-lab
# In separate terminals, with Playwright and @axe-core/playwright installed:
python3 tests/serve_vpn_fixture.py --interactive --port 8795
NODE_PATH=/path/to/node_modules node tests/browser_interactive.cjs http://127.0.0.1:8795
```

Refresh the fixture before repeating the UI test; it queues the synthetic job.
The native lab requires the optional dependencies/account and removes only its
own temporary service, code copy and browser profile. No live Shodan request is
sent by these reproduction commands.

Deployment rollback: use the stable pre-feature release
`/opt/shodan-studio/releases/release-C094WAMQ` and the private backup
`/var/backups/shodan-studio/pre-browser-20261024-211324.tar.gz`, following the
[shutdown, unit restoration and data-preservation procedure](BROWSER_SESSION_AR.md).
The intermediate 1.4.0 releases are diagnostics history, not preferred rollback
targets. CI, GitHub merge and production deployment are separate evidence.
