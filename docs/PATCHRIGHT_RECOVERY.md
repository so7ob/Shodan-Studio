# Patchright browser recovery

Shodan Studio 1.6.0 can open a headed browser once when a VPN-backed HTML task
encounters `cf-mitigated: challenge`. The worker saves its checkpoint and exits
before the manager reserves the browser lease. Verification and resume are manual.
The pending query/facet determines the page; saved URLs are never executed.

## Install and select the optional backend

The normal application and Chromium backend remain standard-library based.
Install Python venv support, Xvfb and Xauth, then run as root:

```bash
bash tools/install_browser.sh --patchright
```

This installs Patchright 1.64.3, pyee 13.0.0, greenlet 3.5.6 and
typing_extensions 4.15.0 in `/opt/shodan-studio/browser-runtime/venv`, with
the matching Chromium revision in the adjacent `browsers` directory. The
runtime is root-owned and read-only to the browser account. No browser starts.
The installer requires network access to PyPI and the browser distribution CDN.

Set the root-owned `/etc/default/shodan-studio-browser` file to:

```text
SHODAN_STUDIO_BROWSER_BACKEND=patchright
```

Install the updated VPN service unit, reload systemd, and restart the helper and
application during the deployment window. Omitting the setting, or selecting
`chromium`, uses the original backend. Patchright profiles use a separate
`-patchright` directory under `/var/lib/shodan-studio-browser`; a first login
may be necessary. Cookies stay in that private profile and are not exported.

## Policies and recovery behavior

`settings.browser_recovery` accepts `manual` or `on_challenge`. Eligible new
tasks default to `on_challenge`. A one-time transactional migration enables it
for unfinished existing HTML/VPN tasks that have no explicit policy, including
failed tasks. Completed/cancelled history and explicit opt-outs are preserved.
Migration never starts work or opens a browser.

`POST /api/jobs/{id}/browser-policy` accepts only
`{"browser_recovery":"manual"}` or `{"browser_recovery":"on_challenge"}`.
Existing authentication and CSRF rules apply. The task must be stopped, with no
active browser lease or network operation. The dashboard exposes the same control.

The response's `browser_recovery_attempt` records opening, browser state or a
failure, and `browser_backend` identifies a started backend. Browser responses
include measured dimensions and native browser identity. HTTP User-Agent
settings do not override browser identity; browser extraction disables rotation.

One automatic page navigation consumes one request from the failed run's budget
and is recorded in its checkpoint, statistics and event log. The delay and saved
rate-limit deadlines apply. Attempts are marked before launch and are not replayed
after crashes or polling. A repeated challenge retains the existing browser.
Ordinary authentication errors do not trigger automatic startup; 429 retains its
separate waiting policy. Failure keeps the task stopped, with saved results.

The browser keeps the unprivileged account, private X display/pipe, namespace
firewall and approved HTTPS destinations. Chromium sandboxing is explicitly on.
Service workers and WebSockets are blocked to retain request interception;
downloads, file upload selection, extra windows and dialogs are restricted.

## Validation and rollback

Offline contracts: `python3 -m unittest discover -s tests`. Real browser tests
use synthetic responses in a disconnected, temporary systemd namespace:

```bash
python3 tools/verify_browser_session.py --run-root-lab --backend chromium
python3 tools/verify_browser_session.py --run-root-lab --backend patchright
```

Before deployment, stop scheduling and snapshot the database, job files, browser
profiles, configuration and service units. Verify SQLite integrity and a restored
copy, and record the previous release symlink. Deploy from a tested commit and
require package/health version parity and active services.

For the authorized live check, use only job
`5ba0104d00ff5e62aed75057d438c959`. Inspect its pending page, verify manually,
and run at most one extraction request with a temporary one-request budget.
Restore its original setting and leave it paused. Preserve collected IPs.
Record a remaining challenge as incomplete live acceptance.

Rollback selects the previous release and browser backend and restores only the
policy fields changed by migration. Keep the new runtime and profiles available
for inspection. Retain post-deployment results; restore the full database backup
only for a failed migration before subsequent writes. The additive settings do
not change the checkpoint schema or SQLite user_version.

Patchright can change automation compatibility but does not guarantee Cloudflare
clearance. See the [Patchright documentation](https://github.com/Kaliiiiiiiiii-Vinyzu/patchright-python)
and [Cloudflare browser support](https://developers.cloudflare.com/cloudflare-challenges/reference/supported-browsers/).
