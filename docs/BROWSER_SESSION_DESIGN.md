# Isolated interactive HTML session (Issue #4)

The existing Python server, queue and VPN namespace remain authoritative. A new
optional Chromium process runs headed on a private Xvfb display as a dedicated
unprivileged account inside `ssvpn-worker`. Chromium's sandbox stays enabled.
There is no VNC, CDP TCP listener, external frontend library, cookie export or
challenge-solving code. A private CDP pipe carries fixed screenshot/input/page
operations; the root broker does not accept JavaScript, process arguments or
arbitrary URLs. Browser documents/requests are restricted to Shodan and the
Cloudflare challenge host. File uploads/downloads and popup windows are disabled.

Authenticated CSRF-protected dashboard actions select a stopped HTML job and its
already verified VPN. The session reserves that job's tunnel and the single queue
slot until closed or idle-expired. Resume uses the same browser profile and page
for the existing facet parser. A challenge/login/denial pauses the worker at its
checkpoint; manual interaction is disabled while extraction runs. The browser
must be closed before changing the VPN; switching never transfers clearance.
Enabled Failover now closes the browser after the worker releases its lease,
switches on a fresh 429 or persistent Shodan transport failure, and starts a blank
browser using the new VPN profile's own directory. The worker performs the first
navigation through its normal request budget and persisted Retry-After checks.
Saved waits alone cannot request another switch. Login/challenge states still
require interaction when the newly selected profile is not authorized.

A separate private profile directory stores browser state, outside application
SQLite and out of static/download endpoints. Only root and the browser UID can
read it. Input text, screenshots, HTML and cookies are not written to audit logs.
The dashboard displays compressed page images with mouse/keyboard controls over
its existing authenticated HTTP API. No new public port or host route is added.

Broker/host restart invalidates the live browser process and verification state.
A web-service-only restart restores a live broker lease, but still verifies the
page again before resume. Profiles may persist. Missing Chromium,
sandbox failure, lost tunnel, expired session or unavailable source fails closed.
Data and checkpoint formats remain compatible; this requires no database migration.

Login redirects can leave the current tab on an account/home page. Version 1.4.1
reports `off_task_page` and offers an explicit return button. The existing `verify`
RPC accepts the exact optional pair `return_to_results: true`; the child uses its
server-owned pending facet URL, never a caller-supplied URL. Ordinary verification
and frame polling stay read-only. Returning does not enable resume: the current
document and its main-frame HTTP response must match the expected query/facet,
return HTTP 200 without a challenge, and pass the facet parser. Equivalent query
parameter order/encoding is accepted; different queries, facets and endpoints are
not. Navigation invalidates readiness. No helper protocol allowlist expansion,
VPN switch, profile replacement or database migration is needed for this fix.

Real challenge acceptance requires the user. Offline and local browser tests can
prove transport, controls, security and checkpoint behavior, not Shodan consent.
Cloudflare documents production challenges as unsupported in automated browsers;
this integration neither hides automation signals nor solves challenges itself.
