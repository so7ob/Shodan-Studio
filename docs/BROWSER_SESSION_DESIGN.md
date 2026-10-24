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

Real challenge acceptance requires the user. Offline and local browser tests can
prove transport, controls, security and checkpoint behavior, not Shodan consent.
Cloudflare documents production challenges as unsupported in automated browsers;
this integration neither hides automation signals nor solves challenges itself.
