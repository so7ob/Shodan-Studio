# Shodan Studio: IP progress adaptation

## Independent execution spaces — Issue #35

Reuse the operations design. Two keyboard-accessible navigation controls open
`/extraction` and `/enrichment`; metrics, tables and creation intent follow the
selected space. One compact status line keeps both lanes visible. The VPN manager
and diagnostics share an explicit space selector; job controls follow the job's
kind. Existing RTL, fonts, tokens and dialogs remain the reference. The workspace
footer uses `--muted` to meet contrast when auditing the full workspace.


## Target repository and enrichment jobs — Issue #33

Keep the existing Arabic RTL operations dashboard: dark, precise, compact and
legible. Reuse its fonts, `--bg`, `--panel`, `--text`, `--muted`, `--line`,
`--cyan` and monospace figures. The inventory uses a horizontal numeric summary,
labelled filters, direct-labelled distributions, and a paged evidence table.
Its distinguishing behavior is one IP with its complete discovery trail, while
discovery time, enrichment time and upstream observation time stay explicit.

Native inputs, meters and dialogs carry the interaction. The existing create,
detail, network, browser and resume controls serve enrichment jobs. Their progress
counts processed targets and presents outcomes separately. Background refresh
retains selection/focus; errors are announced, ordinary refreshes are not.
IP/query text is LTR, source text is escaped, and mobile tables scroll inside
their containers. No new fonts, framework, images, decorative motion or theme.

Audit: rendered at 375/1280, with keyboard navigation, stable focus and selection,
and zero axe violations in the inventory and target/enrichment/runtime dialogs.
The operational layout fits the existing dense data tool; the audit score is 9/10.
Manual screen-reader testing was not performed. Machine-readable evidence and
screenshots are under `docs/target-repository-evidence/`.

Issue #31 adds request history within the existing Arabic RTL dashboard. A compact
current/latest request card sits beside progress and pacing; the execution log
defaults to expandable request rows with a separate all-events view. Keep current
fonts, tokens and controls. Render queries LTR and facet labels as text, distinguish
service records from unique IPs, and label missing historic data explicitly. Polls
update existing rows without collapsing details, replacing focused controls or
resetting the user's scroll position. Load older attempts and facet values only
on demand; announce errors without announcing every background update.

Issue #31 verification: the authenticated fixture passed 375/1280 RTL, keyboard
focus, expanded-state retention, 100-value pagination, reload and axe (zero
violations). Screenshots and machine-readable evidence are under
`docs/request-history-evidence/`; no manual screen-reader audit was performed.

The existing Arabic RTL operations dashboard is the design reference. This is a
focused metric change, preserving its buildless HTML/JS structure. The interface
should remain dark, precise, compact and legible: “clear collection status”.

Use existing tokens: `--font` (Tahoma/Segoe UI), `--mono` for tabular figures,
`--bg`, `--panel`, `--text`, `--muted`, `--line`, `--cyan`. No new font download,
global theme, UI framework or decorative element. The main information order is
unique IP count and estimated total, estimated percentage, secondary leaf count,
then coverage warnings. Explicit unknown and successful-zero states are required.

The supplied component is adapted to those tokens. It uses textContent, numeric
ARIA values only with a known denominator, reduced-motion support, and isolated
LTR branch ratios within RTL text. Animation does not interpolate layout width.
The table's absolute accessible label is contained by its existing scroller;
mobile detail actions wrap below the heading.

Issue #29: retain the same tokens and layout. Show a numeric estimated reference
against the source record total while unique-IP planning is incomplete; explicitly
label the two units and keep branch counts secondary. Countdown text includes the
configured task interval, uses server time, and stays in place between requests.
Preserve non-live timer announcements and numeric progressbar ARIA semantics.

2026-10-24 audit: verified actual authenticated page at 1280 and 375 CSS pixels,
keyboard entry to details, no document horizontal overflow, matching list/detail
65% bars for synthetic 512/782 and 16/77, and zero axe violations in the changed
progress widgets. The existing table scrolls horizontally on mobile. Screenshots
and browser results are in `docs/ip-progress-evidence/`. This is not a full-site
accessibility certification; manual screen-reader testing was not performed.

## VPN Manager extension — 2026-10-24

Preserve the existing compact Arabic RTL operational dashboard, fonts and dark
palette. The design remains precise, practical and legible. Add two navigation
items, a dense profile/audit table, a definition-list connection summary, and
separate host/worker diagnostic panels. No external fonts, images or UI framework.
Use existing `--panel`, `--line`, `--text`, `--muted` and button tokens; tables scroll
within their container on mobile. Native modal forms and text labels keep actions
keyboard accessible. An unverified request must never appear as successful.

Acceptance: VPN page at 375/1280, no document overflow; zero axe violations in VPN,
diagnostics, job-network and policy controls; keyboard job entry and modal close.
Evidence uses a simulated provider and is labelled accordingly. Namespace/runtime
proof is a separate root-only lab; these screenshots do not prove a Premium egress.

## Dynamic Premium catalog

Keep the same Arabic RTL tokens and native dialogs. A subscription status panel
precedes the existing connection table; a labelled search input handles a long
country list without changing the queue/detail layout. Show cached-versus-gateway
catalog provenance, device registration and slot counts separately from verified
tunnel status. Never preload or display subscription credentials. Premium country
labels come from the account catalog and cannot be edited into a false location.

## Patchright recovery controls — 1.6.0

Keep the compact Arabic RTL controls and existing tokens. Place recovery status
and the automatic/manual policy beside the interactive browser action. Opening a
server session never opens a modal or moves focus. Verification and resume remain
explicit actions; failures are visible in text. Use measured frame dimensions for
pointer mapping. Check keyboard operation, overflow and axe at 375/1280.

## Automatic planning and request pacing — Issue #23

Keep the existing Arabic RTL dashboard. Show the reported source service total
next to IP progress, explicitly separate from the distinct-IP estimate. Place a
text countdown below progress; label ordinary request spacing separately from
source rate-limit waits. Use a timer role without per-second live announcements,
retain the existing colors and typography, and hide legacy facet ordering in
adaptive mode. No new fonts, animations or layout system.

## Saved Shodan accounts — Issue #25

Use the existing Arabic RTL controls and colors. Account management is a named
modal reachable from the sidebar and job network card. Show account labels and
usernames; passwords are write-only and empty on edit. The job has a labelled
account selector, and the browser has a separate sign-in action with explicit
submission/verification status. Account CRUD, keyboard entry and sign-in controls
are checked at 375/1280 with axe. No new fonts, framework or visual theme.
