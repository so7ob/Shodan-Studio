# Shodan Studio: IP progress adaptation

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
