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
