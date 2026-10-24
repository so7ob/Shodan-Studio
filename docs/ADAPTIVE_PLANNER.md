# Adaptive request planning (Issue #6)

Design: add an adaptive strategy for new jobs while preserving priority/tree
checkpoints exactly. Start at the original query's IP facet. Collect each valid
page immediately and stop when the returned row counts account for its total.
A service-record count is not a distinct-IP count: even a large record total may
fit on one IP page. API mode uses existing paginated IP search directly.

Only an incomplete HTML scope needs partitioning. Probe supported facets within
a bounded candidate list, estimate downstream requests from bucket counts and
oversized children, and stop probing once another probe cannot pay for itself
against the theoretical leaf-count lower bound. Choose the cheapest observed
complete partition; never force country or city. Missing/unknown/truncated or
non-reducing partitions are rejected. If no safe split remains, keep the IPs
already collected and report an unresolved coverage warning.

Each pending child is verified through its IP page before any further split.
A text facet may overlap or have stale counts; actual child results control the
next decision. Query narrowing, deduplication, request budgets, Retry-After,
source validation and fail-closed browser transport stay authoritative.

Rebuild decisions deterministically from checkpointed pages on resume; no saved
URL or executable plan is trusted. Completed pages are reused without HTTP.
The plan is provisional while a pending scope might split. Reports retain
candidate estimates, rejection reasons, selected facets and bounded probe counts.
The heuristic minimizes observed cost; it cannot promise a global optimum from
unseen facets or prove completeness of a changing external search index.
