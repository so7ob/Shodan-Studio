# Adaptive request planning (Issue #6)

Design: use an adaptive strategy for new jobs while preserving priority/tree
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

## Automatic grouping and pacing (Issue #23)

Complete facet snapshots are eligible even when their totals differ from an
older parent probe. The comparison is recorded as `SNAPSHOT_COUNT_CHANGED`;
missing bucket counts or a mismatch within the same facet page still rejects
that candidate. Small buckets are packed deterministically with best-fit
decreasing into groups of at most 100 estimated service records before scoring.
Each member passes the original scope checks. The query uses Shodan's documented
[comma-list OR filters](https://book.shodan.io/getting-started/query-syntax/),
with independently quoted/escaped values and the original exclusions retained.
A group can split on the same facet again if its observed size grows.

The adaptive UI chooses candidates automatically and hides legacy ordering.
Explicit CLI candidate subsets remain supported, with automatic probe ordering.
Reports expose raw bucket counts beside grouped children. The root's reported
service count is displayed separately from estimated unique-IP progress; it is
never substituted for the unique-IP denominator. While that denominator is unknown,
the UI uses a clearly labeled provisional comparison with source records, such as
100 unique IPs / 579 expected records = 17% estimated. It prefers the unique-IP
estimate when available, preserves the conservative API fields, and reserves 100%
for successful completion of the planned work.

The worker emits an absolute `stats.request_wait.until` deadline and a reason
(`request_delay` or `rate_limit`) before waiting, and clears it in a finally block.
The UI derives the remaining time every second, including after reload, and hides
ordinary pacing for paused or finished jobs. Persisted Retry-After deadlines and
unbounded holds retain precedence and their existing retry behavior.

Issue #29 synchronizes that countdown with `X-Studio-Server-Time` and elapsed
`performance.now()` time, so a skewed browser clock does not change the wait.
The label includes the job's configured delay. It reaches zero while the wait is
still active, then retains the configured interval between requests instead of
disappearing. Reloading uses the existing deadline; it does not start a new wait.
Worker progress snapshot time counts toward the same monotonic deadline. Normal
request pacing is bounded by the job setting; Retry-After remains a separate wait.

Offline regression using anonymized bucket sizes from the reported query:
53 port buckets previously scored 60 extraction requests. Grouping and accepting
the complete 580-record ASN snapshot against the older 581-record parent selects
four initial ASN branches after three facet probes, with eight estimated downstream
requests. One branch still needs direct verification and possibly further splits;
these are estimates, not a live extraction result or a promised final branch count.
