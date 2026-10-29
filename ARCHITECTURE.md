# Shodan Studio 1.5.0 — architecture

## Cross-job inventory and enrichment — Issue #33

`targets.py` owns additive SQLite inventory, discovery evidence, immutable host
snapshots, current service metadata, automatic claims and enrichment item state.
Inventory evidence has no cascading job ownership: it survives job deletion.
IP identity includes the real/demo dataset. Discovery filters correlate task,
query, source and time within the same observation. Lists use SQL pagination and
exports use one bounded read snapshot; dashboard polling never contacts Shodan.

Jobs have `kind=extraction|enrichment` (legacy default: extraction). Enrichment
shares the scheduler, worker process entrypoint, controls, pacing/rate-limit
implementation, request history, VPN helper lease, accounts and interactive
browser. Its adapter reads validated Shodan host pages or the host API and stores
allowlisted metadata rather than raw banners. The browser resource validator
accepts canonical host URLs as well as the existing facet URLs; verification
must parse the exact requested resource. Enrichment preserves a separate source
policy while the existing `mode` reports the active source.

The manager snapshots selected targets to a private, owned manifest at launch.
Automatic jobs inherit origin-task settings and accept additional targets only
before their first claim. Enrichment checkpoints persist item outcomes, metadata
and source wait deadlines before IPC; replay uses the same request identity.
Extraction records already received API host metadata in a private sidecar for
crash recovery. Existing extraction checkpoints retain their format; enrichment
checkpoints are explicitly discriminated and imported paused.

Optional persistent enrichment API credentials use the existing account cipher
and private key file, with ciphertext in a separate table. They are absent from
job documents, events, checkpoints, exports and argv. Core HTML operation retains
the standard-library-only dependency boundary. See `docs/TARGET_REPOSITORY_AR.md`.

This release is a self-hosted, single-user application for Debian 12 and a trusted
local network or an SSH tunnel. It uses Python's standard library, SQLite and a
buildless Arabic browser interface. It is not packaged as a publicly exposed,
multi-tenant service.

## Components

| Component | Responsibility |
|---|---|
| `studio/server.py` | WSGI routes, setup/login/session/CSRF/Host checks, static files, HTTP listener |
| `studio/store.py` | SQLite WAL, atomic queue claims, events, password/session hashing |
| `studio/jobs.py` | One-worker scheduler, typed actions, memory-only keys, exports and checkpoint import |
| `studio/worker.py` | Isolated process adapting the collection engine into structured events and controls |
| `studio/engine.py` | ShodanSpider source-resume core and legacy traversal |
| `studio/adaptive.py` | Bounded cost-based partition selection, direct IP probing and deterministic cache replay |
| `studio/config.py` | Job schema and range validation; no shell parsing |
| `studio/static/` | Browser interface; same-origin JSON polling every two seconds |
| `deploy/` | Unprivileged systemd service |

## Job lifecycle

New tasks enter `queued`, unless an explicit API task needs a key. The scheduler
atomically claims one task and launches `python3 -m studio.worker`. Its input is a
JSON object sent through stdin. User queries are data, never executable commands.
The API key is omitted from the process command line, persistent job document,
event log, checkpoint and exports. The server keeps keys in process memory; a
restart requires re-entry for API work.

The worker writes JSON lines for progress, warnings and final state. The manager
stores these in SQLite and the browser polls by increasing event cursor. Recent
logs are bounded to 10,000 events per task. Results are deduplicated per task;
the overview sums per-task counts and does not claim uniqueness across tasks.

Pause/cancel controls are written atomically in the private task directory. The
worker checks them between requests and during interruptible retry sleeps. A
request already in progress may finish or reach its configured timeout first.
Cancellation keeps collected results, while resuming a cancelled task is disabled;
duplicating it creates an independent new task.

On startup the HTTP listener binds before the queue starts. A failed bind cannot
silently start queued network work. A process-level lock prevents two schedulers
using the same data directory. Interrupted active tasks require manual resume.
Queued tasks can start when the service restarts; queued API tasks without a key
become `waiting_input`.

## Recovery and checkpoint boundaries

Each task owns a private directory containing its checkpoint, outputs and control
file. Imported v6/v7 checkpoints are validated as JSON data, their output paths
are rebound to that directory, and their old output hashes are removed. Cached
queries, IPs and API pagination state are validated without making requests.
Imported tasks stay paused for review. Synthetic Studio checkpoints retain their
demo marker and cannot silently become live queries on import.

The worker verifies the exact owned result/report paths and TXT format before
resuming. Those generated outputs may be regenerated from the checkpoint if a
crash occurred between committing outputs and recording their hashes. This
controlled regeneration does not allow arbitrary paths or symlink outputs.

Source switching retains the original query and its scope. Completed API leaves
can be reused in HTML; an HTML IP leaf is conservatively revisited in API mode.
Cached facet snapshots retain source provenance. Switching source creates a
coverage warning because the snapshots may not describe identical data.

An eligible API authentication/permission/credit failure can fall back to HTML
once in a worker run. If both sources fail, the task waits for browser input.
HTTP 429 uses a separate bounded retry policy; persisted Retry-After deadlines
are respected on resume and are not cleared by source changes.

## Progress semantics

The primary list/detail bars consume only `job.ip_progress`. The unchanged
`stats.percent` remains a legacy branch metric for older clients. The adapter
uses the supplied IP Progress Integration Kit v1 and recognizes Studio's
`completed_warnings` success state, gated by successful traversal of every leaf.

`job_ips(job_id, ip)` has a composite primary key and cascading job ownership.
Worker IP batches are canonicalized and inserted with `INSERT OR IGNORE`;
`stats.unique_ips` is updated from the database count in the same transaction.
The cached exact count and numeric `_ip_progress_inputs` live in `jobs.document`.
Plans above 1,000 leaves are summarized into at most three numeric buckets;
`leaf_count` preserves cardinality while expected counts sum only remaining
records. This supports the existing 100,000-node limit without oversized IPC.
Public responses strip private inputs and recalculate only the inexpensive
estimator, using current status so interruption/cancellation cannot show 100%.
Progress/final events include the same `ip_progress` payload. IP batches are not
stored in the event log. Results and TXT/CSV/JSON exports use the persisted IP set.

The plan adapter consumes `plan.extraction_order`, drops duplicate queries and
ancestors, and checks the scope trie. Country/city/ASN/port sibling buckets can
be disjoint service-record scopes, although the same IP can occur in several
leaves. Sibling product/version/org/os text searches are not assumed exclusive;
ambiguous scopes or unknown unfinished counts yield an indeterminate bar.
Tree-mode planning remains unknown until successful traversal because the engine
does not build a complete terminal plan in that mode.

The kit estimates total IPs as the database count plus estimated remaining IPs.
This adapter retains the conservative one-new-IP-per-remaining-record prior:
completed caches cannot establish a reliable global processed-record/dedup ratio.
Partial API progress subtracts rows only from persisted `api_progress` with one
unique banner ID per received row, full page shapes, valid IP counts, and no
API pagination warning. HTTP attempts and retried records never count as work.
The denominator can change and is never a coverage guarantee.

`saved_config()` adds the numeric-only `studio_ip_progress` checkpoint extension
through the existing atomic checkpoint writer. It does not alter engine schema,
search scopes, queries, source selection, pagination or request counts. Startup
reconciles all job files/checkpoints once with SQLite, before queue startup, to
recover lost IPC and support re-upgrade after rollback. Normal API polling does
not scan results/checkpoints or contact Shodan. Legacy jobs without a stored plan
remain unknown until the plan can be recovered or rebuilt during normal resume.

`requests_this_run` is measured against that run's request budget. `requests`
includes previous resumes. API credentials, quota, web-page accessibility and
upstream coverage remain properties of the configured source.

## Deployment boundary

The installer places versioned application code under `/opt/shodan-studio`,
preserves `/var/lib/shodan-studio`, and uses a dedicated system account. It does
not install operating-system packages or change firewall rules. Default binding
is loopback. LAN access needs an exact Host allowlist; remote individual use can
keep loopback binding and use SSH port forwarding.

`--secure-cookies` only selects HTTPS browser cookies/origin expectations behind
a correctly configured proxy. It does not add TLS to the Python listener or make
the standard-library reference HTTP server a hardened public production stack.
For the installation steps and backup instructions, see `README_AR.md`.

## VPN extension (1.2)

`vpn_config.py` parses policy/config data; `vpn.py` owns the provider interface,
public registry, health/cooldown and durable audit. `vpn_helper.py` owns only the
fixed namespace/interface and approved root-only files. `vpn_client.py` bridges
worker stdin/events over an authenticated Unix socket. The helper enters the
namespace then drops privileges before launching the existing worker. Neither
curl nor Python gets a host network fallback. `vpn_probe.py` has fixed, bounded
probes. Metadata migration is additive and backup-first (`vpn_schema.py`).

The existing one-worker queue remains authoritative. Bounded request retries
occur at the engine request boundary and retain budget accounting. Switching
occurs only after worker exit/atomic checkpoint persistence. Failed health,
profile cooldowns, allowlists, and a persisted lifetime switch budget govern
recovery. HTTP permission/quota/rate limiting is not a VPN-switch signal.
A helper lease rejects concurrent switches while its worker is alive. Restarted
jobs retain results and lose stale verified-health claims.

See [VPN operating guide](docs/VPN_MANAGER_AR.md),
[deployment and rollback](docs/VPN_DEPLOYMENT_AR.md), and
[discovery/design evidence](docs/VPN_DISCOVERY.md).

## Premium extension (1.3)

`premium.py` implements the AmneziaVPN 5.0.3.0 gateway protocol, with fixed HTTPS
origins and the pinned production RSA public key. A root-private record persists
an independent worker UUID. Each country connection obtains a fresh AWG config
for that UUID; no native export or revoke operation exists. Public country IDs
are deterministic UUID5 values and reuse the existing job allowlists and audit.

The gateway subprocess runs as `shodan-vpn-gateway`, separate from web/worker,
with all capabilities dropped and a 28-second deadline. Credentials cross private
pipes only. The root bootstrap tool reads the installed client without modifying
it. The authenticated Premium API cannot choose a gateway or command.

Connection verification retries the same tunnel at most three times. Account and
protocol failures stop failover, as do destination-only failures on a healthy
tunnel. Dashboard reads during the helper's periodic probe return unverified
busy status immediately. No database schema change is required beyond VPN v1.

Adaptive planning and legacy checkpoint boundaries are described in [the planner design](docs/ADAPTIVE_PLANNER.md) and [the Arabic operations guide](docs/ADAPTIVE_PLANNER_AR.md).
