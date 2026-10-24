# Shodan Studio 1.0.0 — architecture

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
| `studio/engine.py` | ShodanSpider 7.1.0 source-resume engine, unchanged from its standalone release |
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

During discovery/partitioning the final number of leaves is unknown. During
priority extraction, the denominator is the number of known planned leaves,
including explicit unresolved fallback leaves. The percentage is completed
known leaves divided by that denominator. A completed traversal does not promise
a full Shodan export. The planner selects the first useful configured facet and
orders eligible leaves by record count; it is a heuristic, not a proof of the
minimum possible number of requests or maximum unique-IP yield.

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
