"""IP-centric estimated progress for Shodan Studio (Python >=3.10; stdlib only).

Separate job progress from collection completeness. Shodan facet counts usually
represent service records, not distinct IP addresses. All totals returned by
this module are estimates unless a finished job is being described.

The integration must pass *disjoint terminal extraction leaves*, never both a
parent AND its descendants; doing so would double count expected work.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
import math
from typing import Any


FINISHED_BRANCH_STATES = frozenset({"done", "completed", "complete", "succeeded", "success"})
SUCCESS_JOB_STATES = frozenset({"completed", "completed_warnings", "complete", "succeeded", "success", "finished"})
PRIOR_RECORDS = 100
MIN_YIELD_RATIO = 0.05


def _nonnegative_int(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a non-negative integer, not a boolean")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and value.isascii() and value.isdecimal():
        number = int(value)
    else:
        raise ValueError(f"{field} must be a non-negative integer")
    if number < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return number


def _optional_count(value: Any, field: str) -> int | None:
    return None if value is None else _nonnegative_int(value, field)


def _branch_complete(branch: Mapping[str, Any]) -> bool:
    if "completed" in branch and isinstance(branch["completed"], bool):
        return branch["completed"]
    return str(branch.get("status", "pending")).strip().lower() in FINISHED_BRANCH_STATES


def calculate_ip_progress(
    *,
    extracted_unique_ips: int,
    branches: Iterable[Mapping[str, Any]],
    planning_complete: bool,
    job_status: str,
    successfully_processed_records: int | None = None,
    prior_records: int = PRIOR_RECORDS,
) -> dict[str, Any]:
    """Return a JSON-serializable, conservative estimated IP progress object.

    branches must consist of nonoverlapping *leaf* extraction branches. Keys:
      expected_records: service-row count returned by facet planner, or None;
      processed_records: service rows already successfully consumed by the
          extractor for this leaf (not HTTP attempts), or None;
      completed: boolean or status: done/pending/running/failed.

    If no reliable expected_records count exists for ANY unfinished leaf, the
    total and percentage are deliberately unknown until that leaf resolves.
    The estimator starts with a prior yield ratio of 1 new unique IP per
    service row, then gradually adjusts it using actual processed records.
    It is only an estimate; facet counts may omit records or change over time.
    """
    unique = _nonnegative_int(extracted_unique_ips, "extracted_unique_ips")
    observed = _optional_count(successfully_processed_records, "successfully_processed_records")
    prior = _nonnegative_int(prior_records, "prior_records")
    if prior == 0:
        raise ValueError("prior_records must be positive")
    if not isinstance(planning_complete, bool):
        raise ValueError("planning_complete must be a boolean")
    if not isinstance(job_status, str):
        raise ValueError("job_status must be a string")

    rows: list[Mapping[str, Any]] = list(branches)
    finished = 0
    remaining_service_records = 0
    unknown_leaf_count = 0
    total_leaves = 0

    for index, branch in enumerate(rows):
        if not isinstance(branch, Mapping):
            raise ValueError(f"branches[{index}] must be a mapping")
        complete = _branch_complete(branch)
        # The Studio adapter can coalesce a large plan into numeric buckets.
        # Record counts in a bucket are already summed; only cardinality scales.
        leaf_count = _nonnegative_int(branch.get("leaf_count", 1), "leaf_count")
        if leaf_count < 1:
            raise ValueError("leaf_count must be positive")
        total_leaves += leaf_count
        if complete:
            finished += leaf_count
        expected = _optional_count(branch.get("expected_records"), f"branches[{index}].expected_records")
        processed = _optional_count(branch.get("processed_records"), f"branches[{index}].processed_records")
        if complete:
            branch_remaining = 0
        elif expected is None:
            branch_remaining = None
            unknown_leaf_count += leaf_count
        elif processed is None:
            branch_remaining = expected
        else:
            branch_remaining = max(0, expected - processed)
        if branch_remaining is not None:
            remaining_service_records += branch_remaining

    pending_leaves = total_leaves - finished
    job_succeeded = job_status.strip().lower() in SUCCESS_JOB_STATES

    if observed is None or observed == 0:
        ratio = 1.0
        yield_basis = "conservative_default"
    else:
        ratio = max(MIN_YIELD_RATIO, min(1.0, (unique + prior) / (observed + prior)))
        yield_basis = "observed_dedup_ratio"

    # No exact percentage can be inferred during planning, or while incomplete
    # branches have unknown counts (especially after an unresolved fallback).
    estimation_possible = bool(planning_complete and total_leaves > 0 and unknown_leaf_count == 0)
    if job_succeeded and planning_complete and pending_leaves == 0:
        estimated_remaining_ips = 0
        estimated_total_ips = unique
        percent: int | None = 100
        basis = "planned_work_finished"
    elif estimation_possible:
        # ceil is conservative against overstating completion for small leaves.
        estimated_remaining_ips = math.ceil(remaining_service_records * ratio)
        estimated_total_ips = unique + estimated_remaining_ips
        if estimated_total_ips:
            percent = min(99, round(100 * unique / estimated_total_ips))
        else:
            # No IP discovered, and 0 records remain, but the job has not
            # transitioned into its successful final state.
            percent = 0
        basis = "estimated_unique_ips"
    else:
        estimated_remaining_ips = None
        estimated_total_ips = None
        percent = None
        basis = "unknown_until_planned" if not planning_complete else "unknown_unresolved_branches"

    return {
        "calculation_mode": basis,
        "is_estimate": basis != "planned_work_finished",
        "extracted_unique_ips": unique,
        "estimated_total_ips": estimated_total_ips,
        "remaining_estimated_ips": estimated_remaining_ips,
        "progress_percent": percent,
        "planning_complete": planning_complete,
        "completed_leaves": finished,
        "total_leaves": total_leaves,
        "remaining_leaves": pending_leaves,
        "unknown_remaining_leaves": unknown_leaf_count,
        "observed_processed_records": observed,
        "estimated_unique_ips_per_record": round(ratio, 4),
        "yield_basis": yield_basis,
        "job_finished_successfully": bool(job_succeeded and planning_complete and pending_leaves == 0),
        "coverage_note": (
            "النسبة تقديرية مبنية على عناوين IP الفريدة المتاحة وعدّادات سجلات الخدمات "
            "المتبقية؛ ولا تمثل ضمانًا لاكتمال بيانات Shodan."
        ),
    }


def attach_ip_progress(
    job_json: dict[str, Any],
    *,
    branches: Iterable[Mapping[str, Any]],
    planning_complete: bool,
    processed_records: int | None = None,
    unique_ip_count_field: str = "unique_ips",
) -> dict[str, Any]:
    """Non-mutating adapter for an existing dashboard/API job payload.

    Preserve existing `progress_percent` (branch-based) for compatibility;
    let the new UI consume nested `job['ip_progress']` exclusively.
    """
    result = dict(job_json)
    result["ip_progress"] = calculate_ip_progress(
        extracted_unique_ips=result.get(unique_ip_count_field, 0),
        branches=branches,
        planning_complete=planning_complete,
        job_status=str(result.get("status", "pending")),
        successfully_processed_records=processed_records,
    )
    return result


# Studio adapter. No network, requests counters, or per-branch IP sums enter it.
def terminal_leaves(plan: dict) -> tuple[list[dict], bool]:
    """Deduplicate leaves and remove ancestors, then prove record disjointness.

    ASN and port buckets are disjoint service-record scopes, NOT disjoint IP
    sets. Text product/version (also org/os) sibling searches are deliberately
    not assumed exclusive. An ambiguous tree gets no numeric denominator.
    """
    tree: dict = {}
    queries = set()
    valid = True
    for leaf in plan.get("extraction_order", []):
        query = leaf.get("query")
        if not isinstance(query, str) or not query:
            return [], False
        if query in queries:
            continue
        queries.add(query)
        node = tree
        for part in leaf.get("path", []):
            facet, value = part.get("facet"), part.get("value")
            if not isinstance(facet, str) or not isinstance(value, str):
                return [], False
            node = node.setdefault((facet, value.strip().casefold()), {})
        if None in node:
            valid = False  # Different queries claiming the same scope.
        node[None] = leaf

    leaves = []
    def visit(node):
        nonlocal valid
        children = [key for key in node if key is not None]
        if children:
            facets = {key[0] for key in children}
            if len(facets) != 1 or (len(children) > 1 and not facets <= {"country", "city", "asn", "port"}):
                valid = False
            for key in children:
                visit(node[key])
        elif None in node:
            leaves.append(node[None])
    visit(tree)
    return leaves, valid


def crawler_progress_inputs(crawler) -> dict:
    """Summarize the already-built plan and committed pagination checkpoints.

    Keep the kit's conservative yield prior. Completed caches do not retain
    enough banner identity information to measure a global dedup yield safely.
    Partial API rows are usable only when every received row has a distinct ID,
    the page shape is complete, and that query has no pagination warning.
    """
    plan = crawler.report.get("plan")
    traversed = crawler.report.get("traversal_completed") is True
    if not isinstance(plan, dict):
        return {"branches": [], "planning_complete": traversed,
                "traversal_completed": traversed, "denominator_reason": "planning_incomplete"}
    leaves, disjoint = terminal_leaves(plan)
    branches = []
    for leaf in leaves:
        query = leaf["query"]
        # A saved cache counts as completed only after collect_ips marked the
        # leaf completed. read_page checkpoints its cache BEFORE HTML collection.
        complete = leaf.get("status") == "completed"
        expected = leaf.get("expected_count")
        if type(expected) is not int or expected < 0:
            expected = None
        processed = None
        saved = crawler.api_progress.get(query)
        if saved and crawler.args.mode == "api":
            # first_total belongs to the retained pagination snapshot, and can
            # supersede an older facet count without another network request.
            expected = saved["first_total"]
            received = saved["received"]
            pages = saved["next_page"] - 1
            bad = any(w.get("query") == query and w.get("code", "").startswith("API_")
                      for w in crawler.report.get("warnings", []))
            full_pages = received == min(pages * 100, expected)
            if (not bad and full_pages and received == len(set(saved["known_ids"]))
                    and received == sum(saved["counts"].values())):
                processed = received
        branches.append({"expected_records": expected if disjoint else None,
                         "processed_records": processed if disjoint else None,
                         "completed": complete})
    return {"branches": compact_branches(branches),
            "planning_complete": crawler.report.get("planning_stage") in {"extracting", "completed"},
            "traversal_completed": traversed,
            "denominator_reason": "terminal_record_scopes" if disjoint else "overlapping_or_unproven_scopes"}


def compact_branches(branches: list[dict]) -> list[dict]:
    """Keep up to 100,000 configured leaves below IPC/JSON storage limits.

    Buckets retain exact leaf cardinalities and sum only remaining service
    counts. This is an estimator-input summary, never a new extraction plan.
    """
    if len(branches) <= 1000:
        return branches
    groups = {}
    for row in branches:
        kind = "done" if row["completed"] else "unknown" if row["expected_records"] is None else "known"
        group = groups.setdefault(kind, {"completed": kind == "done", "leaf_count": 0,
                                        "expected_records": None if kind == "unknown" else 0,
                                        "processed_records": None})
        group["leaf_count"] += 1
        if kind == "known":
            group["expected_records"] += max(0, row["expected_records"] - (row["processed_records"] or 0))
    return list(groups.values())


def progress_from_job(job: dict) -> dict:
    """Use SQLite's persisted per-job distinct count, never worker counters."""
    inputs = job.get("_ip_progress_inputs") or {}
    status = job.get("status", "queued")
    if not inputs.get("traversal_completed"):
        status = "running" if status in SUCCESS_JOB_STATES else status
    result = calculate_ip_progress(
        extracted_unique_ips=job.get("stats", {}).get("unique_ips", 0),
        branches=inputs.get("branches", []),
        planning_complete=inputs.get("planning_complete", False),
        job_status=status,
    )
    result["denominator_reason"] = inputs.get("denominator_reason", "planning_incomplete")
    return result


def validate_progress_inputs(value: dict) -> dict:
    """Accept the optional numeric-only Studio checkpoint extension."""
    branches = value.get("branches")
    if not isinstance(branches, list) or len(branches) > 100000:
        raise ValueError("Invalid progress branches")
    if type(value.get("planning_complete")) is not bool or type(value.get("traversal_completed")) is not bool:
        raise ValueError("Invalid progress state")
    clean = []
    for row in branches:
        if not isinstance(row, dict) or type(row.get("completed")) is not bool:
            raise ValueError("Invalid progress leaf")
        clean.append({"completed": row["completed"],
                      "expected_records": _optional_count(row.get("expected_records"), "expected_records"),
                      "processed_records": _optional_count(row.get("processed_records"), "processed_records"),
                      "leaf_count": _nonnegative_int(row.get("leaf_count", 1), "leaf_count")})
    if any(row["leaf_count"] < 1 for row in clean) or sum(row["leaf_count"] for row in clean) > 100000:
        raise ValueError("Invalid progress leaf count")
    reason = value.get("denominator_reason", "planning_incomplete")
    if reason not in {"terminal_record_scopes", "planning_incomplete", "overlapping_or_unproven_scopes"}:
        reason = "planning_incomplete"
    return {"branches": clean, "planning_complete": value["planning_complete"],
            "traversal_completed": value["traversal_completed"], "denominator_reason": reason}
