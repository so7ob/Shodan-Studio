"""Bounded, lazy HTML partitioning; decisions use validated cached page data."""
from __future__ import annotations

from dataclasses import replace
import heapq

from .engine import (FACET_LIMIT, FacetPage, PlanBranch, PriorityPlanError,
                     _plan_branch_valid, _plan_count, _plan_text, scope_filters,
                     narrow_query_values, comparable)

DEFAULT_FACETS = ('port', 'version', 'asn', 'country', 'product', 'org', 'os', 'city')
FACETS = frozenset(DEFAULT_FACETS)


def pack_children(branch, facet, children):
    """Best-fit decreasing packs complete small buckets into <=100 records.

    Large buckets remain separate for recursive planning. Grouped filters can
    be split again if the source grows beyond the extraction limit later.
    """
    groups = []
    for child in sorted(children, key=lambda c: (-c.count, c.query)):
        candidates = [group for group in groups if child.count <= FACET_LIMIT and
                      sum(c.count for c in group) + child.count <= FACET_LIMIT and
                      len(','.join(c.path[-1][1] for c in [*group, child])) <= 512]
        if candidates:
            max(candidates, key=lambda g: sum(c.count for c in g)).append(child)
        else:
            groups.append([child])
    packed = []
    for group in groups:
        if len(group) == 1:
            packed.append(group[0])
            continue
        values = [child.path[-1][1] for child in group]
        query = narrow_query_values(branch.query, facet, values)
        if len(query) > 100000:
            packed.extend(group)
            continue
        packed.append(PlanBranch(query,
                                 sum(c.count for c in group), branch.used_facets,
                                 branch.path + ((facet, ','.join(values)),), branch.depth + 1))
    return packed


def complete_ip_page(page):
    """Counts account for the returned snapshot, not a full-export guarantee."""
    if page.facet != 'ip' or page.warnings or page.total is None:
        return False
    if page.total == 0:
        return not page.rows and page.explicit_empty
    return (0 < len(page.rows) <= FACET_LIMIT and
            len({row.value for row in page.rows}) == len(page.rows) and
            all(type(row.count) is int and row.count > 0 for row in page.rows) and
            sum(row.count for row in page.rows) == page.total)


class AdaptivePlanner:
    """Select the cheapest observed complete split, paying for each probe.

    Record counts estimate cost conservatively: one IP request per <=100 child,
    and ceil(records/100)+2 for a child needing another IP probe and partition.
    Probing stops when its modelled maximum saving is <= the next probe's cost.
    All eight supported facets bound a decision. Order resolves unobserved ties;
    it is not a mandatory traversal. No candidate is probed twice in a decision.
    """
    def __init__(self, read_page, narrow_branch, facets=DEFAULT_FACETS, event=None):
        facets = tuple(facets)
        if not facets or len(set(facets)) != len(facets) or any(f not in FACETS for f in facets):
            raise PriorityPlanError('[PLAN_CONFIG] Invalid adaptive facet candidates.')
        # Candidate selection is automatic; legacy/custom input ordering is not
        # an instruction to traverse that order in adaptive mode.
        self.facets = tuple(f for f in DEFAULT_FACETS if f in facets)
        self.read_page, self.narrow_branch = read_page, narrow_branch
        self.event = event or (lambda *args, **kwargs: None)
        self.probes = 0

    def choose(self, branch, remaining_nodes):
        _plan_branch_valid(branch)
        fixed = {name for name, entries in scope_filters(branch.query).items()
                 if any(not negative and len(values) == 1 for _, _, values, negative in entries)}
        best = None
        started = self.probes
        constant = set()
        lower_bound = 2
        for facet in self.facets:
            if facet in fixed or facet in branch.used_facets:
                continue
            if best and (best[0][0] <= lower_bound + 1 or
                         self.probes-started >= max(2, best[0][0]-lower_bound)):
                break
            self.probes += 1
            page = self.read_page(branch.query, facet, branch.count)
            if page is None:
                self.event('CANDIDATE_REJECTED', branch, facet, reason='unavailable')
                continue
            if getattr(page, 'facet', None) != facet or not isinstance(page.rows, (list, tuple)):
                raise PriorityPlanError('[PLAN_SCHEMA] Invalid adaptive facet response.')
            total = _plan_count(page.total)
            children = []
            values, queries = set(), set()
            clean = not page.warnings
            for row in page.rows:
                value = _plan_text(row.value, 512);count = _plan_count(row.count)
                identity = comparable(facet, value)
                if identity in values:
                    clean = False
                    continue
                values.add(identity)
                if count == 0:
                    continue
                query = self.narrow_branch(branch.query, facet, row)
                if query is None or query == branch.query or query in queries:
                    clean = False
                    continue
                _plan_text(query, 100000);queries.add(query)
                children.append(PlanBranch(query, count, branch.used_facets + (facet,),
                                           branch.path + ((facet, value),), branch.depth + 1))
            accounted = sum(c.count or 0 for c in children)
            reason = None
            if not children or not clean or total is None or any(c.count is None for c in children) or accounted != total:
                reason = 'incomplete_partition'
            elif len(children) == 1:
                reason = 'no_reduction'
            if reason:
                if reason == 'no_reduction':constant.add(facet)
                self.event('CANDIDATE_REJECTED', branch, facet, reason=reason, children=len(children))
                continue
            # A complete newer snapshot is useful even when its total differs
            # from the parent probe. Coverage within this page stays mandatory.
            if branch.count is not None and total != branch.count:
                self.event('SNAPSHOT_COUNT_CHANGED', branch, facet,
                           previous_total=branch.count, observed_total=total)
            raw_children = len(children)
            children = pack_children(branch, facet, children)
            if any(child.query == branch.query for child in children):
                self.event('CANDIDATE_REJECTED', branch, facet, reason='no_reduction', children=len(children))
                continue
            if len(children) > remaining_nodes:
                self.event('CANDIDATE_REJECTED', branch, facet, reason='node_limit', children=len(children))
                continue
            oversized = [c for c in children if c.count > FACET_LIMIT]
            cost = sum(((c.count+FACET_LIMIT-1)//FACET_LIMIT) + (2 if c.count > FACET_LIMIT else 0) for c in children)
            score = (cost, len(oversized), len(children), max(c.count for c in children))
            self.event('CANDIDATE_EVALUATED', branch, facet, estimated_requests=cost,
                       children=len(children), raw_children=raw_children, oversized_children=len(oversized))
            if best is None or score < best[0]:
                best = score, facet, children, raw_children
            # This is a lower bound within the record-count cost model only;
            # service counts cannot prove the optimal distinct-IP partition.
            lower_bound = max(2, ((total+FACET_LIMIT-1)//FACET_LIMIT))
            if best[0][0] <= lower_bound + 1:
                break
        if best is None:
            return None
        score, facet, children, raw_children = best
        self.event('PARTITION_CHOSEN', branch, facet, estimated_requests=score[0],
                   children=len(children), raw_children=raw_children, oversized_children=score[1])
        return [replace(child, used_facets=tuple(dict.fromkeys((*child.used_facets, *sorted(constant)))))
                for child in children]


def run_adaptive(crawler):
    """Interleave extraction and decisions; cache replay preserves completed work."""
    c = crawler
    plan = dict(strategy='adaptive', leaf_limit=FACET_LIMIT, extraction_order=[],
                completed_leaves=0, ready_branches=0, fallback_branches=0,
                facet_probes=0, events=[], events_omitted=0, planning_complete=False,
                optimization='bounded observed downstream request cost; heuristic',
                ordering_basis='largest pending record count; direct IP verification first')
    c.report['plan'] = plan
    c.report['planning_stage'] = 'discovering'
    pending = []
    seen = set()
    serial = 0
    def event(code, branch, facet=None, **details):
        entry = dict(code=code, query=branch.query, facet=facet, **details)
        if len(plan['events']) < 1000:plan['events'].append(entry)
        else:plan['events_omitted'] += 1
        plan['facet_probes'] = planner.probes
        if code == 'PARTITION_CHOSEN':
            plan['last_decision'] = dict(facet=facet, **details)
            c.progress(f"[ADAPTIVE] اختيار {facet}: {details['children']} فروع؛ كلفة الاستخراج المتوقعة {details['estimated_requests']} طلبات.")
    planner = AdaptivePlanner(c.read_page, c.branch, c.args.split_facets, event)
    def resolved_ip_probe(branch, page):
        # Expected top-N truncation is handled by a complete partition. Keep
        # parser errors, changing snapshot totals and unresolved coverage gaps.
        codes = {'DISPLAYED_COUNT_MISMATCH', 'FACET_LIMIT_REACHED'}
        if branch.count is None or branch.count == page.total:codes.add('PARENT_COUNT_MISMATCH')
        resolved = [w for w in c.report['warnings'] if w.get('query') == branch.query and
                    w.get('facet') == 'ip' and w.get('code') in codes]
        if resolved:
            c.report['warnings'] = [w for w in c.report['warnings'] if w not in resolved]
            event('IP_PROBE_RESOLVED', branch, 'ip', warning_codes=sorted({w['code'] for w in resolved}))
    def admit(branch):
        nonlocal serial
        if branch.query in seen:return
        seen.add(branch.query);serial += 1
        entry = dict(branch.to_dict(), status='pending', kind='ready', rank=serial)
        plan['extraction_order'].append(entry)
        heapq.heappush(pending, (branch.count is None, -(branch.count or 0), serial, branch, entry))
    admit(PlanBranch(c.args.effective_query, None))
    while pending:
        _, _, _, branch, entry = heapq.heappop(pending)
        c.report['planning_stage'] = 'extracting'
        plan['planning_complete'] = c.args.mode == 'api' or all(
            item['status'] == 'completed' or type(item['expected_count']) is int and item['expected_count'] <= FACET_LIMIT
            for item in plan['extraction_order'])
        entry.update(status='extracting', cached=c.cached_page_available(branch.query, 'ip'))
        before = len(c.accepted)
        c.progress('[ADAPTIVE] فحص IP قبل أي تقسيم | ' + branch.query)
        # Cache/429/checkpoint/source restrictions remain in the original reader.
        page = c.read_page(branch.query, 'ip', branch.count)
        if not branch.path:
            plan['source_total_records'] = page.total
        c.collect_ips(page)
        entry.update(expected_count=page.total, new_unique_ips=len(c.accepted)-before)
        if c.args.mode == 'api' or complete_ip_page(page):
            if c.args.mode == 'html':resolved_ip_probe(branch, page)
            entry['status'] = 'completed'
            plan['completed_leaves'] += 1
            event('DIRECT_IP_COMPLETE', branch)
        else:
            plan['planning_complete'] = False
            original_branch = branch
            branch = replace(branch, count=page.total)
            children = None
            c.report['planning_stage'] = 'partitioning'
            if len(seen) < c.args.max_plan_nodes and branch.depth < len(FACETS):
                children = planner.choose(branch, c.args.max_plan_nodes-len(seen))
            if children:
                resolved_ip_probe(original_branch, page)
                plan['extraction_order'].remove(entry)
                for child in sorted(children, key=lambda child: -child.count):
                    c.report['visited'][child.path[-1][0]] += 1
                    admit(child)
            else:
                entry.update(status='completed', kind='fallback', fallback_reason='no_safe_partition')
                plan['completed_leaves'] += 1;plan['fallback_branches'] += 1
                c.warning('UNRESOLVED_BRANCH', 'تعذر إيجاد تقسيم كامل ضمن الحدود؛ حُفظت العناوين المتاحة وقد تبقى نتائج غير مستخرجة.', branch.query, 'ip')
        plan['ready_branches'] = len(plan['extraction_order'])-plan['fallback_branches']
        c.checkpoint('collecting')
    plan['planning_complete'] = True
    c.report['planning_stage'] = 'completed'
