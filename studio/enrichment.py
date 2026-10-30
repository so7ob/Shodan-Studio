"""Host enrichment adapters, private settings, and the shared job worker."""
from __future__ import annotations

import ipaddress
import json
import math
import re
import signal
import time
from urllib.parse import parse_qs, quote, urlsplit

from . import engine
from .store import _json, utc_now
from .targets import normalize_details, timestamp


def host_url(ip):
    return 'https://www.shodan.io/host/' + quote(str(ipaddress.ip_address(ip)), safe=':')


def host_page_url(url):
    if not isinstance(url, str) or len(url) > 200: raise ValueError('صفحة عنوان غير صالحة.')
    u = urlsplit(url)
    if u.scheme != 'https' or u.netloc != 'www.shodan.io' or u.query or u.fragment or not u.path.startswith('/host/'):
        raise ValueError('تُقبل صفحة تفاصيل عنوان Shodan فقط.')
    try: ip = str(ipaddress.ip_address(u.path[6:]))
    except ValueError: raise ValueError('عنوان صفحة المضيف غير صالح.') from None
    if url != host_url(ip): raise ValueError('عنوان صفحة المضيف غير قياسي.')
    return ip


def parse_host_html(html, ip):
    """Read labelled host metadata and service sections; reject interstitials."""
    ip = str(ipaddress.ip_address(ip))
    if not isinstance(html, str) or len(html.encode()) > engine.MAX_CHECKPOINT_BYTES:
        raise engine.FacetParseError('[HTML_LIMIT] Host HTML exceeds the size limit.')
    dom = engine._FacetDOM()
    try: dom.feed(html); dom.close()
    except (ValueError, AssertionError, RecursionError): raise engine.FacetParseError('[HTML_PARSE] Invalid host HTML.') from None
    nodes = list(dom.root.walk())
    title = ' '.join(n.text() for n in nodes if n.tag == 'title').lower()
    if any(n.tag == 'input' and n.attrs.get('type', '').lower() == 'password' for n in nodes) or re.search(r'\b(log[ -]?in|sign[ -]?in)\b', title):
        raise engine.FacetParseError('[LOGIN] Sign in to view the host information.')
    if any(x in title for x in ('just a moment', 'captcha', 'attention required')) or any(
        n.attrs.get('id', '').startswith('cf-chl-') or n.attrs.get('id') == 'challenge-form' or 'cf-turnstile' in n.classes() or
        (n.tag == 'iframe' and n.attrs.get('src', '').startswith('https://challenges.cloudflare.com/')) for n in nodes):
        raise engine.FacetParseError('[ACCESS] Browser verification was returned instead of host information.')
    if 'access denied' in title: raise engine.FacetParseError('[DENIED] Host information access denied.')
    headings = [n.text().strip() for n in nodes if n.tag in ('h1', 'h2')]
    if ip not in headings:
        raise engine.FacetParseError('[HTML_PARSE] Host page does not identify the requested IP.')
    result = {'ip_str': ip, 'services': []}
    labels = {'country': 'country_name', 'city': 'city', 'organization': 'org', 'isp': 'isp', 'asn': 'asn',
              'hostnames': 'hostnames', 'domains': 'domains', 'operating system': 'os'}
    recognized = 0
    layout_headings = {re.sub(r'\s+', '', n.text()).casefold() for n in nodes if n.tag in ('h2', 'h3')}
    host_layout = {'generalinformation', 'openports'} <= layout_headings
    for node in nodes:
        allowed = node.tag in ('th', 'dt', 'td') or (host_layout and node.tag in ('div', 'span', 'label', 'strong'))
        key = labels.get(re.sub(r'\s+', ' ', node.text()).strip().rstrip(':').casefold()) if allowed else None
        if not key or not node.parent: continue
        siblings = [x for x in node.parent.children if isinstance(x, engine._FacetNode)]
        position = siblings.index(node)
        value = siblings[position + 1] if position + 1 < len(siblings) else None
        if value is None or value.tag not in ('td', 'dd', 'div', 'span', 'a', 'ul', 'code'): continue
        text = re.sub(r'\s+', ' ', value.text()).strip()
        if not text or len(text) > 2000: continue
        if key in ('hostnames', 'domains'):
            children = [n.text().strip() for n in value.walk() if n.tag in ('a', 'li') and n.text().strip()]
            result[key] = children or [v for v in re.split(r'[\s,]+', text) if v]
        else: result[key] = text
        recognized += 1
        if key == 'country_name':
            for link in value.walk():
                query = parse_qs(urlsplit(link.attrs.get('href', '')).query).get('query', [''])[0]
                match = re.search(r'\bcountry:["\']?([A-Za-z]{2})', query)
                if match: result['country_code'] = match[1].upper()
    # Service headings have both a numeric port and transport; never infer TCP
    # from an unlabelled list of ports.
    seen_services = set()
    for node in nodes:
        if node.tag not in ('h2', 'h3', 'h4', 'h5', 'h6', 'div', 'span', 'strong'): continue
        match = re.fullmatch(r'\s*(\d{1,5})\s*/\s*(tcp|udp)\s*', node.text(), re.I)
        if not match or not 1 <= int(match[1]) <= 65535: continue
        identity = (int(match[1]), match[2].lower())
        if identity in seen_services: continue
        seen_services.add(identity)
        section = node.parent
        ancestor = section
        for _ in range(5):
            if ancestor is None: break
            if ancestor.classes() & {'service', 'service-details'} or re.fullmatch(r'port-?\d+', ancestor.attrs.get('id', '')):
                section = ancestor; break
            ancestor = ancestor.parent
        service = {'port': int(match[1]), 'transport': match[2].lower()}
        if section:
            times = [n.attrs.get('datetime') or n.text() for n in section.walk() if n.tag == 'time' or 'timestamp' in n.classes()]
            dates = [timestamp(v) for v in times]
            valid = [v for v in dates if v]
            if valid: service['timestamp'] = max(valid)
            for n in section.walk():
                if n.tag == 'a':
                    q = parse_qs(urlsplit(n.attrs.get('href', '')).query).get('query', [''])[0]
                    for field in ('product', 'version'):
                        m = re.fullmatch(field + r':(?:"([^"]+)"|([^\s]+))', q)
                        if m: service[field] = m[1] or m[2]
        result['services'].append(service); recognized += 1
    # A real host page can legitimately omit every optional field, but a bare IP
    # heading/error page must not be accepted as a successful enrichment.
    if not recognized: raise engine.FacetParseError('[HTML_PARSE] Host metadata structure is unavailable.')
    return normalize_details(ip, result)


class EnrichmentSettings:
    def __init__(self, store, accounts):
        self.store, self.accounts = store, accounts
        with store.connection() as c:
            c.execute('CREATE TABLE IF NOT EXISTS enrichment_credentials (id INTEGER PRIMARY KEY CHECK(id=1), encrypted TEXT NOT NULL)')

    def public(self):
        with self.store.connection() as c:
            has_key = c.execute('SELECT 1 FROM enrichment_credentials WHERE id=1').fetchone() is not None
        return {'source_mode': 'auto', 'automatic': True, **self.store.get_setting('enrichment_options', {}), 'has_key': has_key}

    def key(self):
        with self.store.connection() as c: row = c.execute('SELECT encrypted FROM enrichment_credentials WHERE id=1').fetchone()
        if row is None: return None
        try: return self.accounts._cipher().decrypt(row[0].encode()).decode()
        except Exception: raise RuntimeError('تعذر فتح مفتاح الإثراء المحفوظ؛ أعد إدخاله من إعدادات المستودع.') from None

    def save(self, payload):
        from .config import validate_key
        if not isinstance(payload, dict) or set(payload) - {'source_mode', 'automatic', 'api_key', 'clear_key'}:
            raise ValueError('إعدادات إثراء غير صالحة.')
        options = self.public()
        mode = payload.get('source_mode', options['source_mode'])
        automatic = payload.get('automatic', options['automatic'])
        if mode not in ('auto', 'html', 'api') or type(automatic) is not bool: raise ValueError('إعدادات إثراء غير صالحة.')
        key = validate_key(payload.get('api_key'))
        if type(payload.get('clear_key', False)) is not bool: raise ValueError('طلب مسح المفتاح غير صالح.')
        with self.store.connection() as c:
            c.execute('BEGIN IMMEDIATE')
            if payload.get('clear_key'): c.execute('DELETE FROM enrichment_credentials')
            if key:
                encrypted = self.accounts._cipher(create=True).encrypt(key.encode()).decode()
                c.execute('INSERT INTO enrichment_credentials VALUES(1,?) ON CONFLICT(id) DO UPDATE SET encrypted=excluded.encrypted', (encrypted,))
            c.execute('INSERT OR REPLACE INTO settings VALUES(?,?)', ('enrichment_options', _json({'source_mode': mode, 'automatic': automatic})))
            c.commit()
        return self.public()


def validate_checkpoint(payload):
    engine._checkpoint_validate(payload)
    if payload.get('kind') != 'enrichment': raise ValueError('نقطة الاستكمال ليست لمهمة إثراء.')
    cfg, state = payload['config'], payload['state']
    from .config import settings_from
    settings_from(cfg.get('settings', {}), allow_demo=True)
    if cfg.get('source_mode') not in ('html', 'api', 'auto'): raise ValueError('مصدر نقطة الإثراء غير صالح.')
    items = state.get('items')
    if not isinstance(items, list) or len(items) > 100000: raise ValueError('قائمة أهداف نقطة الإثراء غير صالحة.')
    ips = set()
    for item in items:
        if not isinstance(item, dict): raise ValueError('هدف إثراء غير صالح.')
        ip = str(ipaddress.ip_address(item.get('ip')))
        if ip in ips or item.get('status') not in ('pending', 'success', 'partial', 'not_found', 'failed'): raise ValueError('حالة هدف إثراء غير صالحة.')
        ips.add(ip)
        item['ip'] = ip
        if not isinstance(item.get('snapshots', []), list) or len(item.get('snapshots', [])) > 2: raise ValueError('لقطات إثراء غير صالحة.')
        for snap in item.get('snapshots', []):
            if snap.get('source') not in ('html', 'api') or not re.fullmatch('[a-f0-9]{32}', str(snap.get('request_id', ''))): raise ValueError('لقطة إثراء غير صالحة.')
            normalize_details(ip, snap['details'])
    for key in ('requests_total', 'session_number'):
        if type(state.get(key, 0)) is not int or state.get(key, 0) < 0: raise ValueError('عداد استكمال غير صالح.')
    deadline = state.get('not_before_utc')
    if deadline is not None and (type(deadline) not in (int, float) or not math.isfinite(deadline) or deadline < 0): raise ValueError('موعد انتظار غير صالح.')
    if type(state.get('wait_unbounded', False)) is not bool: raise ValueError('حالة انتظار غير صالحة.')
    pending = state.get('pending_request')
    if pending is not None and (not isinstance(pending, dict) or str(ipaddress.ip_address(pending.get('query'))) not in ips): raise ValueError('طلب إثراء معلّق غير صالح.')
    return payload


def pending_url(job, path):
    payload = validate_checkpoint(engine.load_checkpoint(path / 'checkpoint.json'))
    pending = payload['state'].get('pending_request')
    ip = pending['query'] if pending else next((x['ip'] for x in payload['state']['items'] if x['status'] == 'pending'), None)
    if ip is None: raise ValueError('لا يوجد هدف معلق لفتح المتصفح.')
    return host_url(ip)


def run(job_dir, payload):
    from .worker import StudioCrawler, atomic_text, build_args, emit
    job = payload['job']
    if 'targets' not in payload:
        manifest = job_dir / 'enrichment-targets.json'
        if manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size > engine.MAX_CHECKPOINT_BYTES:
            raise ValueError('ملف أهداف الإثراء غير صالح.')
        payload['targets'] = json.loads(manifest.read_text(encoding='utf-8'))
    if not isinstance(payload['targets'], list) or len(payload['targets']) > 100000: raise ValueError('قائمة أهداف غير صالحة.')
    args = build_args(job_dir, job, payload.get('api_key'), ignore_checkpoint=True)
    if (job_dir / 'checkpoint.json').exists():
        validate_checkpoint(engine.load_checkpoint(job_dir / 'checkpoint.json'))
        args.force = True
    engine.preflight(args)

    class EnrichmentCrawler(StudioCrawler):
        def __init__(self):
            self.items = [{**x, 'status': 'pending', 'snapshots': []} for x in payload['targets']]
            self.source_policy = job.get('source_mode', job['mode'])
            self.private_key = args.api_key_resolved
            self.job = job
            super().__init__(args, job_dir, demo=job['settings'].get('demo', False))
            checkpoint = job_dir / 'checkpoint.json'
            if checkpoint.exists():
                saved = validate_checkpoint(engine.load_checkpoint(checkpoint)); state = saved['state']
                by_ip = {x['ip']: x for x in self.items}
                if set(by_ip) != {x['ip'] for x in state['items']}: raise ValueError('أهداف نقطة الاستكمال لا تطابق المهمة.')
                self.items = [{**x, 'target_id': by_ip[x['ip']]['target_id']} for x in state['items']]
                self.previous_requests = state.get('requests_total', 0)
                self.session_number = state.get('session_number', 0) + 1
                self.not_before_utc = state.get('not_before_utc'); self.wait_unbounded = state.get('wait_unbounded', False)
                self.pending_request = state.get('pending_request')
            self.report['kind'] = 'enrichment'
            for item in self.items: self.publish(item)

        def stats(self):
            counts = {k: sum(x['status'] == k for x in self.items) for k in ('pending', 'success', 'partial', 'not_found', 'failed')}
            total = len(self.items); done = total - counts['pending']
            result = super().stats()
            result.update(phase='waiting' if self.not_before_utc or self.wait_unbounded else 'enriching',
                          unique_ips=done, completed_branches=done, ready_branches=total, remaining_branches=total-done,
                          percent=round(100*done/total, 1) if total else 100, plan_known=True,
                          enrichment_progress={'total': total, 'processed': done, **counts})
            return result

        def snapshot(self, force=False):
            if not force and time.monotonic() - self._last_snapshot < 1: return
            self._last_snapshot = time.monotonic()
            emit('progress', stats=self.stats())

        def checkpoint(self, status=None):
            engine.save_checkpoint(job_dir / 'checkpoint.json', {
                'app': 'ShodanSpider', 'kind': 'enrichment', 'schema_version': 1, 'saved_at_utc': utc_now(),
                'config': {'settings': job['settings'], 'source_mode': self.source_policy, 'title': job.get('title', '')},
                'state': {'status': status or 'running', 'items': self.items, 'pending_request': self.pending_request,
                          'requests_total': self.previous_requests + self.report['requests_attempted'], 'session_number': self.session_number,
                          'not_before_utc': self.not_before_utc, 'wait_unbounded': self.wait_unbounded}}, allow_replace=True)

        def publish(self, item):
            for snap in item.get('snapshots', []): emit('target_snapshot', target_id=item['target_id'], **snap)
            if item['status'] != 'pending': emit('enrichment_item', item=item)

        def switch_source(self, mode, reason):
            old = self.args.mode
            self.args.api_key_resolved = self.private_key if mode == 'api' else None
            self.configure_source(mode); self.args.mode = mode
            if old != mode: self.record_source_change(old, mode, reason)
            self.checkpoint('source_changed')

        def lookup(self, ip, source):
            self.switch_source(source, 'enrichment source selection')
            if self.demo_data:
                operation = (lambda: {'ip_str': ip, 'country_code': 'EG', 'city': 'Cairo', 'org': 'Fixture',
                                     'data': [{'port': 443, 'transport': 'tcp', 'product': 'Fixture', 'timestamp': utc_now()}]})
            elif source == 'api':
                operation = lambda: self.client.host(ip)
            else:
                def operation():
                    try: return parse_host_html(self.fetcher(host_url(ip)), ip)
                    except engine.FacetParseError as exc:
                        kind = 'browser_challenge' if str(exc).startswith('[ACCESS]') else 'auth' if str(exc).startswith('[LOGIN]') else 'response'
                        raise engine.SpiderError(str(exc), failure_kind=kind) from None
            def checked_operation():
                raw = operation()
                try: return engine.redact_report(normalize_details(ip, raw), self.private_key)
                except ValueError: raise engine.SpiderError('[HOST_SCHEMA] Host information does not match the requested address or schema.', failure_kind='response') from None
            details, entry = self._request_with_rate_limits(checked_operation, {'query': ip, 'facet': 'host', 'operation': 'host_lookup'}, 'HOST ' + ip)
            entry.update(status='parsed', row_count=len(details['services']))
            self.request_observed(entry, rows=[{'value': str(s['port'])+'/'+s['transport'], 'label': s.get('product') or str(s['port']), 'count': None} for s in details['services']])
            return {'source': source, 'details': details, 'request_id': entry['request_id'], 'fetched_at': entry['finished_at']}

        def run(self):
            for item in self.items:
                if item['status'] != 'pending': continue
                self.check_control(); self._current_query = item['ip']
                sources = (['api', 'html'] if self.source_policy == 'api' and self.args.api_fallback == 'html' else
                           [self.source_policy]) if self.source_policy != 'auto' else ['api', 'html'] if self.private_key else ['html']
                # Keep successful partial results when a second source needs user input.
                tried = {x['source'] for x in item.get('snapshots', [])}
                not_found = False
                for source in sources:
                    if source in tried: continue
                    try:
                        snap = self.lookup(item['ip'], source)
                    except engine.FacetParseError as exc:
                        kind = 'browser_challenge' if str(exc).startswith('[ACCESS]') else 'auth' if str(exc).startswith('[LOGIN]') else 'response'
                        raise engine.SpiderError(str(exc), failure_kind=kind) from None
                    except (engine.SpiderError, engine.ShodanAPIError) as exc:
                        if isinstance(exc, engine.PauseRequested): raise
                        if getattr(exc, 'http_status', None) == 404:
                            not_found = True; continue
                        fallback = self.source_policy == 'auto' or (self.source_policy == 'api' and getattr(exc, 'http_status', None) in (401, 402, 403))
                        if fallback and source != sources[-1] and getattr(exc, 'http_status', None) != 429 and not self.wait_unbounded and not self.not_before_utc and not str(exc).startswith('[REQUEST_LIMIT]'):
                            self.warning('SOURCE_FALLBACK', engine.safe_detail(exc), item['ip'], 'host'); continue
                        raise
                    item.setdefault('snapshots', []).append(snap)
                    # Persist before IPC: restart replays this exact request identity.
                    self.checkpoint('running'); self.publish(item)
                    combined = {k: v for s in item['snapshots'] for k, v in s['details'].items() if v not in (None, [], '')}
                    if self.source_policy != 'auto' or (combined.get('country_code') and combined.get('city') and combined.get('services')): break
                combined = {k: v for s in item.get('snapshots', []) for k, v in s['details'].items() if v not in (None, [], '')}
                item['status'] = ('success' if combined.get('country_code') and combined.get('city') and combined.get('services') else 'partial') if item.get('snapshots') else 'not_found' if not_found else 'failed'
                self.pending_request = None; self.checkpoint('running'); self.publish(item); self.snapshot(force=True)
            self.report['traversal_completed'] = True
            return self.report

    crawler = EnrichmentCrawler()
    signal.signal(signal.SIGTERM, lambda *_: setattr(crawler, 'stop_reason', 'pause'))
    signal.signal(signal.SIGINT, lambda *_: setattr(crawler, 'stop_reason', 'pause'))
    state, error = 'completed', None
    crawler.checkpoint('starting'); emit('state', status='running', message='بدأت مهمة إثراء الأهداف.')
    try:
        crawler.run()
        if any(x['status'] != 'success' for x in crawler.items): state = 'completed_warnings'
    except (engine.SpiderError, engine.ShodanAPIError, OSError, KeyboardInterrupt) as exc:
        error = engine.safe_detail(exc)
        if crawler.stop_reason: state = 'cancelled' if crawler.stop_reason == 'cancel' else 'paused'
        else:
            crawler.input_reason = ('browser_challenge' if getattr(exc, 'failure_kind', None) == 'browser_challenge' or '[ACCESS]' in str(exc) else
                                    'request_budget' if str(exc).startswith('[REQUEST_LIMIT]') else crawler.input_reason or 'source_error')
            state = 'waiting_input'
    crawler._finalizing = True
    crawler.checkpoint(state)
    report = {**crawler.report, 'status': state, 'error': error, 'finished_at_utc': utc_now(), 'items': crawler.items}
    atomic_text(job_dir / 'result.txt.report.json', json.dumps(report, ensure_ascii=False, allow_nan=False))
    atomic_text(job_dir / 'result.txt', ''.join(x['ip']+'\n' for x in crawler.items if x['status'] != 'pending'))
    emit('final', status=state, error=error, stats=crawler.stats(), input_reason=crawler.input_reason,
         vpn_failover_requested=crawler.vpn_failover_requested)
    return 0 if state.startswith('completed') else 75
