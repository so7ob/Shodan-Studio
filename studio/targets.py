"""Cross-job target inventory. Discovery evidence survives deletion of a job."""
from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import io
import ipaddress
import json
import re
import secrets

from .store import _json, utc_now


FIELDS = ('country_code', 'country_name', 'city', 'asn', 'org', 'isp', 'os',
          'hostnames', 'domains', 'last_seen')
FILTERS = {'q', 'country', 'city', 'asn', 'org', 'port', 'protocol', 'product',
           'job_id', 'query', 'source', 'enrichment_source', 'status', 'from', 'to', 'demo'}


def timestamp(value):
    if not isinstance(value, str): return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None: parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat()
    except (ValueError, OverflowError): return None


def clean_text(value, maximum=512):
    if not isinstance(value, str): return None
    value = ''.join(c for c in value if ord(c) >= 32 and ord(c) != 127).strip()
    return value[:maximum] or None


def normalize_details(ip, payload):
    """Persist only public host metadata, never raw banners/HTML/credentials."""
    address = str(ipaddress.ip_address(ip))
    if not isinstance(payload, dict): raise ValueError('تفاصيل الهدف غير صالحة.')
    reported = payload.get('ip_str', payload.get('ip', address))
    try:
        if str(ipaddress.ip_address(reported)) != address: raise ValueError()
    except (ValueError, TypeError): raise ValueError('عنوان استجابة الإثراء لا يطابق الهدف.') from None
    location = payload.get('location') if isinstance(payload.get('location'), dict) else {}
    result = {'ip': address}
    for field in FIELDS:
        value = payload.get(field, location.get(field))
        if field in ('hostnames', 'domains'):
            result[field] = sorted({v for x in value[:1000] if (v := clean_text(x))}) if isinstance(value, list) else []
        elif field == 'last_seen': result[field] = timestamp(value or payload.get('last_update'))
        else: result[field] = clean_text(value)
    if result['country_code']:
        result['country_code'] = result['country_code'].upper() if re.fullmatch('[A-Za-z]{2}', result['country_code']) else None
    services = {}
    rows = payload.get('services', payload.get('data', []))
    for row in rows[:10000] if isinstance(rows, list) else []:
        if not isinstance(row, dict): continue
        port, protocol = row.get('port'), row.get('transport', row.get('protocol'))
        if type(port) is not int or not 0 <= port <= 65535: continue
        protocol = protocol.lower() if isinstance(protocol, str) else 'unknown'
        if protocol not in ('tcp', 'udp', 'unknown'): protocol = 'unknown'
        item = {'port': port, 'transport': protocol, 'product': clean_text(row.get('product')),
                'version': clean_text(row.get('version')), 'timestamp': timestamp(row.get('timestamp'))}
        services[port, protocol] = item
    for port in payload.get('ports', []) if isinstance(payload.get('ports'), list) else []:
        if type(port) is int and 0 <= port <= 65535 and not any(k[0] == port for k in services):
            services[port, 'unknown'] = {'port': port, 'transport': 'unknown', 'product': None, 'version': None, 'timestamp': None}
    result['services'] = [services[k] for k in sorted(services)]
    seen = [s['timestamp'] for s in result['services'] if s['timestamp']]
    if seen: result['last_seen'] = max([result['last_seen']] + seen) if result['last_seen'] else max(seen)
    return result


class TargetRepository:
    def __init__(self, store):
        self.store = store
        with store.connection() as c:
            c.executescript('''
                CREATE TABLE IF NOT EXISTS targets (
                    id TEXT PRIMARY KEY, ip TEXT NOT NULL, ip_version INTEGER NOT NULL,
                    ip_key BLOB NOT NULL, demo INTEGER NOT NULL DEFAULT 0,
                    first_found_at TEXT, last_found_at TEXT, enriched_at TEXT,
                    status TEXT NOT NULL DEFAULT 'pending', country TEXT, city TEXT,
                    asn TEXT, org TEXT, document TEXT NOT NULL DEFAULT '{}', UNIQUE(ip,demo));
                CREATE INDEX IF NOT EXISTS targets_address ON targets(ip_version,ip_key);
                CREATE INDEX IF NOT EXISTS targets_location ON targets(demo,country,city);
                CREATE INDEX IF NOT EXISTS targets_status ON targets(demo,status);
                CREATE INDEX IF NOT EXISTS targets_asn ON targets(demo,asn);
                CREATE INDEX IF NOT EXISTS targets_org ON targets(demo,org);
                CREATE TABLE IF NOT EXISTS target_discoveries (
                    target_id TEXT NOT NULL, job_id TEXT NOT NULL, request_id TEXT NOT NULL,
                    found_at TEXT, time_quality TEXT NOT NULL, original_query TEXT NOT NULL,
                    query TEXT, source TEXT, context TEXT NOT NULL,
                    PRIMARY KEY(target_id,job_id,request_id),
                    FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE);
                CREATE INDEX IF NOT EXISTS discovery_filter ON target_discoveries(job_id,source,found_at,target_id);
                CREATE INDEX IF NOT EXISTS discovery_target ON target_discoveries(target_id,found_at);
                CREATE INDEX IF NOT EXISTS discovery_time ON target_discoveries(found_at,target_id);
                CREATE INDEX IF NOT EXISTS discovery_source ON target_discoveries(source,found_at,target_id);
                CREATE TABLE IF NOT EXISTS target_snapshots (
                    id TEXT PRIMARY KEY, target_id TEXT NOT NULL, job_id TEXT NOT NULL,
                    request_id TEXT NOT NULL, source TEXT NOT NULL, fetched_at TEXT NOT NULL,
                    document TEXT NOT NULL, UNIQUE(target_id,job_id,request_id),
                    FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE);
                CREATE INDEX IF NOT EXISTS snapshots_target ON target_snapshots(target_id,fetched_at);
                CREATE TABLE IF NOT EXISTS target_services (
                    target_id TEXT NOT NULL, port INTEGER NOT NULL, transport TEXT NOT NULL,
                    product TEXT, version TEXT, observed_at TEXT, fetched_at TEXT NOT NULL, source TEXT NOT NULL,
                    PRIMARY KEY(target_id,port,transport),
                    FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE);
                CREATE INDEX IF NOT EXISTS services_filter ON target_services(port,transport,product,target_id);
                CREATE TABLE IF NOT EXISTS enrichment_items (
                    job_id TEXT NOT NULL, target_id TEXT NOT NULL, position INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending', document TEXT NOT NULL DEFAULT '{}',
                    PRIMARY KEY(job_id,target_id), UNIQUE(job_id,position),
                    FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE,
                    FOREIGN KEY(target_id) REFERENCES targets(id));
                CREATE TABLE IF NOT EXISTS target_auto_claims (target_id TEXT PRIMARY KEY, job_id TEXT NOT NULL);
            ''')

    def _target(self, c, ip, demo=False):
        address = ipaddress.ip_address(ip)
        c.execute('INSERT OR IGNORE INTO targets(id,ip,ip_version,ip_key,demo) VALUES(?,?,?,?,?)',
                  (secrets.token_hex(16), str(address), address.version, address.packed, int(demo)))
        return c.execute('SELECT id FROM targets WHERE ip=? AND demo=?', (str(address), int(demo))).fetchone()[0]

    def discover(self, job, entry, ips, *, quality='observed', connection=None):
        if job.get('kind', 'extraction') != 'extraction': return
        from .vpn_config import NETWORK_DEFAULTS
        context = {k: job.get(k) for k in ('id', 'title', 'query', 'created_at', 'shodan_account_id')}
        context['settings'] = job.get('settings', {})
        context.update({k: job.get(k, v) for k, v in NETWORK_DEFAULTS.items()})
        request_id = entry.get('request_id') or 'legacy-unattributed'
        at = timestamp(entry.get('finished_at')) if quality != 'unknown' else None
        query = entry.get('query') if isinstance(entry.get('query'), str) else None
        def write(c):
            for ip in ips:
                try: ident = self._target(c, ip, job.get('settings', {}).get('demo', False))
                except ValueError: continue
                if request_id == 'legacy-unattributed' and c.execute('SELECT 1 FROM target_discoveries WHERE target_id=? AND job_id=? LIMIT 1', (ident, job['id'])).fetchone():
                    continue
                c.execute('''INSERT INTO target_discoveries VALUES(?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(target_id,job_id,request_id) DO UPDATE SET
                    found_at=COALESCE(target_discoveries.found_at,excluded.found_at),
                    time_quality=CASE WHEN target_discoveries.found_at IS NULL THEN excluded.time_quality ELSE target_discoveries.time_quality END''',
                    (ident, job['id'], request_id, at, quality if at else 'unknown', job.get('query', ''),
                     query, entry.get('source'), _json(context)))
                recorded_at = c.execute('SELECT found_at FROM target_discoveries WHERE target_id=? AND job_id=? AND request_id=?', (ident, job['id'], request_id)).fetchone()[0]
                if recorded_at:
                    c.execute('''UPDATE targets SET first_found_at=CASE WHEN first_found_at IS NULL OR first_found_at>? THEN ? ELSE first_found_at END,
                        last_found_at=CASE WHEN last_found_at IS NULL OR last_found_at<? THEN ? ELSE last_found_at END WHERE id=?''',
                        (recorded_at, recorded_at, recorded_at, recorded_at, ident))
                if request_id != 'legacy-unattributed':
                    c.execute("DELETE FROM target_discoveries WHERE target_id=? AND job_id=? AND request_id='legacy-unattributed'", (ident, job['id']))
        if connection is not None: write(connection)
        else:
            with self.store.connection() as c:
                c.execute('BEGIN IMMEDIATE'); write(c); c.commit()

    def observe_request(self, job, entry, rows):
        if entry.get('origin') not in ('live', 'legacy') or entry.get('facet') != 'ip' or entry.get('status') not in ('success', 'parsed'): return
        with self.store.connection() as c:
            c.execute('BEGIN IMMEDIATE')
            accepted = {r[0] for r in c.execute('SELECT ip FROM job_ips WHERE job_id=?', (job['id'],))}
            ips = []
            for row in rows:
                try: ip = str(ipaddress.ip_address(row.get('value')))
                except (ValueError, TypeError): continue
                if ip in accepted: ips.append(ip)
            self.discover(job, entry, ips, quality='recovered' if entry.get('origin') == 'legacy' else 'observed', connection=c)
            c.commit()

    def backfill(self, job):
        if job.get('kind', 'extraction') != 'extraction': return
        with self.store.connection() as c:
            accepted = [r[0] for r in c.execute('SELECT ip FROM job_ips WHERE job_id=?', (job['id'],))]
            rows = c.execute('''SELECT h.document AS request,v.document AS value FROM request_history h
                JOIN request_values v ON v.job_id=h.job_id AND v.request_id=h.request_id
                WHERE h.job_id=? AND json_extract(h.document,'$.facet')='ip'
                AND h.origin IN ('live','legacy') AND h.status='success' ''', (job['id'],)).fetchall()
        groups = {}
        for row in rows:
            e = json.loads(row['request']); groups.setdefault(e['request_id'], (e, []))[1].append(json.loads(row['value']))
        with self.store.connection() as c:
            c.execute('BEGIN IMMEDIATE')
            # Only missing historical links get an unknown-time record.
            for ip in accepted:
                ident = self._target(c, ip, job.get('settings', {}).get('demo', False))
                if not c.execute('SELECT 1 FROM target_discoveries WHERE target_id=? AND job_id=?', (ident, job['id'])).fetchone():
                    self.discover(job, {}, [ip], quality='unknown', connection=c)
            c.commit()
        for e, values in groups.values(): self.observe_request(job, e, values)

    def snapshot(self, job_id, target_id, request_id, source, details, fetched_at=None):
        if source not in ('html', 'api'): raise ValueError('مصدر إثراء غير صالح.')
        fetched = timestamp(fetched_at) or utc_now()
        with self.store.connection() as c:
            c.execute('BEGIN IMMEDIATE')
            row = c.execute('SELECT * FROM targets WHERE id=?', (target_id,)).fetchone()
            if row is None: raise KeyError(target_id)
            clean = normalize_details(row['ip'], details)
            ident = hashlib.sha256(f'{target_id}:{job_id}:{request_id}'.encode()).hexdigest()
            inserted = c.execute('INSERT OR IGNORE INTO target_snapshots VALUES(?,?,?,?,?,?,?)',
                                (ident, target_id, job_id, request_id, source, fetched, _json(clean))).rowcount
            if not inserted: c.commit(); return
            current = json.loads(row['document']); provenance = current.setdefault('provenance', {})
            for field in FIELDS:
                value = clean.get(field)
                if value in (None, [], ''): continue
                previous = provenance.get(field, {})
                order = (clean.get('last_seen') or fetched, fetched, source == 'api')
                old = (previous.get('observed_at') or previous.get('fetched_at', ''), previous.get('fetched_at', ''), previous.get('source') == 'api')
                if order >= old:
                    current[field] = value
                    provenance[field] = {'source': source, 'observed_at': clean.get('last_seen'), 'fetched_at': fetched}
            for service in clean['services']:
                if service['transport'] == 'unknown' and c.execute("SELECT 1 FROM target_services WHERE target_id=? AND port=? AND transport!='unknown'", (target_id, service['port'])).fetchone():
                    continue
                if service['transport'] != 'unknown':
                    c.execute("DELETE FROM target_services WHERE target_id=? AND port=? AND transport='unknown'", (target_id, service['port']))
                c.execute('''INSERT INTO target_services VALUES(?,?,?,?,?,?,?,?)
                    ON CONFLICT(target_id,port,transport) DO UPDATE SET product=COALESCE(excluded.product,target_services.product),
                    version=COALESCE(excluded.version,target_services.version), observed_at=excluded.observed_at,
                    fetched_at=excluded.fetched_at,source=excluded.source
                    WHERE COALESCE(excluded.observed_at,excluded.fetched_at)>=COALESCE(target_services.observed_at,target_services.fetched_at)''',
                    (target_id, service['port'], service['transport'], service['product'], service['version'], service['timestamp'], fetched, source))
            count = c.execute('SELECT COUNT(*) FROM target_services WHERE target_id=?', (target_id,)).fetchone()[0]
            status = 'success' if current.get('country_code') and current.get('city') and count else 'partial'
            c.execute('UPDATE targets SET document=?,country=?,city=?,asn=?,org=?,enriched_at=CASE WHEN enriched_at IS NULL OR enriched_at<? THEN ? ELSE enriched_at END,status=? WHERE id=?',
                      (_json(current), current.get('country_code'), current.get('city'), current.get('asn'), current.get('org'), fetched, fetched, status, target_id))
            c.commit()

    def _where(self, filters):
        if not isinstance(filters, dict) or set(filters) - FILTERS: raise ValueError('فلتر أهداف غير مدعوم.')
        if any(not isinstance(v, (str, int)) or isinstance(v, bool) or (isinstance(v, str) and len(v) > 8192) for v in filters.values()):
            raise ValueError('قيمة فلتر غير صالحة.')
        terms, values = ['t.demo=?'], [1 if str(filters.get('demo', '0')) == '1' else 0]
        for key in ('country', 'city', 'asn', 'org', 'status'):
            value = filters.get(key)
            if value:
                if not isinstance(value, str) or len(value) > 512: raise ValueError('قيمة فلتر غير صالحة.')
                terms.append(f't.{key}=? COLLATE NOCASE'); values.append(value)
        q = filters.get('q')
        if q:
            if not isinstance(q, str) or len(q) > 512: raise ValueError('بحث غير صالح.')
            if '/' in q:
                try: net = ipaddress.ip_network(q, strict=False)
                except ValueError: raise ValueError('نطاق CIDR غير صالح.') from None
                terms.extend(['t.ip_version=?', 't.ip_key BETWEEN ? AND ?']); values.extend([net.version, net.network_address.packed, net.broadcast_address.packed])
            else:
                terms.append("(instr(lower(t.ip),lower(?))>0 OR instr(lower(COALESCE(json_extract(t.document,'$.hostnames'),'')||COALESCE(json_extract(t.document,'$.domains'),'')),lower(?))>0)"); values.extend([q, q])
        if filters.get('enrichment_source'):
            terms.append('EXISTS(SELECT 1 FROM target_snapshots p WHERE p.target_id=t.id AND p.source=?)'); values.append(filters['enrichment_source'])
        service_terms = ['s.target_id=t.id']; service_values = []
        for key, column in (('port', 'port'), ('protocol', 'transport'), ('product', 'product')):
            value = filters.get(key)
            if value not in (None, ''):
                if key == 'port':
                    try: value = int(value)
                    except (ValueError, TypeError): raise ValueError('البورت غير صالح.') from None
                    if not 0 <= value <= 65535: raise ValueError('البورت غير صالح.')
                service_terms.append(f's.{column}=? COLLATE NOCASE'); service_values.append(value)
        if service_values:
            terms.append('EXISTS(SELECT 1 FROM target_services s WHERE ' + ' AND '.join(service_terms) + ')'); values.extend(service_values)
        discovery_clause, discovery_values = self._discovery_where(filters)
        if discovery_values:
            terms.append('EXISTS(SELECT 1 FROM target_discoveries d WHERE d.target_id=t.id AND ' + discovery_clause + ')'); values.extend(discovery_values)
        return ' AND '.join(terms), values

    def _discovery_where(self, filters):
        discovery_terms = ['1=1']; discovery_values = []
        for key, column in (('job_id', 'job_id'), ('source', 'source')):
            if filters.get(key): discovery_terms.append(f'd.{column}=?'); discovery_values.append(filters[key])
        if filters.get('query'):
            discovery_terms.append('(instr(lower(d.query),lower(?))>0 OR instr(lower(d.original_query),lower(?))>0)')
            discovery_values.extend([filters['query'], filters['query']])
        for key, operator in (('from', '>='), ('to', '<')):
            if filters.get(key):
                at = timestamp(filters[key])
                if at is None: raise ValueError('تاريخ الفلتر غير صالح.')
                discovery_terms.append(f'd.found_at{operator}?'); discovery_values.append(at)
        return ' AND '.join(discovery_terms), discovery_values

    def _public(self, c, row):
        result = dict(row); result.pop('ip_key', None)
        result.update(json.loads(result.pop('document')))
        result['services'] = [dict(r) for r in c.execute('SELECT port,transport,product,version,observed_at,fetched_at,source FROM target_services WHERE target_id=? ORDER BY port,transport', (row['id'],))]
        result['discovery_count'] = c.execute('SELECT COUNT(*) FROM target_discoveries WHERE target_id=?', (row['id'],)).fetchone()[0]
        result['job_count'] = c.execute('SELECT COUNT(DISTINCT job_id) FROM target_discoveries WHERE target_id=?', (row['id'],)).fetchone()[0]
        result['unknown_discovery_times'] = bool(c.execute('SELECT 1 FROM target_discoveries WHERE target_id=? AND found_at IS NULL LIMIT 1', (row['id'],)).fetchone())
        return result

    def list(self, filters=None, offset=0, limit=100):
        where, values = self._where(filters or {})
        offset, limit = max(0, int(offset)), min(1000, max(1, int(limit)))
        with self.store.connection() as c:
            total = c.execute('SELECT COUNT(*) FROM targets t WHERE ' + where, values).fetchone()[0]
            rows = c.execute('SELECT t.* FROM targets t WHERE ' + where + ' ORDER BY t.ip_version,t.ip_key LIMIT ? OFFSET ?', [*values, limit, offset]).fetchall()
            return {'items': [self._public(c, r) for r in rows], 'total': total, 'offset': offset, 'limit': limit}

    def detail(self, ident, offset=0, limit=100):
        with self.store.connection() as c:
            row = c.execute('SELECT * FROM targets WHERE id=?', (ident,)).fetchone()
            if row is None: raise KeyError(ident)
            result = self._public(c, row)
            rows = c.execute('''SELECT d.*,CASE WHEN j.id IS NULL THEN 1 ELSE 0 END AS job_deleted FROM target_discoveries d
                LEFT JOIN jobs j ON j.id=d.job_id WHERE d.target_id=? ORDER BY d.found_at DESC,d.job_id,d.request_id LIMIT ? OFFSET ?''',
                (ident, min(1000, max(1, int(limit))), max(0, int(offset)))).fetchall()
            result['discoveries'] = [{**dict(r), 'context': json.loads(r['context'])} for r in rows]
            result['discovery_offset'] = max(0, int(offset))
            result['has_more_discoveries'] = result['discovery_offset'] + len(rows) < result['discovery_count']
            result['snapshots'] = [{**dict(r), 'document': json.loads(r['document'])} for r in c.execute(
                'SELECT * FROM target_snapshots WHERE target_id=? ORDER BY fetched_at DESC LIMIT 100', (ident,))]
            result['enrichment_jobs'] = [dict(r) for r in c.execute('''SELECT j.id,j.status,json_extract(j.document,'$.title') AS title,e.status AS target_status
                FROM enrichment_items e JOIN jobs j ON j.id=e.job_id WHERE e.target_id=? ORDER BY j.created_at DESC LIMIT 100''', (ident,))]
            return result

    def stats(self, filters=None):
        where, values = self._where(filters or {})
        selected = 'SELECT t.id FROM targets t WHERE ' + where
        discovery_clause, discovery_values = self._discovery_where(filters or {})
        with self.store.connection() as c:
            def grouped(sql): return [dict(r) for r in c.execute(sql, values)]
            total = c.execute('SELECT COUNT(*) FROM targets t WHERE ' + where, values).fetchone()[0]
            services = c.execute('SELECT COUNT(*) FROM target_services WHERE target_id IN (' + selected + ')', values).fetchone()[0]
            jobs = c.execute('SELECT COUNT(DISTINCT d.job_id) FROM target_discoveries d WHERE d.target_id IN (' + selected + ') AND ' + discovery_clause, [*values, *discovery_values]).fetchone()[0]
            result = {'total': total, 'services': services, 'jobs': jobs}
            for field in ('country', 'city', 'status'):
                result[field] = grouped(f'SELECT COALESCE(t.{field},\'غير معروف\') AS value,COUNT(*) AS count FROM targets t WHERE {where} GROUP BY t.{field} ORDER BY count DESC,value LIMIT 20')
            result['ports'] = grouped('SELECT port AS value,COUNT(DISTINCT target_id) AS count FROM target_services WHERE target_id IN (' + selected + ') GROUP BY port ORDER BY count DESC,value LIMIT 20')
            # Discovery-day buckets use Aden time; only actual recorded times participate.
            result['timeline'] = [dict(r) for r in c.execute("SELECT date(d.found_at,'+3 hours') AS value,COUNT(DISTINCT d.target_id) AS count FROM target_discoveries d WHERE d.found_at IS NOT NULL AND d.target_id IN (" + selected + ') AND ' + discovery_clause + ' GROUP BY 1 ORDER BY 1 DESC LIMIT 90', [*values, *discovery_values])]
            return result

    def select_ids(self, filters=None):
        where, values = self._where(filters or {})
        with self.store.connection() as c:
            return [r[0] for r in c.execute('SELECT t.id FROM targets t WHERE ' + where + ' ORDER BY t.ip_version,t.ip_key', values)]

    def export(self, filters, format_name):
        if format_name not in ('txt', 'csv', 'json'): raise ValueError('صيغة تصدير غير صالحة.')
        where, values = self._where(filters or {})
        output = io.BytesIO()
        def write(data):
            if output.tell() + len(data) > 128 * 1024 * 1024: raise ValueError('التصدير أكبر من 128 MiB؛ ضيّق الفلاتر ثم أعد المحاولة.')
            output.write(data)
        stream = io.StringIO(newline=''); writer = csv.writer(stream)
        columns = ['ip', 'country', 'city', 'asn', 'org', 'first_found_at', 'last_found_at', 'enriched_at', 'last_seen', 'status', 'services']
        if format_name == 'csv': writer.writerow(columns); write(b'\xef\xbb\xbf' + stream.getvalue().encode()); stream.seek(0); stream.truncate()
        if format_name == 'json': write(b'{"targets":[')
        first = True
        # Keep one read snapshot while workers continue writing through WAL.
        with self.store.connection() as c:
            c.execute('BEGIN')
            cursor = c.execute('SELECT t.* FROM targets t WHERE ' + where + ' ORDER BY t.ip_version,t.ip_key', values)
            for row in cursor:
                if format_name == 'txt': write((row['ip'] + '\n').encode()); continue
                item = self._public(c, row)
                if format_name == 'json':
                    write((('' if first else ',') + json.dumps(item, ensure_ascii=False)).encode()); first = False
                else:
                    cells = [json.dumps(item[k], ensure_ascii=False) if k == 'services' else item.get(k, '') for k in columns]
                    writer.writerow(["'" + str(v) if str(v).startswith(('=', '+', '-', '@', '\t', '\r')) else v for v in cells])
                    write(stream.getvalue().encode()); stream.seek(0); stream.truncate()
        if format_name == 'json': write(b']}')
        return output.getvalue(), {'txt': 'text/plain', 'json': 'application/json', 'csv': 'text/csv'}[format_name] + '; charset=utf-8'

    def add_items(self, job_id, target_ids, automatic=False):
        with self.store.connection() as c:
            c.execute('BEGIN IMMEDIATE')
            position = c.execute('SELECT COALESCE(MAX(position),-1)+1 FROM enrichment_items WHERE job_id=?', (job_id,)).fetchone()[0]
            for ident in dict.fromkeys(target_ids):
                if not c.execute('SELECT 1 FROM targets WHERE id=?', (ident,)).fetchone(): raise ValueError('هدف غير موجود.')
                if automatic and not c.execute('INSERT OR IGNORE INTO target_auto_claims VALUES(?,?)', (ident, job_id)).rowcount: continue
                inserted = c.execute('INSERT OR IGNORE INTO enrichment_items(job_id,target_id,position) VALUES(?,?,?)', (job_id, ident, position)).rowcount
                position += inserted
            c.commit()

    def items(self, job_id):
        with self.store.connection() as c:
            return [dict(r) for r in c.execute('SELECT e.target_id,t.ip,t.demo,e.status,e.document FROM enrichment_items e JOIN targets t ON t.id=e.target_id WHERE e.job_id=? ORDER BY position', (job_id,))]

    def apply_item(self, job_id, item):
        if item.get('status') not in ('success', 'partial', 'not_found', 'failed'): raise ValueError('حالة إثراء غير صالحة.')
        with self.store.connection() as c:
            c.execute('UPDATE enrichment_items SET status=?,document=? WHERE job_id=? AND target_id=?',
                      (item['status'], _json(item), job_id, item['target_id']))
            if item['status'] in ('not_found', 'failed'):
                c.execute('UPDATE targets SET status=? WHERE id=? AND enriched_at IS NULL', (item['status'], item['target_id']))

    def progress(self, job_id):
        with self.store.connection() as c:
            counts = dict(c.execute('SELECT status,COUNT(*) FROM enrichment_items WHERE job_id=? GROUP BY status', (job_id,)).fetchall())
        total = sum(counts.values()); done = total - counts.get('pending', 0)
        return {'total': total, 'processed': done, 'percent': round(100 * done / total, 1) if total else 100,
                **{k: counts.get(k, 0) for k in ('pending', 'success', 'partial', 'not_found', 'failed')}}

    def automatic_candidates(self):
        with self.store.connection() as c:
            rows = c.execute('''SELECT d.target_id,d.context,d.found_at FROM target_discoveries d JOIN targets t ON t.id=d.target_id
                WHERE t.demo=0 AND t.enriched_at IS NULL AND NOT EXISTS(SELECT 1 FROM target_auto_claims a WHERE a.target_id=t.id)
                ORDER BY d.target_id,d.found_at IS NULL,d.found_at,json_extract(d.context,'$.created_at'),d.job_id''').fetchall()
        selected = {}; groups = {}
        for row in rows: selected.setdefault(row['target_id'], json.loads(row['context']))
        for ident, context in selected.items(): groups.setdefault(context['id'], {'context': context, 'ids': []})['ids'].append(ident)
        return groups.values()
