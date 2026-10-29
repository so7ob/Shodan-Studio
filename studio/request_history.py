"""Bounded request messages and durable, offline-recoverable query history."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re

from .engine import SUPPORTED_FACETS, api_redact
from .store import _json


STATES = {'requesting', 'processing', 'success', 'empty', 'unavailable', 'failed',
          'rate_limited', 'challenge', 'login_required', 'connection_failed', 'uncertain', 'cached', 'snapshot'}
NUMBERS = ('number', 'session_number', 'api_page', 'retry_number', 'total_records',
           'row_count', 'new_unique_ips', 'http_status', 'duration_ms')
TEXT = ('query', 'facet', 'source', 'transport', 'started_at', 'finished_at', 'error')


def state_for(entry):
    status, error = entry.get('result_status',entry.get('status')), str(entry.get('error') or '')
    if status=='parsed' and entry.get('row_count')==0:
        return 'empty' if entry.get('displayed_total',entry.get('total_records'))==0 else 'unavailable'
    if status == 'interrupted': return 'uncertain'
    if status == 'failed':
        if 'BROWSER_CHALLENGE' in error or '[ACCESS]' in error: return 'challenge'
        if 'BROWSER_LOGIN' in error or '[LOGIN]' in error or entry.get('http_status') == 401: return 'login_required'
        if entry.get('http_status') == 429: return 'rate_limited'
        if any(x in error for x in ('TIMEOUT', 'NETWORK', 'CONNECTION', 'DNS', 'TLS', 'HTTP_ERROR', 'CURL')):
            return 'connection_failed'
        return 'failed'
    return {'parsed':'success', 'received':'processing'}.get(status, status if status in STATES else 'uncertain')


def summary(entry, origin='live'):
    """An allowlist deliberately excludes URLs, headers, raw responses and keys."""
    result = {'request_id':entry['request_id'], 'status':state_for(entry), 'origin':origin}
    for key in TEXT:
        value = entry.get(key)
        result[key] = api_redact(value, None) if isinstance(value, str) else None
    aliases = {'total_records':('total_records','displayed_total','api_total'),
               'row_count':('row_count','records_received')}
    for key in NUMBERS:
        value = next((entry[k] for k in aliases.get(key,(key,)) if entry.get(k) is not None), None)
        result[key] = value if type(value) in (int,float) and math.isfinite(value) and value >= 0 else None
    return result


def clean_value(row):
    value=api_redact(row['value'],None)
    label=api_redact(row.get('label') or row['value'],None)
    # A malformed source can return an enormous label. Keep logging bounded
    # without changing the original page, query or extraction behavior.
    return {'value':value[:4096],'label':label[:4096],'count':row.get('count'),
            'truncated':bool(row.get('truncated')) or len(value)>4096 or len(label)>4096}


def batches(rows):
    """Stay below the 2 MiB worker boundary even for maximum-size API facets."""
    batch, size, offset = [], 0, 0
    for row in rows:
        clean = clean_value(row)
        length = len(_json(clean).encode())
        if batch and (len(batch) >= 100 or size + length > 64000):
            yield offset, batch
            offset += len(batch); batch, size = [], 0
        batch.append(clean); size += length
    if batch: yield offset, batch


class RequestHistory:
    def __init__(self, store):
        self.store = store
        with store.connection() as c:
            c.executescript('''
                CREATE TABLE IF NOT EXISTS request_history (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL,
                    request_id TEXT NOT NULL, origin TEXT NOT NULL, status TEXT NOT NULL,
                    document TEXT NOT NULL, accepted_ips INTEGER NOT NULL DEFAULT 0,
                    attribution_seen INTEGER NOT NULL DEFAULT 0, UNIQUE(job_id,request_id),
                    FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE);
                CREATE INDEX IF NOT EXISTS requests_job ON request_history(job_id,seq DESC);
                CREATE TABLE IF NOT EXISTS request_values (
                    job_id TEXT NOT NULL, request_id TEXT NOT NULL, position INTEGER NOT NULL,
                    document TEXT NOT NULL, PRIMARY KEY(job_id,request_id,position),
                    FOREIGN KEY(job_id,request_id) REFERENCES request_history(job_id,request_id) ON DELETE CASCADE);
                CREATE TABLE IF NOT EXISTS request_imports (
                    job_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL,
                    FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE);
            ''')
            columns={r[1] for r in c.execute('PRAGMA table_info(request_history)')}
            for name in ('accepted_ips','attribution_seen'):
                if name not in columns:c.execute(f'ALTER TABLE request_history ADD COLUMN {name} INTEGER NOT NULL DEFAULT 0')

    def save(self, job_id, entry, *, recovered=False):
        ident = entry.get('request_id')
        if not isinstance(ident,str) or not re.fullmatch(r'[a-f0-9]{32}',ident):
            raise ValueError('Invalid request identity')
        origin = entry.get('origin','live')
        if origin not in ('live','cache','legacy','snapshot'): raise ValueError('Invalid request origin')
        clean = summary(entry,origin)
        with self.store.connection() as c:
            c.execute('BEGIN IMMEDIATE')
            old=c.execute('SELECT accepted_ips,attribution_seen FROM request_history WHERE job_id=? AND request_id=?',(job_id,ident)).fetchone()
            if origin in ('live','cache'):
                if old and old['attribution_seen']:
                    clean['new_unique_ips']=old['accepted_ips']
                elif recovered:
                    clean['new_unique_ips']=None
                elif clean['new_unique_ips'] is not None:
                    clean['new_unique_ips']=0  # Complete collection, but no newly inserted IP batches.
            c.execute('''INSERT INTO request_history(job_id,request_id,origin,status,document) VALUES(?,?,?,?,?)
                ON CONFLICT(job_id,request_id) DO UPDATE SET status=excluded.status,document=excluded.document''',
                (job_id,ident,origin,clean['status'],_json(clean)))
            c.commit()
        return clean

    def values(self, job_id, request_id, offset, rows):
        if type(offset) is not int or offset < 0 or offset > 100000 or not isinstance(rows,list) or len(rows)>100:
            raise ValueError('Invalid request values')
        values=[]
        for i,row in enumerate(rows):
            if not isinstance(row,dict) or not isinstance(row.get('value'),str): raise ValueError('Invalid facet value')
            count=row.get('count')
            if count is not None and (type(count) is not int or count<0): raise ValueError('Invalid facet count')
            value=clean_value(row)
            values.append((job_id,request_id,offset+i,_json(value)))
        with self.store.connection() as c:
            c.execute('BEGIN IMMEDIATE')
            c.executemany('INSERT OR REPLACE INTO request_values VALUES(?,?,?,?)',values)
            c.commit()

    def list(self, job_id, before=0, limit=50):
        limit=min(200,max(1,int(limit)))
        with self.store.connection() as c:
            rows=c.execute('''SELECT seq,document,(SELECT COUNT(*) FROM request_values v WHERE v.job_id=h.job_id AND v.request_id=h.request_id) AS details_count
                           FROM request_history h WHERE job_id=? AND (?=0 OR seq<?) ORDER BY seq DESC LIMIT ?''',
                           (job_id,before,before,limit+1)).fetchall()
        items=[{**json.loads(r['document']),'seq':r['seq'],'details_count':r['details_count']} for r in rows[:limit]]
        return {'items':items,'next_cursor':items[-1]['seq'] if len(rows)>limit else None}

    def latest(self, job_id):
        with self.store.connection() as c:
            row=c.execute("SELECT seq,document FROM request_history WHERE job_id=? AND origin!='snapshot' ORDER BY seq DESC LIMIT 1",(job_id,)).fetchone()
        return {**json.loads(row['document']),'seq':row['seq']} if row else None

    def detail(self, job_id, request_id, offset=0, limit=100):
        with self.store.connection() as c:
            row=c.execute('SELECT document FROM request_history WHERE job_id=? AND request_id=?',(job_id,request_id)).fetchone()
            if row is None: raise KeyError(request_id)
            total=c.execute('SELECT COUNT(*) FROM request_values WHERE job_id=? AND request_id=?',(job_id,request_id)).fetchone()[0]
            rows=c.execute('SELECT document FROM request_values WHERE job_id=? AND request_id=? ORDER BY position LIMIT ? OFFSET ?',
                           (job_id,request_id,min(1000,max(1,int(limit))),offset)).fetchall()
        return {'request':json.loads(row['document']), 'items':[json.loads(r[0]) for r in rows],
                'total':total,'offset':offset,'has_more':offset+len(rows)<total}

    def interrupt(self, job_id=None):
        with self.store.connection() as c:
            rows=c.execute("SELECT job_id,document FROM request_history WHERE status IN ('requesting','processing') AND (? IS NULL OR job_id=?)",(job_id,job_id)).fetchall()
        for row in rows:
            entry=json.loads(row['document']);entry.update(status='uncertain',duration_ms=None,finished_at=None)
            self.save(row['job_id'],entry)

    def backfill(self, job_id, directory):
        """Import only local evidence, without updating the task or contacting Shodan."""
        def read(name):
            p=Path(directory)/name
            if not p.is_file() or p.is_symlink(): return {}
            try:
                value=json.loads(p.read_text())
                return value if isinstance(value,dict) else {}
            except (OSError,ValueError): return {}
        report,checkpoint=read('result.txt.report.json'),read('checkpoint.json')
        with self.store.connection() as c:
            events=[{**json.loads(r['document']),'id':r['id'],'at':r['at']} for r in c.execute('SELECT id,at,document FROM events WHERE job_id=? ORDER BY id',(job_id,))]
            old=c.execute('SELECT fingerprint FROM request_imports WHERE job_id=?',(job_id,)).fetchone()
            modern=[json.loads(r[0]) for r in c.execute("SELECT document FROM request_history WHERE job_id=? AND origin='live'",(job_id,))]
        fingerprint=hashlib.sha256(json.dumps([report,checkpoint,[(e['id'],e.get('kind')) for e in events]],sort_keys=True).encode()).hexdigest()
        if old and old[0]==fingerprint: return
        def identity(*parts): return hashlib.sha256(json.dumps([job_id,*parts],sort_keys=True).encode()).hexdigest()[:32]
        def key(e): return tuple(e.get(k) for k in ('session_number','number','source','facet','query','api_page'))
        modern_keys={key(e) for e in modern}
        starts=defaultdict(list);session=None
        for event in events:
            session=event.get('stats',{}).get('session_number',session)
            if event.get('request_id'): continue  # Modern start logs are not a second attempt.
            match=re.fullmatch(r'\[(\d+)/\d+\] (API )?([A-Z]+)(?: page=(\d+))?(?: retry=(\d+))? \| (.*)',str(event.get('message','')))
            if not match or match[3].lower() not in SUPPORTED_FACETS: continue
            entry={'request_id':identity('event',event['id']),'origin':'legacy','status':'uncertain',
                   'session_number':session,'number':int(match[1]),'source':'api' if match[2] else 'html',
                   'facet':match[3].lower(),'query':match[6],'api_page':int(match[4]) if match[4] else None,
                   'retry_number':int(match[5] or 0),'started_at':event['at']}
            if key(entry) not in modern_keys: starts[key(entry)].append(entry)
        matched=set();pending=[]
        for index,page in enumerate(report.get('pages',[])):
            if not isinstance(page,dict) or not isinstance(page.get('query'),str): continue
            if page.get('request_id'):
                # Reconcile an IPC crash from a final report with the exact identity.
                try: saved=self.detail(job_id,page['request_id'])['request']
                except KeyError: saved=None
                if saved is None or saved['status'] in ('requesting','processing','uncertain'):
                    recovered={**page,'origin':'live'}
                    if state_for(recovered) in ('requesting','processing'):
                        recovered.update(status='uncertain',duration_ms=None,finished_at=None)
                    self.save(job_id,recovered,recovered=True)
                for offset,rows in batches(page.get('rows',[])): self.values(job_id,page['request_id'],offset,rows)
                continue
            entry={**page,'origin':'legacy','session_number':report.get('resume',{}).get('session_number',1),
                   'request_id':identity('report',report.get('started_at_utc'),index)}
            possible=starts.get(key(entry),[])
            if len(possible)==1 and report.get('started_at_utc') and possible[0]['started_at']>=report['started_at_utc'] and (not report.get('finished_at_utc') or possible[0]['started_at']<=report['finished_at_utc']):
                entry.update(request_id=possible[0]['request_id'],started_at=possible[0]['started_at']);matched.add(entry['request_id'])
            pending.append((entry,page.get('rows',[]),entry.get('started_at') or report.get('started_at_utc')))
        for entries in starts.values():
            for entry in entries:
                if entry['request_id'] not in matched:
                    # Never overwrite a result already recovered on an earlier startup.
                    try: self.detail(job_id,entry['request_id'])
                    except KeyError: pending.append((entry,[],entry.get('started_at')))
        for page in checkpoint.get('state',{}).get('cache',[]):
            if not isinstance(page,dict) or not isinstance(page.get('query'),str): continue
            entry={**page,'request_id':identity('snapshot',page),'origin':'snapshot','status':'snapshot',
                   'total_records':page.get('total'),'row_count':len(page.get('rows',[]))}
            self.save(job_id,entry)
            for offset,rows in batches(page.get('rows',[])): self.values(job_id,entry['request_id'],offset,rows)
        def order(item):
            entry,_,anchor=item
            try: timestamp=datetime.fromisoformat(anchor.replace('Z','+00:00')).timestamp()
            except (ValueError,AttributeError,OverflowError): timestamp=float('-inf')
            return timestamp,entry.get('session_number') or 0,entry.get('number') or 0
        # Unmatched logs from older sessions must not replace the last known
        # request simply because reports were imported first.
        for entry,values,_ in sorted(pending,key=order):
            self.save(job_id,entry)
            for offset,rows in batches(values): self.values(job_id,entry['request_id'],offset,rows)
        with self.store.connection() as c:
            c.execute('INSERT OR REPLACE INTO request_imports VALUES(?,?)',(job_id,fingerprint))
