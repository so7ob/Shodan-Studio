"""Offline request-count acceptance, scope safety and checkpoint replay."""
import contextlib
import html
import io
import json
from collections import Counter
from pathlib import Path
import tempfile
import unittest
from urllib.parse import parse_qs, urlsplit, urlencode
from unittest.mock import patch

from studio import engine
from studio.adaptive import AdaptivePlanner, complete_ip_page
from studio.config import settings_from
from studio.worker import build_args


class Dataset:
    def __init__(self, size=160, *, layout='port', unique=None):
        self.calls = []
        self.records = []
        for i in range(size):
            group = i//80
            record = dict(ip=f'192.0.2.{i % (unique or size)+1}',
                          country='DE' if group == 0 else 'FR',city=f'City{i%26}',
                          asn='AS100',port='80' if group == 0 else '443',version='1.0' if group == 0 else '2.0',
                          product='Fixture',org='Fixture',os='Fixture')
            if layout in ('version','country'):record['port']='80'
            if layout == 'country':record['version']='1.0'
            if layout == 'fragmented':record['port']=str(1000+i%52)
            self.records.append(record)
    def values(self, query, facet):
        fields=engine.scope_filters(query)
        records=[r for r in self.records if all(
            (r[name].casefold() not in {v.casefold() for v in values}) if negative else
            (r[name].casefold() in {v.casefold() for v in values})
            for name,entries in fields.items() for _,_,values,negative in entries)]
        return sorted(Counter(r[facet] for r in records).items(),key=lambda row:(-row[1],row[0])),len(records)
    def fetch(self,url):
        params=parse_qs(urlsplit(url).query);query=params['query'][0];facet=params['facet'][0]
        self.calls.append((query,facet))
        rows,total=self.values(query,facet)
        return self.html(query,facet,rows[:100],total)
    @staticmethod
    def html(query,facet,rows,total):
        title='' if total is None else f'<h2>Total: {total}</h2>'
        body=[f'<html><title>Facet analysis</title>{title}<form><input name="query" value="{html.escape(query,quote=True)}"><select name="facet"><option selected value="{facet}">{facet}</option></select></form><table class="facet-table">']
        for value,count in rows:
            narrowed=engine.narrow_query(query,facet,value) if facet!='ip' else query+' ip:"'+value+'"'
            link='/search?'+urlencode({'query':narrowed})
            body.append(f'<tr><td><a href="{html.escape(link,quote=True)}">{html.escape(value)}</a></td><td>{count}</td></tr>')
        body.append('</table></html>')
        return ''.join(body)


class AdaptiveTests(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def crawler(self,data,strategy='adaptive',**kwargs):
        args=engine.parse_args(['--query',kwargs.pop('query','fixture'),'--mode','html','--strategy',strategy,
            '--delay','0','--max-requests',str(kwargs.pop('max_requests',300)), '--include-non-global',
            '--output',str(self.root/'ips.txt'),'--checkpoint',str(self.root/'checkpoint.json'),*kwargs.pop('extra',[])])
        return engine.Crawler(args,fetcher=data.fetch, sleeper=lambda _:None)
    def run_crawler(self,c):
        with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):return c.run()
    def test_160_results_52_cities_drop_from_55_to_4_requests(self):
        legacy=Dataset();old=self.run_crawler(self.crawler(legacy,'priority'))
        # Separate checkpoint identity for the independent adaptive run.
        (self.root/'checkpoint.json').unlink()
        data=Dataset();new=self.run_crawler(self.crawler(data))
        self.assertEqual(old['plan']['ready_branches'],52)
        self.assertEqual((len(legacy.calls),len(data.calls)),(55,4))
        self.assertEqual(set(old['ips']),set(new['ips']));self.assertEqual(len(new['ips']),160)
        self.assertEqual(new['plan']['last_decision']['facet'],'port')
        self.assertEqual(len(new['plan']['extraction_order']),2)
        self.assertFalse(any(f in ('country','city') for _,f in data.calls))
        self.assertEqual(new['status'],'finished')
    def test_small_or_many_service_records_fit_one_ip_page(self):
        for size,unique in [(60,None),(100,None),(200,50)]:
            with self.subTest(size=size):
                self.root.joinpath('checkpoint.json').unlink(missing_ok=True)
                data=Dataset(size,unique=unique);report=self.run_crawler(self.crawler(data))
                self.assertEqual(len(data.calls),1);self.assertEqual(len(report['ips']),unique or size)
                self.assertEqual(report['plan']['facet_probes'],0)
    def test_version_handles_constant_ports_and_fragmented_ports_are_packed(self):
        for layout in ('version','fragmented'):
            with self.subTest(layout=layout):
                self.root.joinpath('checkpoint.json').unlink(missing_ok=True)
                data=Dataset(layout=layout);report=self.run_crawler(self.crawler(data))
                self.assertEqual(report['plan']['last_decision']['facet'],'port' if layout == 'fragmented' else 'version')
                self.assertEqual((len(data.calls),len(report['ips'])),(4 if layout == 'fragmented' else 5,160))
                self.assertEqual(len(report['plan']['extraction_order']),2)

    def test_snapshot_drift_keeps_complete_cheaper_partition(self):
        # Anonymized bucket sizes from the reported 581-record query. No IPs,
        # account data or live source requests are used in this regression.
        sizes = {
            'port': [289,191,17,6,6,5,5,4,3,3,3,3,3,2,2,2] + [1]*37,
            'asn': [300,82,59,30,24,22,11,7,6,6,5,5,5,3,3,3,2,2,2,1,1,1],
        }
        events = []
        def read(query, facet, expected):
            counts = sizes.get(facet, [])
            return engine.FacetPage(facet, [engine.FacetRow(str(1000+i), n, '') for i,n in enumerate(counts)], sum(counts), [], False)
        planner = AdaptivePlanner(read, lambda q,f,r: engine.narrow_query(q,f,r.value), event=lambda code,b,f,**kw: events.append((code,f,kw)))
        children = planner.choose(engine.PlanBranch('http.component:"php" country:"EG"',581),1000)
        self.assertEqual(len(children),4)
        chosen = next(e for e in events if e[0]=='PARTITION_CHOSEN')
        self.assertEqual(chosen[1],'asn')
        self.assertEqual(chosen[2]['estimated_requests'],8)
        self.assertEqual(sum(c.count for c in children),580)
        self.assertTrue(any(code=='SNAPSHOT_COUNT_CHANGED' for code,_,_ in events))
        self.assertEqual(planner.probes,3)

    def test_packed_scope_keeps_original_union_and_exclusions(self):
        data=Dataset(layout='fragmented')
        query='fixture country:"DE","FR" port:1000,1001,1002,1003 -port:9999'
        report=self.run_crawler(self.crawler(data,query=query))
        self.assertEqual(len(report['ips']),16)
        # Exercise grouping independently of the direct-IP shortcut.
        from studio.adaptive import pack_children
        branch=engine.PlanBranch(query,160)
        children=[engine.PlanBranch(engine.narrow_query(query,'port',v),40,('port',),(('port',v),),1) for v in ('1000','1001','1002','1003')]
        packed=pack_children(branch,'port',children)
        self.assertEqual(len(packed),2)
        returned=[]
        for child in packed:
            self.assertIn('country:"DE","FR"',child.query)
            self.assertIn('-port:9999',child.query)
            returned.extend(engine.scope_filters(child.query)['port'][0][2])
            self.assertNotIn('port',child.used_facets)
        self.assertCountEqual(returned,['1000','1001','1002','1003'])
        with self.assertRaises(engine.ScopeConflict):engine.narrow_query_values(query,'port',['1000','9999'])
        with self.assertRaises(engine.ScopeConflict):engine.narrow_query_values(query,'port',['1000','8080'])

    def test_grouped_values_are_quoted_and_round_trip(self):
        values=['New York','a,b','a"b','a\\b','القاهرة']
        query=engine.narrow_query_values('fixture -country:FR','city',values)
        self.assertEqual(engine.scope_filters(query)['city'][0][2],values)
        self.assertIn('-country:FR',query)

    def test_packed_checkpoint_reuses_completed_group(self):
        data=Dataset(layout='fragmented')
        with self.assertRaises(engine.SpiderError):self.run_crawler(self.crawler(data,max_requests=3))
        previous=set(data.calls)
        resumed=Dataset(layout='fragmented')
        args=engine.parse_args(['--resume',str(self.root/'checkpoint.json'),'--max-requests','100','--delay','0'])
        report=self.run_crawler(engine.Crawler(args,fetcher=resumed.fetch,sleeper=lambda _:None))
        self.assertEqual(len(report['ips']),160)
        self.assertEqual(len(resumed.calls),1)
        self.assertFalse(previous & set(resumed.calls))

    def test_growing_group_can_split_the_same_facet_again(self):
        class Changed(Dataset):
            def fetch(self,url):
                result=super().fetch(url)
                if self.calls[-1]==('fixture','port'):
                    for row in self.records:
                        if int(row['port']) >= 1045:row['port']='1000'
                return result
        data=Changed(layout='fragmented');report=self.run_crawler(self.crawler(data))
        self.assertEqual(len(report['ips']),160)
        selected=[e['facet'] for e in report['plan']['events'] if e['code']=='PARTITION_CHOSEN']
        self.assertEqual(selected,['port','port'])
        self.assertEqual(report['plan']['fallback_branches'],0)

    def test_source_total_survives_into_worker_stats(self):
        data=Dataset();c=self.crawler(data)
        self.run_crawler(c)
        self.assertEqual(c.report['plan']['source_total_records'],160)
    def test_country_can_be_terminal_without_city(self):
        data=Dataset(layout='country');report=self.run_crawler(self.crawler(data))
        self.assertEqual(report['plan']['last_decision']['facet'],'country')
        self.assertEqual((len(data.calls),len(report['ips'])),(7,160))
        self.assertNotIn('city',[f for _,f in data.calls])
    def test_original_scope_fixed_fields_and_exclusions_are_retained(self):
        data=Dataset();query='fixture country:"FR" -port:80'
        report=self.run_crawler(self.crawler(data,query=query))
        self.assertEqual(len(data.calls),1);self.assertEqual(len(report['ips']),80)
        self.assertTrue(all(q.startswith(query) for q,_ in data.calls))
    def test_gapped_unknown_duplicate_or_unavailable_candidates_are_rejected(self):
        for rows,total in [([('80',60),('443',50)],160),([('80',None),('443',80)],160),([('80',80),('80',80)],160),([],160)]:
            events=[]
            planner=AdaptivePlanner(lambda *args:engine.FacetPage('port',[engine.FacetRow(v,n,v) for v,n in rows],total,[],False),
                                    lambda q,f,row:engine.narrow_query(q,f,row.value),('port',),lambda *a,**kw:events.append(kw))
            self.assertIsNone(planner.choose(engine.PlanBranch('fixture',160),100))
            self.assertEqual(planner.probes,1)
    def test_all_nonreducing_facets_are_bounded_and_keep_partial_ips(self):
        data=Dataset()
        for record in data.records:
            for field in ('port','version','asn','country','city','product','org','os'):
                record[field]=data.records[0][field]
        report=self.run_crawler(self.crawler(data))
        self.assertEqual(len(data.calls),9);self.assertEqual(len(report['ips']),100)
        self.assertEqual(report['plan']['fallback_branches'],1)
        self.assertTrue(any(w['code']=='UNRESOLVED_BRANCH' for w in report['warnings']))
        self.assertFalse(report['complete_export'])
    def test_node_budget_never_admits_excess_children(self):
        data=Dataset();report=self.run_crawler(self.crawler(data,extra=['--max-plan-nodes','2']))
        self.assertEqual(len(report['plan']['extraction_order']),1)
        self.assertEqual(report['plan']['fallback_branches'],1)
        self.assertEqual(len(report['ips']),100)

    def test_node_budget_applies_after_packing_small_buckets(self):
        data=Dataset(layout='fragmented')
        report=self.run_crawler(self.crawler(data,extra=['--max-plan-nodes','3']))
        self.assertEqual(len(report['plan']['extraction_order']),2)
        self.assertEqual(len(report['ips']),160)
        self.assertEqual(report['plan']['fallback_branches'],0)

    def test_adaptive_chooses_automatically_despite_legacy_candidate_order(self):
        data=Dataset()
        report=self.run_crawler(self.crawler(data,extra=['--split-facets','city,os,org,product,country,asn,version,port']))
        self.assertEqual(len(data.calls),4)
        self.assertEqual(report['plan']['last_decision']['facet'],'port')
    def test_unknown_root_total_does_not_mistake_top_100_for_completion(self):
        class Unknown(Dataset):
            def fetch(self,url):
                result=super().fetch(url)
                return result.replace('<h2>Total: 160</h2>','') if self.calls[-1]==('fixture','ip') else result
        data=Unknown();report=self.run_crawler(self.crawler(data))
        self.assertEqual(len(report['ips']),160);self.assertEqual(len(data.calls),4)
        self.assertTrue(any(w['code']=='TOTAL_UNKNOWN' for w in report['warnings']))
    def test_actual_oversized_child_is_split_and_snapshot_warning_survives(self):
        class Changed(Dataset):
            def fetch(self,url):
                result=super().fetch(url)
                if self.calls[-1]==('fixture','port'):
                    for row in self.records[80:110]:row['port']='80'
                return result
        data=Changed();report=self.run_crawler(self.crawler(data))
        self.assertEqual(len(report['ips']),160)
        selected=[e['facet'] for e in report['plan']['events'] if e['code']=='PARTITION_CHOSEN']
        self.assertEqual(selected,['port','version'])
        self.assertTrue(any(w['code']=='PARENT_COUNT_MISMATCH' for w in report['warnings']))
    def test_checkpoint_resume_reuses_root_probes_and_completed_child(self):
        data=Dataset();c=self.crawler(data,max_requests=3)
        with self.assertRaises(engine.SpiderError):self.run_crawler(c)
        saved=engine.load_checkpoint(self.root/'checkpoint.json')
        self.assertEqual(saved['config']['strategy'],'adaptive')
        completed=set(data.calls);self.assertEqual(len(completed),3)
        resumed=Dataset();args=engine.parse_args(['--resume',str(self.root/'checkpoint.json'),'--max-requests','100','--delay','0'])
        final=self.run_crawler(engine.Crawler(args,fetcher=resumed.fetch,sleeper=lambda _:None))
        self.assertEqual(len(resumed.calls),1);self.assertFalse(completed&set(resumed.calls))
        self.assertEqual(len(final['ips']),160)
    def test_legacy_strategy_survives_checkpoint_and_old_job_without_strategy(self):
        data=Dataset();c=self.crawler(data,'priority',max_requests=1)
        with self.assertRaises(engine.SpiderError):self.run_crawler(c)
        args=engine.parse_args(['--resume',str(self.root/'checkpoint.json')])
        self.assertEqual(args.strategy,'priority')
        self.assertEqual(settings_from({'strategy':'priority'})['split_facets'],['asn','port','version','product'])
        self.assertEqual(settings_from({})['strategy'],'adaptive')
    def test_api_uses_paginated_root_search_without_facet_probes(self):
        class API:
            def __init__(self):self.calls=[]
            def request(self,path,params):
                self.calls.append((path,params));assert path.endswith('/search')
                start=(params['page']-1)*100
                return {'total':160,'matches':[{'ip_str':f'192.0.2.{i+1}','port':80,'_shodan':{'id':str(i)}} for i in range(start,min(start+100,160))]}
        data=Dataset();c=self.crawler(data);c.args.api_key_resolved='FIXTURE_ONLY';c.args.api_key_source='fixture'
        api=API();c.args.mode='api';c.configure_source('api',api)
        report=self.run_crawler(c)
        self.assertEqual(len(api.calls),2);self.assertEqual(len(report['ips']),160)
        self.assertFalse(data.calls);self.assertEqual(report['plan']['facet_probes'],0)

class AdaptiveWorkerTests(unittest.TestCase):
    def setUp(self):
        from test_worker import WorkerRecoveryTests
        WorkerRecoveryTests.setUp(self)
        self.job.update(query='fixture',mode='html',id='a'*32,network_mode='manual',browser_session_enabled=True)
        self.job['settings'].update(strategy='adaptive',split_facets=list(engine.ADAPTIVE_FACETS),demo=False,include_non_global=True)
    def tearDown(self):self.tmp.cleanup()
    def run_capture(self):
        from test_worker import WorkerRecoveryTests
        return WorkerRecoveryTests.run_capture(self)
    def checkpoint(self):return engine.load_checkpoint(self.job_dir/'checkpoint.json')
    def test_browser_denial_retains_ips_then_resumes_without_completed_requests(self):
        data=Dataset();calls=[]
        def fetch(op,**fields):
            calls.append(fields['url'])
            if len(calls)==3:raise RuntimeError('[HTTP_403] [BROWSER_CHALLENGE] fixture')
            return {'html':data.fetch(fields['url'])}
        with patch('studio.vpn_client.rpc',side_effect=fetch):code,events=self.run_capture()
        self.assertEqual(code,75);self.assertEqual(events[-1]['stats']['unique_ips'],100)
        self.assertEqual(events[-1]['input_reason'],'browser_challenge')
        completed=set(calls[:2]);resumed=[]
        def again(op,**fields):resumed.append(fields['url']);return {'html':data.fetch(fields['url'])}
        with patch('studio.vpn_client.rpc',side_effect=again):code,events=self.run_capture()
        self.assertEqual(code,0);self.assertEqual(events[-1]['stats']['unique_ips'],160)
        self.assertEqual(len(resumed),2);self.assertFalse(completed&set(resumed))
    def test_browser_retry_after_is_preserved_by_adaptive_checkpoint(self):
        with patch('studio.vpn_client.rpc',return_value={'http_status':429,'retry_after':3600}):code,events=self.run_capture()
        self.assertEqual(code,75);self.assertEqual(events[-1]['input_reason'],'rate_limit')
        with patch('studio.vpn_client.rpc',side_effect=AssertionError('No early retry')) as fetch:code,events=self.run_capture()
        self.assertEqual(code,75);fetch.assert_not_called()
