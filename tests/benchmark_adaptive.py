"""Reproducible synthetic request counts. Never contacts Shodan or target IPs."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
sys.path[:0]=[str(Path(__file__).resolve().parents[1]),str(Path(__file__).resolve().parent)]
from studio import engine
from test_adaptive import Dataset


def benchmark():
    results=[]
    for name,kwargs in [('small_60',{'size':60}),('160_port',{}),('160_version',{'layout':'version'}),
                        ('160_country_only',{'layout':'country'}),('160_fragmented_port',{'layout':'fragmented'}),
                        ('200_records_50_ips',{'size':200,'unique':50})]:
        row={'case':name,'synthetic':True};ips={}
        for strategy in ('priority','adaptive'):
            data=Dataset(**kwargs)
            with tempfile.TemporaryDirectory(prefix='adaptive-benchmark-') as folder:
                args=engine.parse_args(['--query','fixture','--mode','html','--strategy',strategy,'--delay','0',
                    '--max-requests','300','--include-non-global','--checkpoint',str(Path(folder)/'checkpoint.json')])
                with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
                    report=engine.Crawler(args,fetcher=data.fetch,sleeper=lambda _:None).run()
                ips[strategy]=set(report['ips'])
                row[strategy]={'requests':len(data.calls),'branches':len(report['plan']['extraction_order']),
                    'unique_ips':len(ips[strategy]),'chosen':report['plan'].get('last_decision',{}).get('facet'),
                    'facet_requests':[facet for _,facet in data.calls if facet!='ip']}
        assert ips['priority']==ips['adaptive']
        row['identical_ip_sets']=True;results.append(row)
    return {'live_requests':False,'cases':results}

if __name__=='__main__':
    result=benchmark();folder=Path(__file__).resolve().parents[1]/'docs/planner-evidence';folder.mkdir(exist_ok=True)
    (folder/'benchmark.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
