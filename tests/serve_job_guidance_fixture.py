"""Disposable loopback-only dashboard fixture; queue never starts."""
import argparse
import json
from pathlib import Path
import sys
import tempfile
import time
from wsgiref.simple_server import make_server

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from studio import engine
from studio.server import create_app
from studio.worker import build_args
from test_vpn import FakeProvider


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8878)
    parser.add_argument('--info', type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='studio-guidance-fixture-') as folder:
        app = create_app(folder, allowed_hosts=[f'127.0.0.1:{args.port}'], demo=True, autostart=False)
        manager = app.manager
        manager.vpn.provider = FakeProvider()
        manager.store.setup(manager.store.setup_token(), 'fixture', 'local-fixture-password-123!')
        states = {
            'malformed': ('2099-01-01T00:00:00Z', False, False, 'rate_limit', '[HTTP_429] synthetic malformed deadline'),
            'future': (time.time() + 3600, False, True, 'rate_limit', '[HTTP_429] synthetic wait'),
            'manual': (time.time() + 7200, True, True, 'rate_limit', '[RATE_LIMIT_WAIT_LIMIT] synthetic hold'),
            'expired': (time.time() - 60, False, True, 'rate_limit', '[HTTP_429] synthetic expired wait'),
            'denied': (None, False, True, 'source_error', '[HTTP_403] <img data-fixture-injected src=x onerror=alert(1)>'),
            'missing': (None, False, False, None, 'Synthetic interrupted worker'),
        }
        ids = {}
        for name, (deadline, unbounded, checkpoint, reason, error) in states.items():
            job = manager.create_job({'title': 'Fixture · ' + name, 'query': 'synthetic fixture',
                                      'mode': 'html', 'settings': {'demo': True, 'delay': 0}})
            if checkpoint:
                crawler = engine.Crawler(build_args(manager._path(job['id']), job, None))
                crawler.not_before_utc, crawler.wait_unbounded = deadline, unbounded
                crawler.checkpoint('paused')
            manager.store.update_job(job['id'], status='waiting_input', input_reason=reason, error=error,
                                     stats={**job['stats'], 'wait_until': deadline, 'wait_unbounded': unbounded})
            ids[name] = job['id']
        args.info.write_text(json.dumps(ids))
        try:
            with make_server('127.0.0.1', args.port, app) as server: server.serve_forever()
        finally: manager.shutdown()


if __name__ == '__main__': main()
