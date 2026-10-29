#!/usr/bin/env python3
"""Offline rollback guard: pause protected jobs before running pre-VPN code."""
import argparse
import json
from pathlib import Path
import sqlite3


def pause(path):
    path=Path(path)
    if path.is_symlink() or not path.is_file(): raise ValueError('Expected an existing regular SQLite database.')
    with sqlite3.connect(path) as con:
        if con.execute('PRAGMA integrity_check').fetchone()[0]!='ok': raise ValueError('Integrity check failed.')
        changed=0
        for ident,document in con.execute('SELECT id,document FROM jobs').fetchall():
            job=json.loads(document)
            if job.get('network_mode','direct')!='direct' and job.get('status') not in {'completed','completed_warnings','cancelled'}:
                job.update(status='paused',error='VPN task paused for code rollback. Re-upgrade before resuming.',input_reason='vpn_rollback')
                con.execute('UPDATE jobs SET status=?,document=? WHERE id=?',('paused',json.dumps(job,ensure_ascii=False),ident));changed+=1
    return changed


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('database');args=parser.parse_args()
    print('Protected jobs paused:',pause(args.database))
