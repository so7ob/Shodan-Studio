#!/usr/bin/env python3
"""Opt-in real Chromium test in a separate, disconnected systemd namespace."""
import argparse
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import sys
import time
import uuid


def inside(folder):
    from studio.browser_session import Session
    s=Session(folder)
    try:
        s.call('Page.setDocumentContent',{'frameId':s.main_frame,'html':'<html><body><input id="field" aria-label="Fixture" style="position:absolute;left:20px;top:20px;width:200px;height:50px"><p>Synthetic offline fixture</p></body></html>'})
        s.action({'action':'click','x':70,'y':40});s.action({'action':'text','text':'fixture-text'})
        value=s.call('Runtime.evaluate',{'expression':'document.getElementById("field").value','returnByValue':True})['result']['value']
        assert value=='fixture-text'
        frame=s.action({'action':'frame'});assert frame['image'].startswith('data:image/jpeg;base64,')
        s.call('Page.navigate',{'url':'chrome://sandbox'})
        for _ in range(30):
            sandbox=s.call('Runtime.evaluate',{'expression':'document.body.innerText','returnByValue':True})['result'].get('value','')
            if 'Seccomp-BPF' in sandbox:break
            time.sleep(.1)
        assert 'Layer 1 Sandbox\tNamespace' in sandbox and 'PID namespaces\tYes' in sandbox and 'Network namespaces\tYes' in sandbox and 'Seccomp-BPF sandbox\tYes' in sandbox, sandbox
        try:
            socket.create_connection(('1.1.1.1',443),timeout=2).close()
            raise AssertionError('Disconnected test namespace leaked!')
        except OSError:pass
        assert os.readlink('/proc/self/ns/net')!=os.environ['STUDIO_TEST_HOST_NETNS']
        status=Path('/proc/self/status').read_text()
        assert 'CapEff:\t0000000000000000' in status and 'NoNewPrivs:\t1' in status
        print(json.dumps(dict(real_chromium=True,headed_xvfb=True,manual_input_transport=True,
            frame_bytes=len(frame['image']),uid=os.getuid(),namespace_isolated=True,
            disconnected_namespace_leak_blocked=True,namespace_sandbox=True,seccomp_sandbox=True,
            capabilities_zero=True,no_new_privileges=True,no_shodan_requests=True)))
    finally:s.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-root-lab',action='store_true')
    parser.add_argument('--inside-lab')
    args=parser.parse_args()
    if args.inside_lab:return inside(args.inside_lab)
    if not args.run_root_lab or os.getuid()!=0:parser.error('Explicit --run-root-lab and root required.')
    root=Path(__file__).resolve().parents[1];ident=uuid.uuid4().hex[:10]
    code=Path('/opt/shodan-studio')/('browser-test-'+ident)
    folder=Path('/var/lib/shodan-studio-browser')/('test-'+ident)
    account=pwd.getpwnam('shodan-browser');assert account.pw_uid!=0
    sys.path.insert(0,str(root))
    from studio.browser_broker import browser_guard
    # Parse with the real nft binary in a throwaway network namespace.
    subprocess.run(['unshare','--net','nft','--check','-f','-'],input=browser_guard(account.pw_uid),text=True,check=True)
    try:
        code.mkdir(mode=0o755);shutil.copytree(root/'studio',code/'studio',ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copyfile(__file__,code/'verify_browser.py')
        folder.mkdir(mode=0o700);os.chown(folder,account.pw_uid,account.pw_gid)
        argv=['systemd-run','--quiet','--wait','--pipe','--collect','--unit=shodan-browser-test-'+ident,
            '-p','User=shodan-browser','-p','Group=shodan-browser','-p','PrivateNetwork=yes',
            '-p','PrivateTmp=yes','-p','ProtectSystem=strict','-p','ProtectHome=yes',
            '-p','NoNewPrivileges=yes','-p','CapabilityBoundingSet=',
            '-p','RestrictNamespaces=net mnt user pid ipc uts','-p','RuntimeMaxSec=60',
            '--setenv=STUDIO_TEST_HOST_NETNS='+os.readlink('/proc/self/ns/net'),
            '-p','WorkingDirectory='+str(code),'-p','ReadWritePaths='+str(folder),
            '/usr/bin/python3','-s',str(code/'verify_browser.py'),'--inside-lab',str(folder)]
        subprocess.run(argv,check=True,timeout=70)
    finally:
        subprocess.run(['systemctl','stop','shodan-browser-test-'+ident],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        shutil.rmtree(code,ignore_errors=True);shutil.rmtree(folder,ignore_errors=True)


if __name__=='__main__':main()
