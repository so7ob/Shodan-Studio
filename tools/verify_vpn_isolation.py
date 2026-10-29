#!/usr/bin/env python3
"""Explicit root-only local AWG lab. Never uses a customer's keys or endpoints.

Creates two ephemeral tunnel interfaces and a local HTTPS peer; tears them down
in finally. No host default routes/firewall/DNS modifications. Source-only test,
not a production service. Run: python3 tools/verify_vpn_isolation.py --run-root-lab
--awg /absolute/path/to/official/awg
"""
import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from studio import vpn_helper as helper


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--run-root-lab',action='store_true');parser.add_argument('--awg',required=True)
    args=parser.parse_args()
    if not args.run_root_lab or os.geteuid()!=0: raise SystemExit('Requires explicit --run-root-lab as root.')
    helper.AWG=str(Path(args.awg).resolve());helper.NS='ssvpn-proof';helper.IFACE='ssvproofc'
    server_iface='ssvproofs'
    if Path('/run/netns',helper.NS).exists(): raise SystemExit('Lab namespace already exists; refusing to reuse.')
    for name in (helper.IFACE,server_iface):
        if helper.command([helper.IP,'link','show',name],check=False).returncode==0: raise SystemExit('Lab interface already exists.')
    def snapshot():
        return {key:hashlib.sha256(helper.command(cmd).encode()).hexdigest() for key,cmd in {
            'routes4':[helper.IP,'-j','route','show','table','all'],
            'routes6':[helper.IP,'-j','-6','route','show','table','all'],
            'rules':[helper.IP,'rule','show'],'firewall':[helper.NFT,'--stateless','list','ruleset']}.items()} | {
            'dns':hashlib.sha256(Path('/etc/resolv.conf').read_bytes()).hexdigest()}
    def management():
        for port in (22,8787):
            with socket.create_connection(('127.0.0.1',port),timeout=2): pass
    before=snapshot();management()
    result={'kind':'local-synthetic-AWG-lab','real_premium_test':False,'host_management_before':True}
    with tempfile.TemporaryDirectory(prefix='studio-vpn-proof-') as temp:
        root=Path(temp);root.chmod(0o755)
        broker=helper.Broker(root=root/'profiles',runtime=root/'run',code=root,data=root/'data')
        shutil.copytree(Path(__file__).resolve().parents[1]/'studio', root/'studio', ignore=shutil.ignore_patterns('__pycache__'))
        daemon=None; httpd=None
        def awg(*argv,data=None): return helper.command([helper.AWG,*argv],data=data)
        def keypair():
            private=awg('genkey').strip();public=awg('pubkey',data=private+'\n').strip();return private,public
        private1,public1=keypair();private2,public2=keypair();header=base64.b64encode(os.urandom(32)).decode()
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            sock.bind(('127.0.0.1',0));udp=sock.getsockname()[1]
        common=f'Jc = 3\nJmin = 10\nJmax = 50\nS1 = 16\nS2 = 16\nS3 = 16\nS4 = 16\nH1 = 1001\nH2 = 1002\nH3 = 1003\nH4 = 1004\nHeaderProtectionKey = {header}\n'
        try:
            daemon=subprocess.Popen([helper.GO,'-f',server_iface],env=helper.ENV,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            for _ in range(50):
                if Path('/run/amneziawg',server_iface+'.sock').exists(): break
                time.sleep(.1)
            server=f'[Interface]\nPrivateKey = {private1}\nListenPort = {udp}\n{common}[Peer]\nPublicKey = {public2}\nAllowedIPs = 10.203.254.2/32\n'
            awg('setconf',server_iface,'/dev/stdin',data=server)
            helper.command([helper.IP,'addr','add','10.203.254.1/32','dev',server_iface])
            helper.command([helper.IP,'link','set',server_iface,'up'])
            helper.command([helper.IP,'route','add','10.203.254.2/32','dev',server_iface])
            cert=root/'cert.pem'; key=root/'key.pem'
            subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=local-isolation-proof','-addext','subjectAltName=IP:10.203.254.1'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            cert.chmod(0o644)
            class Handler(BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200);self.end_headers();self.wfile.write(b'isolated-local-fixture')
                def log_message(self,*_): pass
            httpd=ThreadingHTTPServer(('10.203.254.1',0),Handler)
            tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(cert,key);httpd.socket=tls.wrap_socket(httpd.socket,server_side=True)
            threading.Thread(target=httpd.serve_forever,daemon=True).start()
            url=f'https://10.203.254.1:{httpd.server_port}/'
            def worker(argv,timeout=10):
                prefix=broker._unprivileged('unused')[:-4]
                # Strip fixed Python module suffix, retaining setpriv and namespaces.
                return subprocess.run(prefix+argv,env=helper.ENV,cwd='/',text=True,capture_output=True,timeout=timeout)
            def local_health():
                info=broker._isolation()
                probe=worker(['/usr/bin/curl','--disable','--noproxy','*','--silent','--max-time','6','--cacert',str(cert),url])
                if probe.returncode or probe.stdout!='isolated-local-fixture': raise RuntimeError('Local isolated HTTPS failed.')
                output=awg('show',helper.IFACE,'latest-handshakes')
                handshake=bool(output.strip()) and all(int(line.split()[1])>0 for line in output.splitlines())
                assert handshake and info['leak_protection'] and info['route_verified']
                return dict(healthy=True,egress_ip='local-fixture-only',handshake=True,**info)
            broker.health_check=local_health
            raw=f'[Interface]\nPrivateKey = {private2}\nAddress = 10.203.254.2/32\nDNS = 1.1.1.1\n{common}[Peer]\nPublicKey = {public1}\nEndpoint = 127.0.0.1:{udp}\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n'
            p=broker.add(raw,{'name':'LOCAL FIXTURE','country':'','enabled':True})
            report=broker.connect(p['id'])
            result['awg3_handshake']=report['handshake'];result['curl_https_in_namespace']=True
            py=worker(['/usr/bin/python3','-c',"import urllib.request,ssl;print(urllib.request.urlopen("+repr(url)+",context=ssl.create_default_context(cafile="+repr(str(cert))+"),timeout=5).read().decode())"])
            assert py.returncode==0 and 'isolated-local-fixture' in py.stdout
            result['python_https_in_namespace']=True
            caps=worker(['/usr/bin/python3','-c',"import os;print(os.getuid());print([x for x in open('/proc/self/status') if x.startswith('CapEff:')][0].strip())"])
            assert str(broker.uid) in caps.stdout and '0000000000000000' in caps.stdout
            result['worker_unprivileged_zero_effective_capabilities']=True
            management();result['ssh_and_dashboard_during_tunnel']=True
            # Run the real crawler through the privileged broker, with synthetic
            # source data and real checkpoint/result files under the dropped UID.
            from studio.config import validate_job
            ident='a'*32
            folder=broker.data/'jobs'/ident
            folder.mkdir(parents=True)
            broker.data.chmod(0o755);folder.parent.chmod(0o755)
            folder.chmod(0o700);os.chown(folder,broker.uid,broker.gid)
            job,_=validate_job({'query':'country:EG','mode':'html','settings':{'demo':True,'delay':0,'max_requests':100}},allow_demo=True)
            job.update(id=ident,active_vpn_profile=p['id'])
            client,remote=socket.socketpair()
            errors=[]
            def stream_worker():
                try:
                    with remote: broker.run_worker({'op':'run','job_id':ident,'payload':{'job':job}},remote)
                except Exception as exc: errors.append(type(exc).__name__)
            thread=threading.Thread(target=stream_worker);thread.start()
            with client,client.makefile('rb') as stream:
                events=[json.loads(line) for line in stream]
            thread.join(timeout=10)
            assert not errors and events[-1]['status']=='completed'
            assert events[-1]['stats']['unique_ips']==292 and (folder/'checkpoint.json').exists()
            assert (folder/'checkpoint.json').stat().st_uid==broker.uid
            assert broker.running_job is None
            result['real_broker_worker_checkpoint_292_synthetic_ips']=True

            broker.disconnect()
            # Both transports must fail after tunnel removal; no alternative route.
            leak=worker(['/usr/bin/python3','-c',"import socket;socket.create_connection(('1.1.1.1',443),2)"])
            assert leak.returncode!=0
            curl=worker(['/usr/bin/curl','--disable','--noproxy','*','--silent','--max-time','3','https://1.1.1.1/'])
            assert curl.returncode!=0
            result['fail_closed_after_disconnect_python_and_curl']=True
            result['empty_namespace_leak_protection']=broker._isolation()['leak_protection']
            management();result['ssh_and_dashboard_after_disconnect']=True
        finally:
            broker._remove_interface()
            helper.command([helper.IP,'netns','del',helper.NS],check=False)
            helper.command([helper.IP,'link','del',server_iface],check=False)
            if daemon:
                daemon.terminate()
                try: daemon.wait(timeout=5)
                except subprocess.TimeoutExpired: daemon.kill();daemon.wait()
            if httpd: httpd.shutdown();httpd.server_close()
            shutil.rmtree(Path('/etc/netns')/helper.NS,ignore_errors=True)
    after=snapshot();result['host_state_restored']=before==after;result['host_snapshot_before']=before;result['host_snapshot_after']=after
    print(json.dumps(result,indent=2))
    assert before==after,'Host route/rule/firewall/DNS snapshot changed.'


if __name__=='__main__': main()
