"""Root-owned, fixed-operation broker. All network mutations are namespace-local.

Not an RPC shell: no commands, paths, namespace names, UIDs or executables are
accepted from clients. Imported configs cannot contain quick hooks.
"""
from __future__ import annotations
import contextlib
import json
import os
from pathlib import Path
import pwd
import secrets
import selectors
import shutil
import signal
import socket
import socketserver
import stat
import struct
import subprocess
import threading
import time

from .vpn_config import metadata, parse_profile, profile_id
from .premium import Premium

NS = 'ssvpn-worker'
IFACE = 'ssvpn0'
IP = '/usr/sbin/ip'
NFT = '/usr/sbin/nft'
SETPRIV = '/usr/bin/setpriv'
WG = '/usr/bin/wg'
AWG = '/usr/local/libexec/shodan-studio/awg'
GO = '/opt/AmneziaVPN/bin/amneziawg-go'
ROOT = Path('/etc/shodan-studio/vpn')
RUNTIME = Path('/run/shodan-studio-vpn')
DATA = Path('/var/lib/shodan-studio')
CODE = Path('/opt/shodan-studio/current')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8',
       'PYTHONUNBUFFERED': '1', 'PYTHONDONTWRITEBYTECODE': '1', 'HOME': '/nonexistent'}


def command(argv, *, data=None, timeout=15, check=True):
    try:
        result = subprocess.run(argv, input=data, capture_output=True, text=True,
                                timeout=timeout, env=ENV, cwd='/', check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError('VPN system operation unavailable or timed out.') from None
    if check and result.returncode:
        # setconf errors can quote secret configuration; never return stderr.
        raise RuntimeError('VPN system operation failed; profile/tool compatibility must be checked.')
    return result.stdout if check else result


def private_write(path, data):
    tmp = path.with_name(path.name + '.new')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


class Broker:
    def __init__(self, root=ROOT, runtime=RUNTIME, code=CODE, data=DATA, uid=None, gid=None):
        self.root, self.runtime, self.code, self.data = map(Path, (root, runtime, code, data))
        account = pwd.getpwnam('shodan-studio')
        self.uid = account.pw_uid if uid is None else uid
        self.gid = account.pw_gid if gid is None else gid
        self.lock = threading.RLock()
        self.active = None
        self.previous = None
        self.running_job = None
        self.daemon = None
        self.last_check = None
        self.last_change = None
        from .browser_broker import BrowserBroker
        self.browser = BrowserBroker(self)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        (self.root / 'profiles').mkdir(exist_ok=True, mode=0o700)
        self.runtime.mkdir(parents=True, exist_ok=True, mode=0o750)
        self.registry = self.root / 'profiles.json'
        self.profiles = json.loads(self.registry.read_text()) if self.registry.exists() else {}
        self.premium = Premium(self.root, transport=self._premium_request)
        self._sync_premium()

    def _premium_request(self, operation, payload):
        # Network/crypto parsing happens without root or network capabilities.
        # The subprocess deadline also bounds DNS lookup and slow response bodies.
        request = dict(operation=operation, payload=payload, transport=self.premium.state.get('transport', {}))
        try:
            run = subprocess.run(self._unprivileged('studio.premium', isolated=False, gateway=True),
                                 input=json.dumps(request), text=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, timeout=28, env=ENV, cwd=self.code)
            result = json.loads(run.stdout)
            if run.returncode or not result.get('ok'):
                from .premium import fail, ERRORS
                fail(result.get('code') if result.get('code') in ERRORS else 'NETWORK')
            # Remember only an index into root-approved origins, never an origin
            # supplied by a subprocess or remote response. Survives restarts.
            index = result.get('gateway_index')
            transport = self.premium.state.get('transport', {})
            if type(index) is int and 0 <= index < min(6, len(transport.get('endpoints', []))):
                transport['preferred_index'] = index
                self.premium.save()
            return result['result']
        except (OSError, ValueError, subprocess.TimeoutExpired):
            from .premium import fail
            fail('NETWORK')

    def _sync_premium(self):
        current = {p['id']: p for p in self.premium.profiles()}
        for ident, old in self.profiles.items():
            if old.get('provider') == 'amnezia-premium' and ident not in current:
                old.update(enabled=False, available=False)
        for ident, item in current.items():
            item.pop('id')
            old = self.profiles.get(ident, {})
            item['enabled'] = bool(item['available'] and old.get('enabled', item['enabled']))
            item['name'] = old.get('name', item['name'])
            self.profiles[ident] = item

    def _save(self):
        private_write(self.registry, json.dumps(self.profiles))

    def _path(self, ident):
        profile_id(ident)
        path = self.root / 'profiles' / (ident + '.conf')
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError('VPN profile must be a root-owned private regular file.')
        return path

    def list_profiles(self):
        self._sync_premium()
        return [dict(id=ident, **value) for ident, value in self.profiles.items()]

    def discover_profiles(self):
        # Candidate filenames only. Never open GUI credentials or subscription keys.
        roots = (Path('/etc/amnezia/amneziawg'), Path('/etc/wireguard'))
        return [dict(source=f'{index}:{p.name}', name=p.stem) for index, root in enumerate(roots)
                if root.is_dir() for p in sorted(root.glob('*.conf'))
                if p.is_file() and not p.is_symlink() and p.stat().st_uid == 0
                and not p.stat().st_mode & 0o077][:50]

    def add(self, raw, meta):
        clean = metadata(meta)
        parsed = parse_profile(raw)
        if sum(p.get('provider') != 'amnezia-premium' for p in self.profiles.values()) >= 50:
            raise ValueError('Maximum 50 VPN profiles.')
        ident = secrets.token_hex(16)
        private_write(self.root / 'profiles' / (ident + '.conf'), raw)
        self.profiles[ident] = dict(**clean, protocol=parsed['protocol'])
        self._save()
        return dict(id=ident, **self.profiles[ident])

    def import_existing(self, source, meta):
        candidates = {x['source'] for x in self.discover_profiles()}
        if source not in candidates:
            raise ValueError('Source is not an approved discovery candidate.')
        index, name = source.split(':', 1)
        path = (Path('/etc/amnezia/amneziawg'), Path('/etc/wireguard'))[int(index)] / name
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as stream:
            return self.add(stream.read(16385), meta)

    def _unprivileged(self, module, *args, isolated=True, gateway=False):
        uid, gid = self.uid, self.gid
        if gateway:
            account = pwd.getpwnam('shodan-vpn-gateway')
            uid, gid = account.pw_uid, account.pw_gid
            if uid in (0, self.uid): raise RuntimeError('Premium gateway requires a separate unprivileged account.')
        prefix = [IP, 'netns', 'exec', NS] if isolated else []
        return prefix + [SETPRIV, '--reuid', str(uid), '--regid', str(gid),
                         '--clear-groups', '--no-new-privs', '--bounding-set=-all',
                         '/usr/bin/python3', '-s', '-m', module, *args]

    def _ns_exists(self):
        return Path('/run/netns', NS).exists()

    def _ensure_ns(self, dns):
        if not self._ns_exists():
            command([IP, 'netns', 'add', NS])
        command([IP, '-n', NS, 'link', 'set', 'lo', 'up'])
        folder = Path('/etc/netns') / NS
        folder.mkdir(mode=0o755, parents=True, exist_ok=True)
        private_write(folder / 'resolv.conf', ''.join(f'nameserver {ip}\n' for ip in dns) + 'options timeout:2 attempts:1\n')
        (folder / 'resolv.conf').chmod(0o644)
        # nss-resolve may otherwise reach host resolved through a Unix socket.
        private_write(folder / 'nsswitch.conf', 'passwd: files\ngroup: files\nshadow: files\nhosts: files dns\nnetworks: files\n')
        (folder / 'nsswitch.conf').chmod(0o644)
        # No changes whatsoever to host nftables, DNS or default route.
        rules = ('table inet studio_vpn { chain output { type filter hook output priority 0; policy drop; '
                 f'oifname "lo" accept; oifname "{IFACE}" accept; }}; }}\n')
        command([IP, 'netns', 'exec', NS, NFT, 'delete', 'table', 'inet', 'studio_vpn'], check=False)
        command([IP, 'netns', 'exec', NS, NFT, '-f', '-'], data=rules)

    def _tool(self, protocol):
        tool = AWG if protocol == 'amneziawg' else WG
        if not Path(tool).is_file() or (protocol == 'amneziawg' and not Path(GO).is_file()):
            raise RuntimeError('Required official VPN tool is not installed.')
        return tool

    def _remove_interface(self):
        if getattr(self, 'browser', None): self.browser.close()
        if self._ns_exists():
            command([IP, '-n', NS, 'link', 'del', IFACE], check=False)
        command([IP, 'link', 'del', IFACE], check=False)
        if self.daemon:
            self.daemon.terminate()
            try:
                self.daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.daemon.kill()
                self.daemon.wait()
            self.daemon = None
        self.active = None
        self.last_check = None

    def _connect(self, ident):
        started = time.monotonic()
        timings = {}
        profile_id(ident)
        if ident not in self.profiles or not self.profiles[ident]['enabled']:
            raise ValueError('VPN profile unavailable or disabled.')
        record = self.profiles[ident]
        if record.get('provider') == 'amnezia-premium':
            # A timed-out gateway request may have changed this device remotely.
            self.last_check = None
            raw = self.premium.configuration(record['location'])
            self._sync_premium()
            self._save()
            parsed = parse_profile(raw)
        else:
            parsed = parse_profile(self._path(ident).read_text())
        timings['configuration_ms'] = round((time.monotonic() - started) * 1000)
        setup_started = time.monotonic()
        tool = self._tool(parsed['protocol'])
        # Reusing an active host key can make the peer roam away from SSH's VPN.
        # Compare public keys only, without exposing either key in responses.
        private = next(line.split('=', 1)[1].strip() for line in parsed['config'].splitlines() if line.startswith('PrivateKey'))
        public = command([tool, 'pubkey'], data=private + '\n').strip()
        active_keys = command([tool, 'show', 'all', 'public-key']).splitlines()
        if any(len(row.split()) == 2 and row.split()[0] != IFACE and row.split()[1] == public for row in active_keys):
            raise RuntimeError('Profile key is already used by a host tunnel; import an independent profile.')
        self._remove_interface()
        self._ensure_ns(parsed['dns'])
        try:
            if parsed['protocol'] == 'amneziawg':
                self.daemon = subprocess.Popen([GO, '-f', IFACE], env=ENV,
                                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                               stderr=subprocess.DEVNULL)
                for _ in range(50):
                    if Path('/run/amneziawg', IFACE + '.sock').exists():
                        break
                    if self.daemon.poll() is not None:
                        raise RuntimeError('AmneziaWG daemon could not start.')
                    time.sleep(.1)
                else:
                    raise RuntimeError('AmneziaWG control socket not ready.')
            else:
                command([IP, 'link', 'add', IFACE, 'type', 'wireguard'])
            command([tool, 'setconf', IFACE, '/dev/stdin'], data=parsed['config'])
            command([IP, 'link', 'set', IFACE, 'netns', NS])
            for address in parsed['addresses']:
                command([IP, '-n', NS, 'address', 'add', address, 'dev', IFACE])
            command([IP, '-n', NS, 'link', 'set', IFACE, 'mtu', str(parsed['mtu']), 'up'])
            for version in {4 if ':' not in addr else 6 for addr in parsed['addresses']}:
                command([IP, '-n', NS, f'-{version}', 'route', 'add', 'default', 'dev', IFACE])
            self.active = ident
            self.last_change = time.time()
            timings['interface_ms'] = round((time.monotonic() - setup_started) * 1000)
            verify_started = time.monotonic()
            report = self._verify_connection()
            timings['verification_ms'] = round((time.monotonic() - verify_started) * 1000)
            timings['total_ms'] = round((time.monotonic() - started) * 1000)
            report['connection_timings'] = timings
            return report
        except Exception:
            failed_check = self.last_check
            self._remove_interface()
            self.last_check = failed_check
            raise

    def _verify_connection(self):
        # Initial AWG handshakes may outlast the first DNS request. Retry the
        # same tunnel, never allocate another Premium configuration or identity.
        for attempt in range(3):
            if attempt: time.sleep(attempt)
            report = self.health_check()
            if report['healthy']: return report
        checks = ', '.join(k + '=' + ('ok' if report.get(k) else 'failed') for k in
                           ('dns', 'tcp', 'tls', 'http', 'handshake', 'route_verified', 'leak_protection'))
        prefix = '[VPN_DESTINATION] ' if report.get('tunnel_healthy') else ''
        raise RuntimeError(prefix + 'Tunnel verification failed; no worker was started. ' + checks)

    def switch_profile(self, ident):
        old = self.active
        if old == ident:
            check = self.launch_check()
            if check['healthy']:
                return check
            if getattr(self,'browser',None) and self.browser.status()['running']:
                raise RuntimeError('أغلق جلسة المتصفح قبل إعادة إنشاء النفق المتعطل.')
        try:
            result = self._connect(ident)
            if old != ident:
                self.previous = old
            return result
        except Exception:
            if old and old != ident:
                with contextlib.suppress(Exception):
                    self._connect(old)
            raise

    connect = switch_profile

    def disconnect(self):
        old = self.active
        self._remove_interface()
        if old:
            self.previous = old
        return self.get_status()

    def restore_previous_state(self):
        if not self.previous:
            raise ValueError('No previous isolated VPN profile is available.')
        return self.switch_profile(self.previous)

    def _isolation(self):
        if not self._ns_exists():
            return dict(interface_up=False, route_verified=False, leak_protection=False)
        try:
            links = json.loads(command([IP, '-n', NS, '-j', 'link', 'show']))
            names = {x['ifname'] for x in links}
            up = any(x['ifname'] == IFACE and 'UP' in x['flags'] for x in links)
            routes = json.loads(command([IP, '-n', NS, '-j', 'route', 'show']))
            routes6 = json.loads(command([IP, '-n', NS, '-j', '-6', 'route', 'show']))
            routes_ok = any(x.get('dst') == 'default' and x.get('dev') == IFACE for x in routes)
            safe_routes = all(x.get('dev') in {IFACE, 'lo'} for x in routes + routes6)
            firewall = json.loads(command([IP, 'netns', 'exec', NS, NFT, '-j', 'list', 'table', 'inet', 'studio_vpn']))
            drop = any(x.get('chain', {}).get('policy') == 'drop' for x in firewall['nftables'])
            return dict(interface_up=up, route_verified=up and routes_ok and safe_routes,
                        leak_protection=names <= {'lo', IFACE} and safe_routes and drop)
        except (RuntimeError, ValueError, KeyError):
            return dict(interface_up=False, route_verified=False, leak_protection=False)

    def get_status(self, busy=False):
        isolation = dict(interface_up=False, route_verified=False, leak_protection=False) if busy else self._isolation()
        verified = bool(self.last_check and self.last_check['healthy']
                        and time.time() - self.last_check.get('checked_at', 0) < 60 and isolation['interface_up']
                        and isolation['route_verified'] and isolation['leak_protection'])
        return dict(active_profile=self.active, previous_profile=self.previous, interface=IFACE,
                    namespace=NS, running_job=self.running_job, last_change=self.last_change,
                    capabilities={"amneziawg": Path(AWG).is_file() and Path(GO).is_file(), "wireguard": Path(WG).is_file(), "gui_country_automation": False,
                                  "premium_subscription": True}, premium=self.premium.status(),
                    browser=self.browser.status() if getattr(self, 'browser', None) else {'running':False},
                    verified=verified, busy=busy, last_check=self.last_check, **isolation)

    def health_check(self, scope='worker', *, source_check=False):
        if scope not in {'host', 'worker'}:
            raise ValueError('Invalid diagnostic scope.')
        isolated = scope == 'worker'
        isolation = self._isolation() if isolated else {}
        if isolated and (not self.active or not isolation['route_verified'] or not isolation['leak_protection']):
            result = dict(scope=scope, healthy=False, error='VPN_NOT_READY', egress_ip=None, **isolation)
        else:
            try:
                run = subprocess.run(self._unprivileged('studio.vpn_probe', *(['--source'] if source_check else []), isolated=isolated),
                                     capture_output=True, text=True, timeout=22, env=ENV, cwd=self.code)
                result = json.loads(run.stdout) if run.returncode == 0 else {'healthy': False, 'error': 'PROBE_FAILED'}
            except (subprocess.TimeoutExpired, OSError, ValueError):
                result = {'healthy': False, 'error': 'PROBE_TIMEOUT'}
            result.update(scope=scope, **isolation)
            if isolated:
                tool = self._tool(self.profiles[self.active]['protocol'])
                prefix = [] if tool == AWG else [IP, 'netns', 'exec', NS]
                try:
                    output = command(prefix + [tool, 'show', IFACE, 'latest-handshakes'])
                    ages = [time.time() - int(row.split()[1]) for row in output.splitlines() if len(row.split()) == 2]
                    result['handshake'] = bool(ages) and all(0 <= age < 180 for age in ages)
                except (RuntimeError, ValueError):
                    result['handshake'] = False
                result['tunnel_healthy'] = bool(result.get('http') and result.get('egress_ip')
                                                and result['handshake'] and isolation['route_verified']
                                                and isolation['leak_protection'])
                result['healthy'] = bool(result.get('healthy') and result['tunnel_healthy'])
        result['checked_at'] = time.time()
        if isolated:
            self.last_check = result
        return result

    verify_tunnel = health_check

    def launch_check(self):
        """Reuse a just-completed probe, while rechecking the actual isolation.

        A worker launch immediately follows prepare/connect. Repeating both TLS
        requests adds seconds without adding leak protection. Cached results are
        usable for ten seconds, for this tunnel only; removal clears last_check.
        """
        check = self.last_check
        if self.active and check and check.get('healthy') and 0 <= time.time() - check.get('checked_at', 0) < 10:
            isolation = self._isolation()
            if all(isolation.get(k) for k in ('interface_up', 'route_verified', 'leak_protection')):
                return dict(check, **isolation)
        return self.health_check()

    def get_egress_ip(self):
        return self.health_check().get('egress_ip')

    def dispatch(self, request):
        op = request.get('op')
        allowed = {'profiles': set(), 'discover': set(), 'status': set(), 'health': {'scope'}, 'diagnostics': {'scope'},
                   'browser': {'job_id', 'input'}, 'browser_fetch': {'job_id', 'url'},
                   'import': {'config', 'metadata'}, 'import_existing': {'source', 'metadata'},
                   'update': {'profile_id', 'metadata'}, 'connect': {'profile_id'},
                   'disconnect': set(), 'restore': set(), 'premium_refresh': set(), 'premium_enroll': {'key'}}
        if op not in allowed or set(request) - ({'op'} | allowed[op]):
            raise ValueError('Operation is not allowed.')
        if op in {'profiles', 'status'}:
            if not self.lock.acquire(blocking=False):
                # The monitor holds the lock while probing DNS/TLS. Polling must
                # remain responsive, and must not claim stale health as verified.
                return self.get_status(busy=True) if op == 'status' else [dict(id=k, **v) for k,v in list(self.profiles.items())]
            try:
                return self.get_status() if op == 'status' else self.list_profiles()
            finally:
                self.lock.release()
        with self.lock:
            if op == 'browser': return self.browser.action(request)
            if op == 'browser_fetch': return self.browser.fetch(request['job_id'],request['url'])
            if op in {'connect','disconnect','restore','update','premium_refresh','premium_enroll'} and getattr(self,'browser',None) and self.browser.status()['running']:
                if op != 'connect' or request.get('profile_id') != self.active:
                    raise RuntimeError('أغلق جلسة المتصفح قبل تغيير اتصال VPN أو إعداداته.')
            if op in {'connect', 'disconnect', 'restore', 'update', 'premium_refresh', 'premium_enroll'} and self.running_job:
                raise RuntimeError('Pause the active worker and wait for its checkpoint before changing VPN.')
            if op == 'profiles': return self.list_profiles()
            if op == 'discover': return self.discover_profiles()
            if op == 'status': return self.get_status()
            if op in {'premium_refresh', 'premium_enroll'}:
                result = self.premium.enroll(request['key']) if op == 'premium_enroll' else self.premium.refresh()
                self._sync_premium()
                self._save()
                return result
            if op in {'health', 'diagnostics'}:
                return self.health_check(request.get('scope', 'worker'), source_check=op == 'diagnostics')
            if op == 'import': return self.add(request['config'], request['metadata'])
            if op == 'import_existing': return self.import_existing(request['source'], request['metadata'])
            if op == 'update':
                ident = profile_id(request['profile_id'])
                if ident not in self.profiles: raise ValueError('Unknown profile.')
                clean = metadata(request['metadata'])
                if self.profiles[ident].get('provider') == 'amnezia-premium':
                    if clean['country'] != self.profiles[ident]['country']:
                        raise ValueError('Premium country is determined by the subscription catalog.')
                    if clean['enabled'] and not self.profiles[ident].get('available'):
                        raise ValueError('Premium location does not support the installed AWG adapter.')
                if ident == self.active and not clean['enabled']: self.disconnect()
                self.profiles[ident].update(clean)
                self._save()
                return dict(id=ident, **self.profiles[ident])
            if op == 'connect': return self.connect(request['profile_id'])
            if op == 'disconnect': return self.disconnect()
            if op == 'restore': return self.restore_previous_state()

    def run_worker(self, request, sock):
        if set(request) != {'op', 'job_id', 'payload'}:
            raise ValueError('Invalid worker request.')
        ident = profile_id(request['job_id'])
        payload = request['payload']
        with self.lock:
            if self.running_job:
                raise RuntimeError('A VPN worker already owns the tunnel.')
            if self.browser.status()['running'] and self.browser.job != ident:
                raise RuntimeError('Another browser job owns the tunnel.')
            if payload['job'].get('browser_session_enabled') and (not self.browser.status()['running'] or self.browser.job != ident):
                raise RuntimeError('[BROWSER_SESSION] افتح جلسة المتصفح وتحقق من الصفحة قبل الاستكمال.')
            if payload['job']['id'] != ident or payload['job'].get('active_vpn_profile') != self.active or not self.active:
                raise ValueError('Worker profile does not match the verified tunnel.')
            # Revalidate at launch, not merely at the earlier browser action.
            if not self.launch_check()['healthy']:
                raise RuntimeError('Tunnel health verification failed before worker launch.')
            path = self.data / 'jobs' / ident
            if path.is_symlink() or not path.is_dir():
                raise ValueError('Invalid worker directory.')
            proc = subprocess.Popen(self._unprivileged('studio.worker', '--job-dir', str(path)),
                                    cwd=self.code, env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, start_new_session=True)
            self.running_job = ident
        try:
            proc.stdin.write(json.dumps(payload).encode())
            proc.stdin.close()
            with selectors.DefaultSelector() as sel:
                sel.register(proc.stdout, selectors.EVENT_READ)
                sel.register(sock, selectors.EVENT_READ)
                while True:
                    for key, _ in sel.select(1):
                        if key.fileobj is sock:
                            # Client disconnected (including bridge SIGTERM).
                            if not sock.recv(1): return
                            raise ValueError('Unexpected worker client input.')
                        chunk = os.read(proc.stdout.fileno(), 65536)
                        if not chunk: return
                        sock.sendall(chunk)
                    if proc.poll() is not None:
                        # Drain remaining structured events before releasing lease.
                        rest = proc.stdout.read()
                        if rest: sock.sendall(rest)
                        return
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
                try: proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
            proc.stdout.close()
            with self.lock: self.running_job = None


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        broker = self.server.broker
        uid = struct.unpack('3i', self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
        if uid not in (0, broker.uid):
            return
        self.request.settimeout(10)
        raw = self.rfile.readline(1024 * 1024 + 1)
        request = {}
        try:
            if len(raw) > 1024 * 1024: raise ValueError('Request too large.')
            request = json.loads(raw)
            if not isinstance(request, dict): raise ValueError('Invalid request.')
            self.request.settimeout(240)
            if request.get('op') == 'run':
                broker.run_worker(request, self.request)
                return
            response = {'ok': True, 'result': broker.dispatch(request)}
        except Exception as exc:
            # Only explicitly raised static messages; KeyError/OSError may contain secrets.
            message = str(exc) if type(exc) in (ValueError, RuntimeError) else 'VPN operation failed.'
            if request.get('op') == 'run':
                response = dict(kind='final', status='waiting_input', input_reason='network_error', error='[VPN_HELPER] ' + message)
            else: response = {'ok': False, 'error': message}
        with contextlib.suppress(OSError):
            self.wfile.write(json.dumps(response).encode() + b'\n')


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    block_on_close = False


def main():
    if os.getuid() != 0: raise SystemExit('Helper requires its dedicated systemd unit.')
    os.umask(0o077)
    broker = Broker()
    socket_path = broker.runtime / 'control.sock'
    socket_path.unlink(missing_ok=True)
    # A restarted helper has no validated tunnel. Remove only owned resources.
    broker._remove_interface()
    command([IP, 'netns', 'del', NS], check=False)
    if Path('/run/netns', NS).exists():
        raise SystemExit('Stale VPN namespace cannot be safely reclaimed.')
    with Server(str(socket_path), Handler) as server:
        server.broker = broker
        os.chown(socket_path, 0, broker.gid)
        socket_path.chmod(0o660)
        os.chown(broker.runtime, 0, broker.gid)
        broker.runtime.chmod(0o750)
        def stop(*_):
            threading.Thread(target=server.shutdown, daemon=True).start()
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        monitor_stop = threading.Event()
        def monitor():
            while not monitor_stop.wait(30):
                with broker.lock:
                    if broker.browser.status()['running'] and not broker.running_job and time.monotonic()-broker.browser.last_used>1800:
                        broker.browser.close()
                    if broker.active and (not broker.last_check or time.time() - broker.last_check.get('checked_at', 0) >= 25):
                        with contextlib.suppress(Exception): broker.health_check()
        threading.Thread(target=monitor, daemon=True).start()
        try: server.serve_forever(.2)
        finally:
            monitor_stop.set()
            broker._remove_interface()
            command([IP, 'netns', 'del', NS], check=False)
            shutil.rmtree(Path('/etc/netns') / NS, ignore_errors=True)
            socket_path.unlink(missing_ok=True)


if __name__ == '__main__': main()
