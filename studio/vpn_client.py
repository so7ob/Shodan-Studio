"""Unprivileged RPC/worker bridge. No sudo or capability is granted to web/worker."""
import argparse
import json
import os
import socket
import sys

SOCKET = '/run/shodan-studio-vpn/control.sock'


def connect(path=SOCKET):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(240)  # Bounded Premium configuration + 3 probes + restoration.
    try:
        sock.connect(path)
        return sock
    except OSError:
        sock.close()
        raise RuntimeError('خدمة VPN المساعدة غير متاحة؛ الاتصال المحمي متوقف بأمان.') from None


def rpc(operation, *, socket_path=SOCKET, **fields):
    with connect(socket_path) as sock:
        sock.sendall(json.dumps({'op': operation, **fields}).encode() + b'\n')
        with sock.makefile('rb') as stream:
            body = stream.readline(1024 * 1024 + 1)
        if len(body) > 1024 * 1024:
            raise RuntimeError('استجابة VPN أكبر من المسموح.')
        try:
            response = json.loads(body)
        except ValueError:
            raise RuntimeError('انقطعت خدمة VPN؛ لم يثبت نجاح العملية.') from None
        if not response.get('ok'):
            raise RuntimeError(response.get('error', 'فشلت عملية VPN.'))
        return response['result']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--job-id', required=True)
    args = parser.parse_args()
    from .vpn_config import profile_id
    profile_id(args.job_id)
    try:
        data = sys.stdin.buffer.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ValueError('Worker input too large.')
        payload = json.loads(data)
        with connect() as sock:
            sock.sendall(json.dumps({'op': 'run', 'job_id': args.job_id, 'payload': payload}).encode() + b'\n')
            sock.settimeout(None)
            with sock.makefile('rb') as stream:
                for line in stream:
                    sys.stdout.buffer.write(line)
                    sys.stdout.buffer.flush()
        return 0
    except Exception:
        print(json.dumps({'kind': 'final', 'status': 'waiting_input', 'input_reason': 'network_error',
                          'error': '[VPN_HELPER] تعذر بدء العامل المعزول؛ لم يستخدم الاتصال المباشر.'}))
        return 75


if __name__ == '__main__':
    raise SystemExit(main())
