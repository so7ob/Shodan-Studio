"""Fixed execution spaces. No request may choose a filesystem path or namespace."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Space:
    kind: str
    namespace: str
    interface: str
    config: str
    runtime: str
    browser: str

    @property
    def socket(self):
        return self.runtime + '/control.sock'


SPACES = {
    'extraction': Space('extraction', 'ssvpn-worker', 'ssvpn0', '/etc/shodan-studio/vpn',
                        '/run/shodan-studio-vpn', '/var/lib/shodan-studio-browser'),
    'enrichment': Space('enrichment', 'ssvpn-enrichment', 'ssenrich0', '/etc/shodan-studio/vpn-enrichment',
                        '/run/shodan-studio-enrichment-vpn', '/var/lib/shodan-studio-enrichment-browser'),
}


def space(kind='extraction'):
    if kind not in SPACES:
        raise ValueError('مساحة تنفيذ غير صالحة.')
    return SPACES[kind]
