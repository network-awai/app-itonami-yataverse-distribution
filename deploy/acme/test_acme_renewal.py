"""AWAI-465 renewer/receiver checks.

Receiver cases use throwaway OpenSSL chains. The renewer case runs a real
lego against a local Pebble ACME server and pebble-challtestsrv DNS. Set
PEBBLE_BIN_DIR (pebble, pebble-challtestsrv), PEBBLE_MINICA (pebble's test
TLS root) and LEGO_TEST_BIN; it is skipped otherwise. These are local
diagnostics, not a production renewal and not a native qualification gate.

    cd deploy/acme && PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v test_acme_renewal
"""
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import unittest
import urllib.request

HERE = Path(__file__).resolve().parent
DOMAIN = 'ipfs.yataverse.com'
SENTINEL = 'sentinel-token-must-never-appear-0123456789'


def run(*args, **kw):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kw)


class Chain:
    """root -> intermediate -> leaf, written under d."""

    def __init__(self, d, name, san=DOMAIN, days=90):
        self.d = Path(d) / name
        self.d.mkdir()
        p = self.d
        run('openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
            '-nodes', '-keyout', p / 'root.key', '-out', p / 'root.pem', '-days', '3650',
            '-subj', '/CN=test root ' + name,
            '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
        self.issue('int', '/CN=test int ' + name, 'root',
                   'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n', 3650)
        self.new_leaf(san, days)

    def issue(self, out, subj, ca, ext, days):
        p = self.d
        run('openssl', 'req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
            '-keyout', p / (out + '.key'), '-out', p / (out + '.csr'), '-subj', subj)
        (p / (out + '.ext')).write_text(ext)
        run('openssl', 'x509', '-req', '-in', p / (out + '.csr'), '-CA', p / (ca + '.pem'),
            '-CAkey', p / (ca + '.key'), '-CAcreateserial', '-out', p / (out + '.pem'),
            '-days', str(days), '-extfile', p / (out + '.ext'))

    def new_leaf(self, san=DOMAIN, days=90):
        self.issue('leaf', '/CN=' + DOMAIN, 'int',
                   'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' % san, days)

    def bundle(self, key=None):
        p = self.d
        return ((p / 'leaf.pem').read_bytes() + (p / 'int.pem').read_bytes()
                + Path(key or p / 'leaf.key').read_bytes())


class Receiver(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.chain = Chain(self.root, 'a')
        self.live = self.root / 'live'
        self.applied = self.root / 'applied'
        self.apply = self.root / 'apply.sh'
        self.apply.write_text('#!/bin/sh\necho x >> %s\n[ ! -e %s/fail ]\n' % (self.applied, self.root))
        self.apply.chmod(0o755)
        self.conf = self.root / 'receive.conf'
        self.conf.write_text('DOMAIN=%s\nLIVE_DIR=%s\nAPPLY_CMD=%s\nCHAIN_CA_production=%s\n'
                             'CHAIN_CA_staging=none\nMIN_DAYS=7\n'
                             % (DOMAIN, self.live, self.apply, self.chain.d / 'root.pem'))
        self.conf.chmod(0o644)

    def tearDown(self):
        self.tmp.cleanup()

    def recv(self, command, data=b''):
        env = {'PATH': os.environ['PATH'], 'SSH_ORIGINAL_COMMAND': command,
               'ACME_RECEIVE_CONF': str(self.conf), 'ACME_TEST_ALLOW_NONROOT': '1'}
        r = subprocess.run(['sh', HERE / 'receive.sh'], input=data, env=env, capture_output=True)
        return r.returncode, r.stdout.decode().strip()

    def link(self, slot='production'):
        p = self.live / slot / 'current.pem'
        return os.readlink(p) if p.is_symlink() else None

    def applies(self):
        return len(self.applied.read_text().splitlines()) if self.applied.exists() else 0

    def test_install_unchanged_and_status(self):
        rc, out = self.recv('install production', self.chain.bundle())
        self.assertEqual(rc, 0, out)
        self.assertRegex(out, r'^ok installed [0-9a-f]{64}$')
        cid = out.split()[-1]
        self.assertEqual(self.link(), 'releases/%s/bundle.pem' % cid)
        self.assertEqual(oct((self.live / 'production' / 'current.pem').stat().st_mode & 0o777), '0o600')
        self.assertEqual(self.applies(), 1)
        self.assertEqual(self.recv('install production', self.chain.bundle()), (0, 'ok unchanged ' + cid))
        self.assertEqual(self.applies(), 1)
        rc, out = self.recv('status production')
        self.assertTrue(out.startswith('ok status ' + cid + ' '), out)

    def test_rejections_leave_installed_cert(self):
        self.assertEqual(self.recv('install production', self.chain.bundle())[0], 0)
        before = self.link()
        other = Chain(self.root, 'b')
        wrong_san = Chain(self.root, 'c', san='other.yataverse.com')
        mismatched = self.chain.bundle(key=other.d / 'leaf.key')
        Chain.new_leaf(self.chain, days=3)
        short = self.chain.bundle()
        cases = {
            'chain-untrusted': other.bundle(),
            'san-mismatch': wrong_san.bundle(),
            'key-mismatch': mismatched,
            'expires-within-7d': short,
            'oversize': b'x' * 70000,
            'bundle-shape': b'not pem',
        }
        for reason, data in cases.items():
            with self.subTest(reason):
                rc, out = self.recv('install production', data)
                self.assertEqual((rc, out), (1, 'error ' + reason))
                self.assertEqual(self.link(), before)
        self.assertEqual(self.applies(), 1)

    def test_no_downgrade(self):
        Chain.new_leaf(self.chain, days=60)
        older = self.chain.bundle()
        Chain.new_leaf(self.chain, days=90)
        self.assertEqual(self.recv('install production', self.chain.bundle())[0], 0)
        self.assertEqual(self.recv('install production', older), (1, 'error older-than-installed'))

    def test_apply_failure_rolls_back(self):
        rc, first = self.recv('install production', self.chain.bundle())
        before = self.link()
        (self.root / 'fail').touch()
        Chain.new_leaf(self.chain, days=91)
        self.assertEqual(self.recv('install production', self.chain.bundle()),
                         (1, 'error apply-failed-rolled-back'))
        self.assertEqual(self.link(), before)
        self.assertEqual(len(list((self.live / 'production' / 'releases').iterdir())), 1)

    def test_staging_slot_is_isolated_and_not_applied(self):
        staging = Chain(self.root, 's')
        rc, out = self.recv('install staging', staging.bundle())
        self.assertEqual(rc, 0, out)
        self.assertIsNone(self.link('production'))
        self.assertEqual(self.applies(), 0)

    def test_only_two_word_commands(self):
        for cmd in ['', 'install', 'install production x', 'install prod',
                    'install production;id', 'status *', 'sh -c id', 'install ../x']:
            with self.subTest(cmd):
                self.assertEqual(self.recv(cmd, self.chain.bundle()), (1, 'error usage'))
        self.assertIsNone(self.link())

    def test_writable_config_is_refused(self):
        self.conf.chmod(0o666)
        self.assertEqual(self.recv('status production'), (1, 'error config'))


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


@unittest.skipUnless(os.environ.get('PEBBLE_BIN_DIR') and os.environ.get('LEGO_TEST_BIN')
                     and os.environ.get('PEBBLE_MINICA'), 'Pebble/lego not provided')
class RenewerWithPebble(unittest.TestCase):
    """Real ACME issuance and renewal through renew.sh, pushed to two receivers."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        r = self.root = Path(self.tmp.name)
        bins = Path(os.environ['PEBBLE_BIN_DIR'])
        acme, mgmt, dns, chall = free_port(), free_port(), free_port(), free_port()
        minica = os.environ['PEBBLE_MINICA']
        certs = Path(minica).parent / 'localhost'
        (r / 'pebble.json').write_text(json.dumps({'pebble': {
            'listenAddress': '127.0.0.1:%d' % acme, 'managementListenAddress': '127.0.0.1:%d' % mgmt,
            'certificate': str(certs / 'cert.pem'), 'privateKey': str(certs / 'key.pem'),
            'httpPort': free_port(), 'tlsPort': free_port(), 'externalAccountBindingRequired': False,
            'retryAfter': {'authz': 1, 'order': 1},
            'profiles': {'default': {'description': 'test', 'validityPeriod': 7776000}}}}))
        self.procs = [
            subprocess.Popen([bins / 'pebble-challtestsrv', '-dns01', '127.0.0.1:%d' % dns,
                              '-http01', '', '-https01', '', '-tlsalpn01', '', '-doh', '',
                              '-management', '127.0.0.1:%d' % chall],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
            subprocess.Popen([bins / 'pebble', '-config', r / 'pebble.json',
                              '-dnsserver', '127.0.0.1:%d' % dns],
                             env={**os.environ, 'PEBBLE_VA_NOSLEEP': '1', 'PEBBLE_WFE_NONCEREJECT': '0'},
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)]
        self.dns, self.acme = dns, acme
        ctx = ssl.create_default_context(cafile=minica)
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT   # Pebble's test root has no AKI
        for _ in range(50):
            try:
                urllib.request.urlopen('https://127.0.0.1:%d/dir' % acme, context=ctx, timeout=1)
                break
            except OSError:
                time.sleep(.2)
        roots = urllib.request.urlopen('https://127.0.0.1:%d/roots/0' % mgmt, context=ctx).read()
        (r / 'pebble-root.pem').write_bytes(roots)

        lego = r / 'lego'
        shutil.copy(os.environ['LEGO_TEST_BIN'], lego)
        lego.chmod(0o755)
        exec_hook = r / 'dns-exec.sh'
        exec_hook.write_text(
            '#!/bin/sh\ncase "$1" in\n'
            'present) curl -sS -d "{\\"host\\":\\"$2\\",\\"value\\":\\"$3\\"}" http://127.0.0.1:%d/set-txt ;;\n'
            'cleanup) curl -sS -d "{\\"host\\":\\"$2\\"}" http://127.0.0.1:%d/clear-txt ;;\nesac\n' % (chall, chall))
        exec_hook.chmod(0o755)
        self.cred = r / 'cred'
        self.cred.mkdir(mode=0o700)
        (self.cred / 'dns.env').write_text('EXEC_PATH=%s\nCF_DNS_API_TOKEN=%s\n' % (exec_hook, SENTINEL))
        (self.cred / 'push_key').write_text('placeholder; the fake ssh ignores it\n')
        for f in self.cred.iterdir():
            f.chmod(0o600)

        # Fake ssh: "down@b" is unreachable until r/b-online exists; every other
        # destination runs receive.sh locally with that target's own config.
        self.targets = {}
        for name in ['a', 'b']:
            live = r / ('live-' + name)
            conf = r / ('receive-%s.conf' % name)
            conf.write_text('DOMAIN=%s\nLIVE_DIR=%s\nCHAIN_CA_production=%s\nCHAIN_CA_staging=none\n'
                            'APPLY_CMD=/usr/bin/true\n' % (DOMAIN, live, r / 'pebble-root.pem'))
            conf.chmod(0o644)
            self.targets[name] = live
        ssh = r / 'ssh'
        ssh.write_text('#!/bin/sh\nfor a; do dest=$cmd; cmd=$a; done\n'
                       'case "$dest" in down@b) [ -e %s/b-online ] || exit 255; t=b ;; recv@a) t=a ;; *) exit 255 ;; esac\n'
                       'SSH_ORIGINAL_COMMAND=$cmd ACME_RECEIVE_CONF=%s/receive-$t.conf exec sh %s/receive.sh\n'
                       % (r, r, HERE))
        ssh.chmod(0o755)
        self.state = r / 'state'
        self.state.mkdir()
        self.conf = r / 'renew.conf'
        self.write_conf(30)

    def write_conf(self, renew_days):
        lego = self.root / 'lego'
        sha = subprocess.run(['sha256sum', lego], capture_output=True, text=True).stdout.split()[0]
        self.conf.write_text('\n'.join([
            'DOMAIN=' + DOMAIN, 'LEGO_BIN=%s' % lego,
            'LEGO_SHA256=' + sha, 'STATE_DIR=%s' % self.state, 'DNS_PROVIDER=exec',
            'DNS_RESOLVERS=127.0.0.1:%d' % self.dns, 'DNS_DISABLE_ANS=1',
            'RENEW_DAYS=%d' % renew_days, 'ALERT_DAYS=21',
            'SERVER_production=https://%s/dir' % '127.0.0.1:%d' % self.acme, 'SERVER_staging=https://%s/dir' % '127.0.0.1:%d' % self.acme,
            'CHAIN_CA_production=%s' % (self.root / 'pebble-root.pem'), 'CHAIN_CA_staging=none',
            'LEGO_CA_CERTIFICATES=%s' % os.environ['PEBBLE_MINICA'],
            'SSH_BIN=%s' % (self.root / 'ssh'), 'KNOWN_HOSTS=/dev/null',
            'TARGETS="a=recv@a b=down@b"', '']))
        self.conf.chmod(0o644)

    def tearDown(self):
        for p in self.procs:
            p.terminate()
            p.wait()
        self.tmp.cleanup()

    def renew(self, profile='production', **env):
        e = {'PATH': os.environ['PATH'], 'ACME_CONF': str(self.conf), 'ACME_TEST_ALLOW_NONROOT': '1',
             'CREDENTIALS_DIRECTORY': str(self.cred), **env}
        r = subprocess.run(['sh', HERE / 'renew.sh', profile], env=e, capture_output=True, text=True, timeout=180)
        status = self.state / ('status-%s.json' % profile)
        doc = json.loads(status.read_text()) if status.exists() else None
        return r.returncode, doc, r.stdout + r.stderr

    def installed(self, name, slot='production'):
        p = self.targets[name] / slot / 'current.pem'
        return os.readlink(p).split('/')[1] if p.is_symlink() else None

    def test_issue_push_retry_renew(self):
        rc, doc, log = self.renew()
        self.assertEqual(rc, 75, log)
        self.assertEqual(doc['result'], 'target-behind')
        self.assertTrue(doc['renewed'])
        self.assertEqual(doc['chain'], 'chain=verified')
        first = doc['cert_sha256']
        self.assertEqual([(t['name'], t['result']) for t in doc['targets']],
                         [('a', 'installed'), ('b', 'unreachable')])
        self.assertEqual(self.installed('a'), first)
        self.assertIsNone(self.installed('b'))

        (self.root / 'b-online').touch()
        rc, doc, log = self.renew()
        self.assertEqual(rc, 0, log)
        self.assertFalse(doc['renewed'])
        self.assertEqual([t['result'] for t in doc['targets']], ['unchanged', 'installed'])
        self.assertEqual(self.installed('b'), first)

        self.write_conf(95)      # 90-day Pebble cert is now due
        rc, doc, log = self.renew()
        self.assertEqual(rc, 0, log)
        self.assertTrue(doc['renewed'])
        self.assertNotEqual(doc['cert_sha256'], first)
        self.assertEqual({self.installed('a'), self.installed('b')}, {doc['cert_sha256']})

        for f in [*self.state.rglob('status-*.json')]:
            self.assertNotIn(SENTINEL, f.read_text())
        self.assertNotIn(SENTINEL, log)

    def test_staging_profile_uses_its_own_store_and_slot(self):
        (self.root / 'b-online').touch()
        rc, doc, log = self.renew('staging')
        self.assertEqual(rc, 0, log)
        self.assertEqual(doc['chain'], 'chain=unverified')
        self.assertTrue((self.state / 'staging' / 'certificates').is_dir())
        self.assertFalse((self.state / 'production').exists())
        self.assertIsNotNone(self.installed('a', 'staging'))
        self.assertIsNone(self.installed('a', 'production'))

    def test_preconditions_fail_closed_before_lego(self):
        bad = self.conf.read_text().replace('LEGO_SHA256=', 'LEGO_SHA256=0')
        self.conf.write_text(bad)
        rc, doc, log = self.renew()
        self.assertEqual((rc, doc), (1, None))
        self.assertIn('lego-digest', log)
        self.write_conf(30)
        (self.cred / 'dns.env').chmod(0o644)
        rc, doc, log = self.renew()
        self.assertEqual((rc, doc), (1, None))
        self.assertIn('dns-credential', log)
        self.assertFalse((self.state / 'production').exists())


if __name__ == '__main__':
    unittest.main()
