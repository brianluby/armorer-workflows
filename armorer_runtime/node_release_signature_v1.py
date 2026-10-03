"""Offline native qualification of public Node checksums; never production authority.

The fixed upstream fixture and system gpgv are qualification inputs, not an
approved production root/tool catalog. No credential, caller command, keyserver,
upstream script or Node archive execution enters this path. Existing producer
launchers continue to report upstream signature authentication as incomplete.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time

from .common import Failure, require
from .producer_launcher_v1 import NODE_PINS, VERSION

ROOT = Path(__file__).resolve().parents[1] / 'tests/fixtures/node-release-signature-v1'
FINGERPRINT = '5BE8A3F6C8A5C01D106C0AD820B1A390B168D356'
EXPECTED = {
    'node-release-keys.kbx': (95960, '610b8d249da3d5733f5a128def2dd0294dbbf5b5713e6ca2529db8db419dee00'),
    'signer-public-key.asc': (924, '5115095e2f8010c75da052ecb1cfb3af630e084f0f8daa93a863557b01b0f90a'),
    'SHASUMS256.txt': (3171, 'f410428039e2c922a14058df067a4482691c9304a5c01a75847f9f3f2d3307f6'),
    'SHASUMS256.txt.asc': (3449, 'dd0fe71660e64f4dc01342664835509c84679d8a87ab4d76cc2f15fdda82ea3e'),
    'SHASUMS256.txt.sig': (119, '865f22b026e4080554e10d247553fd770573893dac8fc7affc7d58b72de35a89'),
}
MAX_BYTES = 65536
MAX_SECONDS = 30


def _read(path, size):
    """Read one bounded regular no-follow file without executing or extracting public data."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        require(stat.S_ISREG(metadata.st_mode) and 0 < metadata.st_size <= size,
                'node signature input type or size unsupported')
        data = stream.read(size + 1)
    require(0 < len(data) <= size, 'node signature input exceeded bound')
    return data


def fixture_bytes():
    """Authenticate exact inert fixture bytes against immutable qualification source expectations."""
    result = {}
    for name, (size, digest) in EXPECTED.items():
        data = _read(ROOT / name, size)
        require(len(data) == size and hashlib.sha256(data).hexdigest() == digest,
                'node signature fixture substitution')
        result[name] = data
    return result


def selected_archives(manifest):
    """Bind each existing native Node archive pin to a unique checksum entry without adopting other platforms."""
    require(type(manifest) is bytes and 0 < len(manifest) <= MAX_BYTES,
            'node checksum manifest bound')
    try:
        text = manifest.decode('ascii')
    except UnicodeDecodeError as error:
        raise Failure('node checksum manifest encoding unsupported') from error
    rows = {}
    for line in text.splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_.\-/]{1,200})', line)
        require(match is not None and match[2] not in rows and
                all(part not in ('', '.', '..') for part in match[2].split('/')),
                'node checksum manifest entry unsupported')
        rows[match[2]] = match[1]
    require(len(rows) <= 100, 'node checksum manifest entry bound')
    selected = {}
    for target, (label, _, digest, _, _) in NODE_PINS.items():
        name = f'node-v{VERSION}-{label}.tar.gz'
        require(rows.get(name) == digest, 'node signed checksum differs from native archive pin')
        selected[target] = {'name': name, 'sha256': digest}
    return selected


def _status(data, current):
    """Require one exact live SHA256/EdDSA signature; error, expired, revoked or unrecognized status cannot pass."""
    require(type(data) is bytes and 0 < len(data) <= MAX_BYTES,
            'node signature status bound')
    try:
        lines = data.decode('ascii').splitlines()
    except UnicodeDecodeError as error:
        raise Failure('node signature status encoding unsupported') from error
    valid = []
    good = []
    allowed = {'NEWSIG', 'KEY_CONSIDERED', 'SIG_ID', 'GOODSIG', 'VALIDSIG', 'PLAINTEXT', 'PLAINTEXT_LENGTH'}
    for line in lines:
        require(line.startswith('[GNUPG:] '), 'node signature status framing unsupported')
        words = line[len('[GNUPG:] '):].split()
        require(bool(words) and words[0] in allowed, 'node signature status unproven')
        if words[0] == 'GOODSIG':
            require(len(words) >= 2 and words[1] == FINGERPRINT[-16:],
                    'node signature signer differs')
            good.append(words)
        if words[0] == 'VALIDSIG':
            require(len(words) in (10, 11) and words[1] == FINGERPRINT and
                    (len(words) == 10 or words[10] == FINGERPRINT) and
                    re.fullmatch(r'\d{4}-\d{2}-\d{2}', words[2]) is not None and
                    words[3].isdigit() and words[4].isdigit() and
                    0 < int(words[3]) <= current and
                    (int(words[4]) == 0 or current < int(words[4])) and
                    words[5:10] == ['4', '0', '22', '8', '00'],
                    'node signature identity or algorithm unsupported')
            valid.append({'fingerprint': words[1], 'created_at': int(words[3]),
                          'expires_at': int(words[4]), 'public_key_algorithm': 'EdDSA', 'hash': 'SHA256'})
    require(len(valid) == len(good) == 1, 'node signature result missing or ambiguous')
    return valid[0]


def _run(executable, arguments, scratch):
    """Run only a native qualification verifier with sterile startup, closed stdin and bounded private process group."""
    environment = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C.UTF-8',
                   'HOME': str(scratch), 'GNUPGHOME': str(scratch / 'home'), 'TMPDIR': str(scratch)}
    process = subprocess.Popen([str(executable), *arguments], cwd=scratch, env=environment,
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    deadline = time.monotonic() + MAX_SECONDS
    counts, blocks = {'stdout': 0, 'stderr': 0}, []
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
            selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
            while selector.get_map():
                require(time.monotonic() < deadline, 'node signature verification timed out')
                for key, _ in selector.select(timeout=min(0.1, max(0, deadline - time.monotonic()))):
                    block = os.read(key.fileobj.fileno(), 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    counts[key.data] += len(block)
                    require(counts[key.data] <= MAX_BYTES, 'node signature verifier output exceeded bound')
                    if key.data == 'stdout':
                        blocks.append(block)
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
        require(process.returncode == 0, 'node native signature verification failed')
        return b''.join(blocks)
    except (OSError, subprocess.SubprocessError) as error:
        raise Failure('node native signature verification failed') from error
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        process.stdout.close()
        process.stderr.close()


def qualify():
    """Verify the exact offline public signature fixture with system Linux gpgv; issue observations, never a production permit."""
    data = fixture_bytes()
    archives = selected_archives(data['SHASUMS256.txt'])
    require(sys.platform == 'linux', 'node native OpenPGP qualification unsupported on this platform')
    native = Path('/usr/bin/gpgv')
    before = _read(native, 16 * 1024 * 1024)
    require(before.startswith(b'\x7fELF') and before[4] == 2,
            'node native OpenPGP qualification executable unsupported')
    with tempfile.TemporaryDirectory(prefix='armorer-node-signature-') as temporary:
        scratch = Path(temporary)
        scratch.chmod(0o700)
        (scratch / 'home').mkdir(mode=0o700)
        for name, value in data.items():
            path = scratch / name
            path.write_bytes(value)
            path.chmod(0o400)
        prefix = ['--homedir', str(scratch / 'home'), '--keyring', str(scratch / 'node-release-keys.kbx'), '--status-fd', '1']
        status = _run(native, [*prefix, str(scratch / 'SHASUMS256.txt.sig'), str(scratch / 'SHASUMS256.txt')], scratch)
        result = _status(status, int(time.time()))
        require(_read(native, 16 * 1024 * 1024) == before, 'node qualification verifier bytes changed')
    return {'kind': 'node-release-signature-qualification-v1', 'node_version': VERSION,
            'state': 'verified-qualification-only',
            'observed_at': int(time.time()), 'native_gpgv': {'sha256': hashlib.sha256(before).hexdigest(), 'size': len(before)},
            'signature': result, 'selected_archive_checksums': archives,
            'native_signature_verified': True, 'qualification_only': True,
            'production_root_approved': False, 'production_verifier_catalog_approved': False,
            'production_node_catalog_accepted': False, 'producer_signature_authentication_enabled': False,
            'downloaded_node_archives_executed': 0, 'credential_values_collected': False,
            'signing_authorized': False, 'publication_authorized': False}


def main():
    """Expose fixed credential-free qualification only, without command/root/URL/provenance arguments."""
    require(len(sys.argv) == 1, 'node signature qualification accepts no caller options')
    print(json.dumps(qualify(), sort_keys=True))


if __name__ == '__main__':
    main()
