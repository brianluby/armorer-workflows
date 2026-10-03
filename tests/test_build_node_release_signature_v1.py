"""Closed native public-signature qualification does not authenticate production tool/root policy."""
from pathlib import Path
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

from armorer_runtime import node_release_signature_v1 as signature
from armorer_runtime.common import Failure


class NodeReleaseSignature(unittest.TestCase):
    """Keep real signed input, exact pins, unavailable platforms and untrusted status distinct."""

    def status(self, overrides=None):
        """Construct test-only native status semantics; no fake record grants runtime authority."""
        values = {'fingerprint': signature.FINGERPRINT, 'date': '2026-09-08',
                  'created': '1788904155', 'expires': '0', 'version': '4',
                  'reserved': '0', 'algorithm': '22', 'hash': '8', 'class': '00',
                  'primary': signature.FINGERPRINT}
        values.update(overrides or {})
        line = ' '.join(values[k] for k in ('fingerprint', 'date', 'created', 'expires',
                                          'version', 'reserved', 'algorithm', 'hash', 'class', 'primary'))
        return ('[GNUPG:] GOODSIG ' + signature.FINGERPRINT[-16:] + ' Public test identity\n'
                '[GNUPG:] VALIDSIG ' + line + '\n').encode()

    def test_exact_public_fixture_matches_all_three_existing_archive_pins(self):
        """Parse the inert fixed manifest and bind Linux x64/ARM64 and macOS ARM64 without executing any archive."""
        data = signature.fixture_bytes()
        self.assertEqual(set(data), set(signature.EXPECTED))
        archives = signature.selected_archives(data['SHASUMS256.txt'])
        self.assertEqual(set(archives), {'x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu', 'aarch64-apple-darwin'})
        self.assertTrue(all(row['name'].endswith('.tar.gz') for row in archives.values()))

    def test_manifest_substitutions_duplicate_names_missing_pins_and_traversal_fail(self):
        """No checksum parser success implies trust; malformed or mismatched selected input is explicitly rejected."""
        original = signature.fixture_bytes()['SHASUMS256.txt']
        first = original.splitlines()[0]
        digest = signature.NODE_PINS['x86_64-unknown-linux-gnu'][2].encode()
        for data in (original.replace(digest, b'f' * 64), original + first + b'\n',
                     b'', b'not a checksum\n', b'f' * 64 + b'  ../escape\n', original + b'\xff'):
            with self.assertRaises(Failure):
                signature.selected_archives(data)

    def test_every_fixture_byte_substitution_and_symlink_is_rejected(self):
        """Fixed signature/root bytes remain inert and no altered fixture reaches native verification."""
        original = signature.fixture_bytes()
        for name in original:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                for key, value in original.items():
                    (root / key).write_bytes(value)
                (root / name).write_bytes(original[name] + b'x')
                with mock.patch.object(signature, 'ROOT', root), self.assertRaises((Failure, OSError)):
                    signature.fixture_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            leaf = root / 'leaf'
            leaf.write_bytes(b'inert')
            link = root / 'link'
            link.symlink_to(leaf)
            with self.assertRaises(OSError):
                signature._read(link, 10)

    def test_native_status_requires_exact_live_signer_hash_algorithm_and_one_result(self):
        """Status protocol doubles never establish crypto; only exact nonexpired native results pass parsing."""
        current = int(time.time())
        self.assertEqual(signature._status(self.status(), current)['fingerprint'], signature.FINGERPRINT)
        for value in ({'fingerprint': 'F' * 40}, {'primary': 'F' * 40}, {'hash': '2'},
                      {'algorithm': '1'}, {'version': '5'}, {'class': '01'},
                      {'created': str(current + 1)}, {'expires': str(current)}):
            with self.assertRaises(Failure):
                signature._status(self.status(value), current)
        for data in (b'', b'lookalike status', self.status() * 2, self.status().replace(b'GOODSIG', b'BADSIG'),
                     self.status() + b'[GNUPG:] EXPKEYSIG bad\n', self.status() + b'[GNUPG:] REVKEYSIG bad\n',
                     self.status() + b'[GNUPG:] ERROR bad\n', b'x' * (signature.MAX_BYTES + 1)):
            with self.assertRaises(Failure):
                signature._status(data, current)

    def test_unsupported_native_platform_never_launches_a_fallback(self):
        """macOS qualification remains explicit unsupported; no hash-only or alternative crypto path runs."""
        with mock.patch.object(signature.sys, 'platform', 'darwin'), mock.patch.object(signature, '_run') as run:
            with self.assertRaisesRegex(Failure, 'unsupported on this platform'):
                signature.qualify()
            run.assert_not_called()

    def test_actual_child_has_closed_stdin_and_no_parent_startup_or_credential_state(self):
        """An inert real child cannot inherit supplied credential/preload/debug environment variables."""
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary)
            (scratch / 'home').mkdir()
            code = 'import os,sys,json; print(json.dumps({"stdin":sys.stdin.read(),"environment":dict(os.environ)}))'
            offered = {'GH_TOKEN': 'synthetic-no-authority', 'GNUPGHOME': '/offered',
                       'PYTHONPATH': '/offered', 'GPG_AGENT_INFO': '/offered', 'LD_PRELOAD': '/offered',
                       'BASH_ENV': '/offered', 'ACTIONS_STEP_DEBUG': 'true'}
            with mock.patch.dict(os.environ, offered):
                result = json.loads(signature._run(Path(sys.executable), ['-I', '-c', code], scratch))
            self.assertEqual(result['stdin'], '')
            self.assertFalse(set(offered) - {'GNUPGHOME'} & set(result['environment']))
            self.assertEqual(result['environment']['GNUPGHOME'], str(scratch / 'home'))
            self.assertEqual(result['environment']['PATH'], '/usr/bin:/bin:/usr/sbin:/sbin')

    def test_actual_child_output_and_failure_never_reflect_native_diagnostics(self):
        """Real excessive stdout/stderr and nonzero child exit all fail the bounded native path."""
        for code, message in (('print("x"*70000)', 'output exceeded bound'),
                              ('import sys; sys.stderr.write("x"*70000)', 'output exceeded bound'),
                              ('import sys; sys.stderr.write("untrusted detail"); sys.exit(1)', 'verification failed')):
            with tempfile.TemporaryDirectory() as temporary:
                scratch = Path(temporary)
                (scratch / 'home').mkdir()
                with self.assertRaisesRegex(Failure, message) as failure:
                    signature._run(Path(sys.executable), ['-I', '-c', code], scratch)
                self.assertNotIn('untrusted detail', str(failure.exception))

    def test_actual_exited_leader_pipe_holder_is_reaped_before_return(self):
        """A surviving fork cannot outlive timeout cleanup merely because its parent exited."""
        if not hasattr(os, 'fork'):
            self.skipTest('native fork unavailable')
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary)
            (scratch / 'home').mkdir()
            code = 'import os,time; p=os.fork(); os._exit(0) if p else time.sleep(30)'
            started = time.monotonic()
            with mock.patch.object(signature, 'MAX_SECONDS', 0.1), self.assertRaisesRegex(Failure, 'timed out'):
                signature._run(Path(sys.executable), ['-I', '-c', code], scratch)
            self.assertLess(time.monotonic() - started, 3)


if __name__ == '__main__':
    unittest.main()
