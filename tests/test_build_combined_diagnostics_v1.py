"""Test coded native-qualification failures without exposing metadata or creating release authority."""
import contextlib
import ast
import io
import json
import os
from pathlib import Path
import re
import signal
import sys
import tempfile
import unittest
from unittest import mock
import urllib.error

from armorer_runtime.common import Failure
from combined_handoff_diagnostics_v1 import CODES, PHASES, PREFIX, INVARIANTS, failure_line, fixed_error_code
import combined_handoff_cases_v1 as worker


class FixedDiagnosticTests(unittest.TestCase):
    """Closed vocabularies survive hostile error content and cannot change collector acceptance."""

    def test_python_node_protocol_vocabularies_are_identical(self):
        """Protocol divergence must fail locally rather than discard genuine hosted diagnoses."""
        source = Path(__file__).with_name('combined_handoff_diagnostics_v1.mjs').read_text()
        for name, expected in [('WORKER_PHASES', PHASES), ('WORKER_CODES', CODES)]:
            literal = re.search('export const ' + name + r' = Object.freeze\((\[.*?\])\);', source, re.S).group(1)
            self.assertEqual(tuple(json.loads(literal)), expected)

    def test_http_status_is_fixed_without_url_header_body_or_message(self):
        """Only recognized numeric HTTP status classes can appear in the failure label."""
        for status, expected in [(403, 'http-forbidden'), (404, 'http-not-found'), (429, 'http-rate-limited'),
                                 (500, 'http-server-error'), (502, 'http-server-error'), (503, 'http-server-error'),
                                 (504, 'http-server-error'), (418, 'http-other')]:
            offered = urllib.error.HTTPError('https://credential-marker-not-for-output.invalid', status,
                'credential-marker-not-for-output', {'Authorization': 'credential-marker-not-for-output'}, None)
            self.assertEqual(failure_line('reviewed-tool-members', offered), PREFIX + ' reviewed-tool-members ' + expected + '\n')
            self.assertNotIn('credential-marker', failure_line('reviewed-tool-members', offered))

    def test_wrapped_http_failure_preserves_fixed_category(self):
        """Existing fail-closed installation wrappers retain safe underlying HTTP classification."""
        wrapped = Failure('credential-marker-not-for-output')
        wrapped.__cause__ = urllib.error.HTTPError('https://example.invalid', 403, 'offered', {}, None)
        self.assertEqual(fixed_error_code(wrapped), 'http-forbidden')

    def test_unsupported_phase_and_errors_never_render_offered_content(self):
        """Arbitrary exception text and phase names cannot become output or workflow claims."""
        class Poison(Exception):
            """Fail the test if diagnostic code attempts to stringify arbitrary error content."""
            def __str__(self):
                """Prevent accidental raw diagnostic rendering."""
                raise AssertionError('arbitrary exception text was accessed')
        self.assertEqual(failure_line('credential-marker-not-for-output', Poison()),
                         PREFIX + ' worker-no-coded-error unclassified\n')
        for offered, expected in [(TimeoutError('offered'), 'timeout'),
                (urllib.error.URLError('offered'), 'network-unclassified'),
                (Failure('offered'), 'invariant-rejected'), (AssertionError('offered'), 'invariant-rejected'),
                (UnicodeError('offered'), 'metadata-decode'), (KeyError('offered'), 'metadata-key'),
                (OSError('offered'), 'io-unclassified')]:
            self.assertEqual(fixed_error_code(offered), expected)

    def test_cyclic_and_long_causes_are_bounded(self):
        """Exception chains cannot create unbounded diagnostic work or retained raw strings."""
        error = Exception('credential-marker-not-for-output')
        error.__cause__ = error
        self.assertEqual(fixed_error_code(error), 'unclassified')
        top = error = Exception('offered')
        for _ in range(32):
            error.__cause__ = Exception('offered')
            error = error.__cause__
        error.__cause__ = urllib.error.HTTPError('https://example.invalid', 403, 'offered', {}, None)
        self.assertEqual(fixed_error_code(top), 'unclassified')

    def test_real_worker_install_failure_emits_only_fixed_code_and_no_result(self):
        """Exercise the worker boundary with a hostile HTTP failure before native API or archive reads."""
        stdout, stderr = io.StringIO(), io.StringIO()
        original_signal = signal.getsignal(signal.SIGTERM)
        offered = urllib.error.HTTPError('https://credential-marker-not-for-output.invalid', 403,
            'credential-marker-not-for-output', {'Authorization': 'credential-marker-not-for-output'}, None)
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(sys, 'argv', ['owned-worker', temporary, temporary]), \
                mock.patch.dict(os.environ, {'ARMORER_WORKFLOW_READ_TOKEN': 'inert-test-token'}), \
                mock.patch.object(worker, '_cancelled', False), \
                mock.patch.object(worker, 'install_gh', side_effect=offered) as install, \
                mock.patch.object(worker.transport, 'QualifiedGhApi') as api, \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as stopped:
                worker.main()
            self.assertEqual(stopped.exception.code, 1)
            self.assertNotIn('ARMORER_WORKFLOW_READ_TOKEN', os.environ)
            install.assert_called_once()
            api.assert_not_called()
        self.assertEqual(stdout.getvalue(), '')
        self.assertEqual(stderr.getvalue(), PREFIX + ' native-gh-install http-forbidden\n')
        self.assertEqual(signal.getsignal(signal.SIGTERM), original_signal)
        self.assertEqual(worker._apis, [])

    def test_real_artifact_set_gate_has_a_specific_fixed_label(self):
        """Identify an actual rejected collector prerequisite without outputting its metadata or granting authority."""
        with self.assertRaises(Failure) as stopped:
            worker.transport._listing({'total_count': 0, 'artifacts': []}, None, {'inert-name'}, 1, 2)
        self.assertEqual(failure_line('archive-pair-reader', stopped.exception),
                         PREFIX + ' archive-pair-reader invariant-artifact-set\n')

    def test_only_exact_bounded_owned_failure_messages_select_codes(self):
        """Known gates select fixed labels; oversized, dynamic or hostile message objects remain generic."""
        class PoisonText(str):
            """Make unintended hashing or equality of offered message subclasses observable."""
            def __hash__(self):
                """Reject dictionary lookup of an unqualified message object."""
                raise AssertionError('offered message was hashed')
        for message, code in INVARIANTS.items():
            self.assertIn(code, CODES)
            self.assertEqual(fixed_error_code(Failure(message)), code)
        for message in ['credential-marker-not-for-output', 'x' * 65536,
                        PoisonText('incomplete or extra provider artifact set'), object()]:
            self.assertEqual(fixed_error_code(Failure(message)), 'invariant-rejected')
        self.assertEqual(fixed_error_code(Failure('incomplete or extra provider artifact set', 'offered')),
                         'invariant-rejected')

    def test_invariant_labels_reference_real_owned_gate_messages(self):
        """A diagnostic typo or stale gate mapping must fail rather than masquerade as usable hosted diagnosis."""
        root = Path(__file__).resolve().parent.parent / 'armorer_runtime'
        messages = set()
        for name in ['combined_handoff_v1.py', 'transport_v1.py', 'build_v3.py', 'policy_v1.py', 'policy_transport_v1.py']:
            messages.update(node.value for node in ast.walk(ast.parse((root / name).read_text()))
                            if isinstance(node, ast.Constant) and type(node.value) is str)
        self.assertEqual(set(INVARIANTS) - messages, set())


if __name__ == '__main__':
    unittest.main()
