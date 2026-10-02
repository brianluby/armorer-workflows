"""Worker boundaries and real cancellation supplement the separately qualified native API observer."""
import copy
from dataclasses import asdict
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from armorer_runtime import producer_job_worker_v1 as worker
from armorer_runtime.common import Failure
from armorer_runtime.source_transport_v1 import SourceGhApi
from armorer_runtime.transport_tools_v1 import DISTRIBUTIONS
from armorer_runtime.transport_v1 import GH_PINS, GH_SOURCE, GH_VERSION
from test_build_controller_context_v1 import fixture, observe


def intent(event="workflow_dispatch", environment=False):
    """Keep independently expected source values separate from synthetic native responses."""
    expected, source, data, policy = fixture(event, environment)
    value = asdict(expected)
    value["source"]["referenced_workflows"] = [list(row) for row in value["source"]["referenced_workflows"]]
    for name in worker.NUMERIC_FIELDS:
        if value["source"][name] is not None:
            value["source"][name] = str(value["source"][name])
    value["environment"] = None if policy is None else asdict(policy)
    if policy is not None:
        value["environment"]["environment_id"] = str(policy.environment_id)
        value["environment"]["reviewer_ids"] = [str(item) for item in policy.reviewer_ids]
    return value, expected, source, data, policy


def distribution():
    """Return explicit inert delivery metadata without claiming an upstream signature or catalog."""
    target = "aarch64-apple-darwin"
    size, digest = GH_PINS[target]
    return {"schema_version": 1, "state": "native-distribution-byte-qualified", "target": target,
            "version": GH_VERSION, "source_commit": GH_SOURCE,
            "archive": DISTRIBUTIONS[target], "executable": {"size": size, "sha256": digest},
            "production_catalog_accepted": False, "upstream_signature_authenticated": False,
            "signing_authorized": False}


class WorkerTests(unittest.TestCase):
    """Reject offered authority and unsafe scope before downloads, tokens or provider access."""

    def tearDown(self):
        """Reset private cancellation state after each isolated in-process worker fixture."""
        worker._cancelled = False
        worker._active_apis.clear()

    def test_canonical_ids_preserve_precision_and_reject_coercion(self):
        """Every cross-language ID is a canonical string even above JavaScript's safe integer range."""
        self.assertEqual(worker._identifier("9007199254740993"), 9007199254740993)
        self.assertEqual(worker._identifier("9223372036854775807"), 2**63 - 1)
        for value in (True, 1, 1.0, None, "0", "01", "+1", "1\n", "9223372036854775808"):
            with self.subTest(value=value), self.assertRaises(Failure):
                worker._identifier(value)

    def test_exact_scope_rejects_before_token_or_download(self):
        """No extra key, unsafe event, caller option or qualification environment can enter native code."""
        original = intent()[0]
        variants = []
        for key, value in (("qualification_only", 1), ("job_name", "job\n"), ("runner_label", "self-hosted")):
            changed = copy.deepcopy(original)
            changed[key] = value
            variants.append(changed)
        changed = copy.deepcopy(original)
        changed["command"] = "provider-secret-marker"
        variants.append(changed)
        changed = copy.deepcopy(original)
        changed["source"]["event"] = "pull_request_target"
        variants.append(changed)
        changed = intent("pull_request", True)[0]
        variants.append(changed)
        with mock.patch.object(worker, "install_gh") as install, mock.patch.dict(os.environ, {}, clear=True):
            for changed in variants:
                with self.subTest(changed=changed), self.assertRaises(Failure):
                    worker.observe(changed)
            install.assert_not_called()

    def test_native_observer_compact_record_and_full_snapshot_digest(self):
        """Real observer logic supplies the digest; raw provider metadata never becomes output authority."""
        value, expected, source, data, policy = intent(environment=True)
        native = observe(expected, source, data, policy)
        with mock.patch.object(worker, "install_gh", return_value=(Path("/inert-never-executed"), distribution())), \
             mock.patch.object(worker, "observe_controller", return_value=native), \
             mock.patch.dict(os.environ, {"ARMORER_WORKFLOW_READ_TOKEN": "synthetic-only-token"}), \
             mock.patch("time.time", return_value=120):
            first = worker.observe(value)
            native["controller"]["attempt_jobs"].append({"id": 999, "name": "another job"})
            os.environ["ARMORER_WORKFLOW_READ_TOKEN"] = "synthetic-only-token"
            second = worker.observe(value)
        self.assertNotEqual(first["snapshot_sha256"], second["snapshot_sha256"])
        self.assertEqual(first["job"]["check_run_id"], "47")
        self.assertEqual(first["job"]["job_id"], "31")
        self.assertEqual(first["environment"]["id"], "61")
        self.assertEqual(first["environment"]["current_attempt_approval"], "unsupported")
        self.assertFalse(first["producer_job_authenticated"])
        self.assertFalse(first["environment_protection_authenticated"])
        self.assertFalse(first["publication_authorized"])
        self.assertNotIn("synthetic-only-token", json.dumps(first))

    def test_cancellation_expires_both_api_deadlines_without_raising_in_spawn_gap(self):
        """Signal handling must defer failure until native cleanup can own any just-spawned process."""
        first = mock.Mock(_deadline=1000)
        second = mock.Mock(_deadline=1000)
        worker._active_apis.extend((first, second))
        worker._cancel(signal.SIGTERM, None)
        self.assertEqual((first._deadline, second._deadline), (0, 0))
        with self.assertRaises(Failure):
            worker._checkpoint()

    def test_invalid_and_overlong_input_have_only_fixed_diagnostics(self):
        """Malformed, duplicate and oversized stdin cannot leak values, API errors or traceback text."""
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":"provider-secret-marker"}', b"x" * 65537):
            stdout, stderr = io.TextIOWrapper(io.BytesIO()), io.StringIO()
            stdin = io.TextIOWrapper(io.BytesIO(raw))
            with self.subTest(raw=raw[:50]), mock.patch.object(sys, "argv", ["worker"]), \
                 mock.patch.object(sys, "stdin", stdin), mock.patch.object(sys, "stdout", stdout), \
                 mock.patch.object(sys, "stderr", stderr), mock.patch.object(worker, "install_gh") as install:
                with self.assertRaises(SystemExit) as denied:
                    worker.main()
                self.assertEqual(denied.exception.code, 1)
                self.assertEqual(stderr.getvalue(), "producer-worker-failed\n")
                self.assertEqual(stdout.buffer.getvalue(), b"")
                install.assert_not_called()

    def test_missing_token_fails_before_native_download(self):
        """Read authentication stays explicit and is never discovered from ambient GH/OIDC variables."""
        with mock.patch.dict(os.environ, {"GH_TOKEN": "inert", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "inert"}, clear=True), \
             mock.patch.object(worker, "install_gh") as install, self.assertRaises(Failure):
            worker.observe(intent()[0])
        install.assert_not_called()

    def test_worker_native_routes_and_operator_mode_reject_before_spawn(self):
        """The cancellation-aware successor does not widen routes or discover operator credentials."""
        api = SourceGhApi(Path("/inert-not-native"), "synthetic-only-token")
        for route in ("repos/owner/repo/releases", "https://evil.invalid", "repos/owner/repo/actions/runs/17/logs"):
            with self.subTest(route=route), mock.patch.object(worker.subprocess, "Popen") as spawn, self.assertRaises(Failure):
                worker._worker_read(api, route, Path("/inert-output"), 256)
            spawn.assert_not_called()
        api._operator = True
        with mock.patch.object(worker.subprocess, "Popen") as spawn, self.assertRaises(Failure):
            worker._worker_read(api, "repos/owner/repo/actions/runs/17", Path("/inert-output"), 256)
        spawn.assert_not_called()

    def test_worker_native_process_is_sterile_fixed_get_and_hash_checked(self):
        """Owned executable fixtures verify the new method's argv, private cwd and credential exclusions."""
        with tempfile.TemporaryDirectory(prefix="armorer-worker-native-test-") as temporary:
            directory = Path(temporary)
            executable = directory / "fixture-native"
            executable.write_text("#!" + sys.executable + "\nimport os,sys,json\n" +
                                  "print(json.dumps({\"argv\":sys.argv[1:],\"env\":dict(os.environ),\"cwd\":os.getcwd()}))\n")
            executable.chmod(0o700)
            api = SourceGhApi(executable, "synthetic-only-token")
            output = directory / "response"
            with mock.patch.object(api, "_check_native") as check, \
                 mock.patch.dict(os.environ, {"APPLE_CERTIFICATE": "unrelated", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "unrelated",
                                              "GH_DEBUG": "api", "HTTP_PROXY": "unrelated", "PYTHONPATH": "unrelated"}):
                worker._worker_read(api, "repos/owner/repo/actions/runs/17", output, 4096)
            check.assert_called_once()
            observed = json.loads(output.read_bytes())
            self.assertEqual(observed["argv"][:5], ["api", "--hostname", "github.com", "--method", "GET"])
            self.assertEqual(observed["argv"][-1], "repos/owner/repo/actions/runs/17")
            self.assertEqual(observed["env"]["GH_TOKEN"], "synthetic-only-token")
            for forbidden in ("APPLE_CERTIFICATE", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "GH_DEBUG", "HTTP_PROXY", "PYTHONPATH"):
                self.assertNotIn(forbidden, observed["env"])
            self.assertEqual(Path(observed["cwd"]).resolve(), Path(observed["env"]["HOME"]).resolve())
            self.assertFalse(Path(observed["cwd"]).exists())
            self.assertEqual(output.stat().st_mode & 0o777, 0o400)

    def test_worker_native_output_and_diagnostics_are_bounded(self):
        """The successor refuses oversized stdout/stderr and failed exit without exposing diagnostics."""
        for mode in ("stdout", "stderr", "failed"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="armorer-worker-bounds-test-") as temporary:
                directory = Path(temporary)
                executable = directory / "fixture-native"
                behavior = {"stdout": "sys.stdout.write(\"x\"*257)",
                            "stderr": "sys.stderr.write(\"x\"*(1024*1024+1))",
                            "failed": "sys.stderr.write(\"provider-secret-marker\");sys.exit(1)"}[mode]
                executable.write_text("#!" + sys.executable + "\nimport sys\n" + behavior + "\n")
                executable.chmod(0o700)
                api = SourceGhApi(executable, "synthetic-only-token")
                with mock.patch.object(api, "_check_native"), self.assertRaises(Failure) as rejected:
                    worker._worker_read(api, "repos/owner/repo/actions/runs/17", directory / "response", 256)
                self.assertNotIn("provider-secret-marker", str(rejected.exception))

    def test_real_signal_reaps_separate_native_process_and_spawn_gap(self):
        """Actual inert native processes are reaped on cancellation both in reads and immediately after spawn."""
        root = Path(__file__).resolve().parents[1]
        for gap in (False, True):
            with self.subTest(gap=gap), tempfile.TemporaryDirectory(prefix="armorer-worker-process-test-") as temporary:
                directory = Path(temporary)
                process = subprocess.Popen(["rtk", "proxy", sys.executable, "-I", str(root / "tests/producer_worker_process_v1.py"),
                                            str(root), str(directory), str(int(gap))],
                                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    process.stdin.write(json.dumps(intent()[0]).encode())
                    process.stdin.close()
                    deadline = time.monotonic() + 10
                    while not (directory / "native.pid").exists():
                        self.assertLess(time.monotonic(), deadline, "fixture native process never started")
                        time.sleep(0.02)
                    native_pid = int((directory / "native.pid").read_text())
                    if not gap:
                        os.kill(int((directory / "worker.pid").read_text()), signal.SIGTERM)
                    self.assertEqual(process.wait(timeout=10), 1)
                    self.assertEqual(process.stdout.read(), b"")
                    self.assertEqual(process.stderr.read(), b"producer-worker-failed\n")
                    with self.assertRaises(ProcessLookupError):
                        os.kill(native_pid, 0)
                finally:
                    if process.poll() is None:
                        if (directory / "worker.pid").exists():
                            try:
                                os.kill(int((directory / "worker.pid").read_text()), signal.SIGTERM)
                            except ProcessLookupError:
                                pass
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
                    process.stdout.close()
                    process.stderr.close()


if __name__ == "__main__":
    unittest.main()
