"""Exercise actual exited leaders with pipe-holding descendants and synthetic read tokens."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from armorer_runtime import controller_context_v1 as controller
from armorer_runtime import producer_job_worker_v1 as worker
from armorer_runtime import source_transport_v1 as source
from armorer_runtime import transport_v1 as transport
from armorer_runtime.common import Failure


class NativeCleanupTests(unittest.TestCase):
    """Ensure every credentialed native reader terminates its entire owned process group."""

    def assert_descendant_reaped(self, kind, worker_read=False):
        """Retain child pipes after leader exit and reject any delayed descendant side effect."""
        with tempfile.TemporaryDirectory(prefix="armorer-exited-reader-") as temporary:
            root = Path(temporary)
            executable, marker = root / "fake-native", root / "descendant-wrote"
            child = "import time; from pathlib import Path; time.sleep(1); Path(" + repr(str(marker)) + ").write_text('bad')"
            executable.write_text("#!" + sys.executable + "\nimport subprocess,sys\nsubprocess.Popen([sys.executable,'-c'," + repr(child) + "])\n")
            executable.chmod(0o700)
            api = kind(executable, "test-only-token")
            api._deadline = time.monotonic() + 0.4
            spawned = []
            native_spawn = subprocess.Popen

            def capture(*args, **kwargs):
                """Retain the real group leader only so the test can verify exit and clean up on failure."""
                process = native_spawn(*args, **kwargs)
                spawned.append(process)
                return process

            try:
                with mock.patch.object(api, "_check_native"), mock.patch.object(worker, "_cancelled", False), \
                        mock.patch.object(subprocess, "Popen", side_effect=capture), \
                        self.assertRaisesRegex(Failure, "(?:read|transport) timed out"):
                    reader = worker._worker_read if worker_read else type(api)._read
                    reader(api, "repos/owner/repo/actions/runs/17", root / "response", 4096)
                self.assertEqual(len(spawned), 1)
                self.assertEqual(spawned[0].returncode, 0, "fixture leader must have exited before cleanup")
                time.sleep(1.1)
                self.assertFalse(marker.exists(), "an exited leader left its descendant running")
            finally:
                # Failure proofs also reap the deliberately exposed test-only descendant.
                for process in spawned:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_source_reader_reaps_exited_leader_descendant(self):
        """The source adapter kills a surviving pipe holder after its leader exits."""
        self.assert_descendant_reaped(source.SourceGhApi)

    def test_artifact_reader_reaps_exited_leader_descendant(self):
        """The shared artifact reader also kills a pipe holder after its leader exits."""
        self.assert_descendant_reaped(transport.QualifiedGhApi)

    def test_controller_reader_reaps_exited_leader_descendant(self):
        """The controller adapter kills a surviving pipe holder after its leader exits."""
        self.assert_descendant_reaped(controller.ControllerGhApi)

    def test_worker_source_reader_reaps_exited_leader_descendant(self):
        """The cancellation-aware worker reaps descendants when using source routes."""
        self.assert_descendant_reaped(source.SourceGhApi, worker_read=True)

    def test_worker_controller_reader_reaps_exited_leader_descendant(self):
        """The cancellation-aware worker reaps descendants when using controller routes."""
        self.assert_descendant_reaped(controller.ControllerGhApi, worker_read=True)
