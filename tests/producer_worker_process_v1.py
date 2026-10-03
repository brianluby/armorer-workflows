"""Owned inert-process harness; test-only bypasses cannot enter the production worker interface."""
import os
from pathlib import Path
import signal
import subprocess
import sys
from unittest import mock

root, directory, gap = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3] == "1"
sys.path.insert(0, str(root))
from armorer_runtime import producer_job_worker_v1 as worker
from armorer_runtime.source_transport_v1 import SourceGhApi
from armorer_runtime.controller_context_v1 import ControllerGhApi

(directory / "worker.pid").write_text(str(os.getpid()))
executable = directory / "inert-native"
executable.write_text("#!" + sys.executable + "\nimport os,time\nfrom pathlib import Path\n" +
                      "Path(" + repr(str(directory / "native.pid")) + ").write_text(str(os.getpid()))\ntime.sleep(30)\n")
executable.chmod(0o700)
original = subprocess.Popen


def spawn_then_cancel(*arguments, **options):
    """Deliver SIGTERM in the exact old native Popen-to-try gap without throwing there."""
    process = original(*arguments, **options)
    if gap:
        # The owned child writes its PID before cancellation so the parent can assert reaping.
        import time
        deadline = time.monotonic() + 5
        while not (directory / "native.pid").exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        os.kill(os.getpid(), signal.SIGTERM)
    return process


sys.argv = ["worker"]
os.environ["ARMORER_WORKFLOW_READ_TOKEN"] = "synthetic-only-token"
with mock.patch.object(worker, "install_gh", return_value=(executable, {})), \
     mock.patch.object(SourceGhApi, "_check_native"), mock.patch.object(ControllerGhApi, "_check_native"), \
     mock.patch.object(subprocess, "Popen", side_effect=spawn_then_cancel):
    worker.main()
