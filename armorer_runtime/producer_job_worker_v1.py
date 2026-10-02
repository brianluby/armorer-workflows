"""Fixed internal read-only worker for the current-job/producer-OIDC controller join."""
from __future__ import annotations

from dataclasses import fields
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from types import MethodType

from .build import parse_json
from .common import Failure, require
from .controller_context_v1 import ControllerGhApi, EnvironmentIntent, JobIntent, observe_controller, _route as controller_route
from .source_transport_v1 import SourceGhApi, SourceIntent, _route as source_route
from .transport_tools_v1 import install_gh
from .transport_v1 import API_VERSION

MAX_INPUT = 64 * 1024
MAX_OUTPUT = 64 * 1024
_cancelled = False
_active_apis = []
NUMERIC_FIELDS = ("repository_id", "owner_id", "run_id", "run_attempt", "workflow_id", "actor_id",
                  "triggering_actor_id", "pull_request")


def _cancel(_number, _frame):
    """Expire registered reads without interrupting the native spawn-to-cleanup critical section."""
    global _cancelled
    _cancelled = True
    for api in _active_apis:
        api._deadline = 0


def _checkpoint():
    """Deny any further stage or successful output after cooperative worker cancellation."""
    require(not _cancelled, "worker cancelled")


def _worker_read(self, endpoint, destination, limit):
    """Fixed worker successor preserves exact native pins/routes and adds cancellation-safe reaping."""
    _checkpoint()
    require((type(self) is SourceGhApi and source_route(endpoint)) or
            (type(self) is ControllerGhApi and controller_route(endpoint)), "worker native route denied")
    require(not self._operator and time.monotonic() < self._deadline, "worker native stage denied")
    self._check_native()
    with tempfile.TemporaryDirectory(prefix="armorer-worker-read-") as temporary:
        scratch = Path(temporary)
        environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8", "GH_HOST": "github.com",
                       "GH_PROMPT_DISABLED": "1", "GH_PAGER": "cat", "TMPDIR": str(scratch),
                       "HOME": str(scratch), "GH_CONFIG_DIR": str(scratch / "config"),
                       "XDG_CACHE_HOME": str(scratch / "cache"), "GH_TOKEN": self._token}
        arguments = [str(self.executable), "api", "--hostname", "github.com", "--method", "GET",
                     "--header", "Accept: application/vnd.github+json", "--header",
                     "X-GitHub-Api-Version: " + API_VERSION, endpoint]
        process = None
        try:
            # The guard starts before Popen: SIGTERM never throws in the spawn-to-assignment gap.
            process = subprocess.Popen(arguments, cwd=scratch, env=environment, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            _checkpoint()
            deadline = min(self._deadline, time.monotonic() + 60)
            counts = {"stdout": 0, "stderr": 0}
            with destination.open("xb") as output, selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, "stdout")
                selector.register(process.stderr, selectors.EVENT_READ, "stderr")
                while selector.get_map():
                    _checkpoint()
                    require(time.monotonic() < deadline, "worker native read timed out")
                    for key, _ in selector.select(timeout=min(0.1, max(0, deadline - time.monotonic()))):
                        block = os.read(key.fileobj.fileno(), 65536)
                        if not block:
                            selector.unregister(key.fileobj)
                            continue
                        counts[key.data] += len(block)
                        require(counts[key.data] <= (limit if key.data == "stdout" else 1024 * 1024),
                                "worker native output exceeded limit")
                        if key.data == "stdout":
                            output.write(block)
                process.wait(timeout=max(0.001, deadline - time.monotonic()))
                _checkpoint()
                require(process.returncode == 0 and counts["stdout"] > 0, "worker native read failed")
                output.flush()
                os.fsync(output.fileno())
            destination.chmod(0o400)
        except (OSError, subprocess.SubprocessError) as error:
            raise Failure("worker native read failed") from error
        finally:
            if process is not None:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except PermissionError as error:
                        try:
                            process.wait(timeout=0.1)
                        except subprocess.TimeoutExpired:
                            raise Failure("worker native termination denied") from error
                process.wait()
                process.stdout.close()
                process.stderr.close()


def _identifier(value):
    """Decode canonical decimal strings without JavaScript precision loss or implicit coercion."""
    require(type(value) is str and re.fullmatch(r"[1-9][0-9]{0,18}", value) is not None and
            int(value) <= 2**63 - 1, "worker numeric identity invalid")
    return int(value)


def _shape(value, names):
    """Require exactly the versioned data keys; no default inheritance or extra provider inputs."""
    require(type(value) is dict and set(value) == set(names), "worker input shape invalid")


def _intent(value):
    """Validate all source/job/environment expectations before any native download or API read."""
    _shape(value, ("source", "workflow_name", "job_name", "runner_label", "qualification_only", "environment"))
    source = value["source"]
    _shape(source, (field.name for field in fields(SourceIntent)))
    source = dict(source)
    for name in NUMERIC_FIELDS:
        if name == "pull_request" and source[name] is None:
            continue
        source[name] = _identifier(source[name])
    referenced = source["referenced_workflows"]
    require(type(referenced) is list and len(referenced) <= 64 and
            all(type(row) is list and len(row) == 2 and all(type(part) is str for part in row)
                for row in referenced), "worker reusable expectations invalid")
    source["referenced_workflows"] = tuple(tuple(row) for row in referenced)
    expected = JobIntent(SourceIntent(**source), value["workflow_name"], value["job_name"],
                         value["runner_label"], value["qualification_only"])
    expected.validate()
    environment = value["environment"]
    if environment is not None:
        _shape(environment, (field.name for field in fields(EnvironmentIntent)))
        require(not expected.qualification_only, "worker protected qualification denied")
        environment = dict(environment)
        environment["environment_id"] = _identifier(environment["environment_id"])
        require(type(environment["reviewer_ids"]) is list and len(environment["reviewer_ids"]) <= 6,
                "worker reviewer expectations invalid")
        environment["reviewer_ids"] = tuple(_identifier(item) for item in environment["reviewer_ids"])
        environment = EnvironmentIntent(**environment)
        environment.validate(expected.source)
    return expected, environment


def observe(value):
    """Produce one bounded fresh canonical identity result using only pinned native read-only tools."""
    expected, environment = _intent(value)
    _checkpoint()
    token = os.environ.pop("ARMORER_WORKFLOW_READ_TOKEN", None)
    require(type(token) is str and 0 < len(token) <= 4096 and
            not any(ord(char) <= 32 or ord(char) == 127 for char in token), "worker read token unavailable")
    with tempfile.TemporaryDirectory(prefix="armorer-producer-worker-") as temporary:
        executable, distribution = install_gh(Path(temporary) / "native")
        _checkpoint()
        source_api = SourceGhApi(executable, token)
        api = ControllerGhApi(executable, token)
        source_api._read = MethodType(_worker_read, source_api)
        api._read = MethodType(_worker_read, api)
        _active_apis.extend((source_api, api))
        _checkpoint()
        del token
        record = observe_controller(source_api, api, expected, environment)
        _checkpoint()
        mapped = record["controller"]["job"]
        # Both snapshots include the complete attempt job identities and mutable source prerequisites.
        stable = {"source_control": record["source_control"], "controller": record["controller"]}
        digest = hashlib.sha256(json.dumps(stable, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        controls = record["controller"]["environment"]
        # Cross-language IDs remain strings even when GitHub grows beyond JS's safe integer range.
        controls = None if controls is None else {
            "name": controls["name"], "id": str(controls["id"]), "node_id": controls["node_id"],
            "configuration_sha256": controls["configuration_sha256"], "state": controls["state"],
            "current_attempt_approval": controls["current_attempt_approval"],
            "effective_enforcement": controls["effective_enforcement"]}
        result = {"schema_version": 1, "state": "independently-mapped-producer-job",
                  "observed_at": record["observed_at"], "run_started_at": record["controller"]["run_started_at"],
                  "snapshot_sha256": digest, "candidate_qualification_only": expected.qualification_only,
                  "source": {"repository": expected.source.repository,
                             "repository_id": str(expected.source.repository_id),
                             "owner_id": str(expected.source.owner_id), "commit": expected.source.source_commit,
                             "caller_commit": expected.source.caller_commit,
                             "caller_sha256": record["source_control"]["caller"]["sha256"],
                             "run_id": str(expected.source.run_id), "run_attempt": str(expected.source.run_attempt)},
                  "job": {"job_id": str(mapped["job_id"]), "check_run_id": str(mapped["check_run_id"]),
                          "name": mapped["name"], "workflow_name": mapped["workflow_name"],
                          "runner_label": mapped["runner_label"], "started_at": mapped["started_at"]},
                  "environment": controls, "native_distribution": distribution,
                  "source_provider_authenticated": True, "current_job_mapping_observed": True,
                  "producer_job_authenticated": False, "environment_protection_authenticated": False,
                  "production_catalog_accepted": False, "signing_authorized": False,
                  "publication_authorized": False}
        require(int(time.time()) >= result["observed_at"], "worker clock rolled back")
        return result


def main():
    """Accept one bounded stdin request and emit only fixed redacted errors or whitelisted JSON."""
    previous = signal.signal(signal.SIGTERM, _cancel)
    try:
        require(len(sys.argv) == 1, "worker command arguments unsupported")
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        require(0 < len(raw) <= MAX_INPUT, "worker input exceeded limit")
        result = observe(parse_json(raw))
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        require(len(encoded) <= MAX_OUTPUT, "worker output exceeded limit")
        _checkpoint()
        sys.stdout.buffer.write(encoded + b"\n")
        sys.stdout.buffer.flush()
    except Exception:
        # Child errors must not propagate API diagnostics, stdin values or interpreter traceback.
        sys.stderr.write("producer-worker-failed\n")
        raise SystemExit(1) from None
    finally:
        _active_apis.clear()
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    main()
