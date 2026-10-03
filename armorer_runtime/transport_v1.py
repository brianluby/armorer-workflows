"""Bound GitHub artifact transport to independent expectations; never authorize signing.

Only the pinned native GitHub CLI performs network reads. Provider-authenticated
storage observations are distinct from Sigstore, producer-job and Apple proofs.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import struct
import subprocess
import tempfile
import time
from types import MappingProxyType
import zipfile
import zlib

from .build import parse_json
from .build_v3 import _names
from .common import Failure, require
from .tools import platform_target

GH_VERSION = "2.102.0"
GH_SOURCE = "fc4b137cdef0a6bd28fd461b7cf9c84a5812a8cd"
GH_PINS = {
    "x86_64-unknown-linux-gnu": (42086560, "7469124f706944133d6a169691dd1c6c3511b12e85878d255e044e2948df4c9b"),
    "aarch64-unknown-linux-gnu": (39059616, "93308395c2d296a63a662742c6366e4db413d2a4870d07bd9b84e491c065d65d"),
    "aarch64-apple-darwin": (39834784, "8a4258433c81106343144857750316241759d06dcf16265cf3c4864a8f2f2ad6"),
}
MAX_JSON = 4 * 1024 * 1024
MAX_ZIP = 1152 * 1024 * 1024
MAX_SELECTIONS = 64
API_VERSION = "2022-11-28"


def _identity(path: Path, limit: int) -> dict:
    """Hash one bounded regular leaf without following a final symlink."""
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= limit, "transport file type or size")
    digest = hashlib.sha256()
    size = 0
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        require((opened.st_dev, opened.st_ino, opened.st_size) ==
                (before.st_dev, before.st_ino, before.st_size), "transport file changed during open")
        while block := stream.read(65536):
            size += len(block)
            require(size <= limit, "transport file exceeds limit")
            digest.update(block)
    after = path.lstat()
    require(size == before.st_size and
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) ==
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns), "transport file changed")
    return {"sha256": digest.hexdigest(), "size": size}


class QualifiedGhApi:
    """Fixed GET-only native adapter with isolated workflow authentication and bounded output.

The separate operator qualification constructor uses the workstation's existing
GitHub credential store through gh; it never reads or exports credential values.
It cannot qualify workflow-token isolation or grant a finalizer authorization.
"""

    def __init__(self, executable: Path, workflow_token: str):
        """Accept an ephemeral actions-read workflow token, never a caller-selected endpoint or tool pin."""
        require(isinstance(workflow_token, str) and 0 < len(workflow_token) <= 4096 and
                not any(ord(char) < 33 or ord(char) == 127 for char in workflow_token),
                "workflow read token unavailable")
        self.executable = executable.absolute()
        self._token = workflow_token
        self._operator = False
        self._deadline = time.monotonic() + 1200

    @classmethod
    def operator_qualification(cls, executable: Path) -> QualifiedGhApi:
        """Use existing gh authentication for explicitly authorized read-only native qualification."""
        result = cls.__new__(cls)
        result.executable = executable.absolute()
        result._token = None
        result._operator = True
        result._deadline = time.monotonic() + 1200
        return result

    def _check_native(self) -> None:
        """Require independently qualified executable bytes for the actual native platform before every read."""
        target = platform_target()
        require(target in GH_PINS, "unsupported native transport platform")
        size, digest = GH_PINS[target]
        require(_identity(self.executable, size) == {"sha256": digest, "size": size},
                "native GitHub transport byte mismatch")
        require(os.access(self.executable, os.X_OK), "native GitHub transport is not executable")

    def _read(self, endpoint: str, destination: Path, limit: int) -> None:
        """Stream fixed native GET output with hard byte/time bounds and discard all diagnostic text."""
        require(re.fullmatch(r"repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/"
                             r"(?:runs/[1-9][0-9]*(?:/attempts/[1-9][0-9]*|/artifacts\?per_page=100)?|"
                             r"artifacts/[1-9][0-9]*(?:/zip)?)", endpoint) is not None,
                "unsupported transport endpoint")
        require(time.monotonic() < self._deadline, "transport stage expired")
        self._check_native()
        with tempfile.TemporaryDirectory(prefix="armorer-gh-read-") as temporary:
            scratch = Path(temporary)
            env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8", "GH_HOST": "github.com",
                   "GH_PROMPT_DISABLED": "1", "GH_PAGER": "cat", "TMPDIR": str(scratch),
                   "HOME": str(scratch), "GH_CONFIG_DIR": str(scratch / "config"),
                   "XDG_CACHE_HOME": str(scratch / "cache")}
            if self._operator:
                env["HOME"] = str(Path.home())
                env.pop("GH_CONFIG_DIR")
            else:
                env["GH_TOKEN"] = self._token
            argv = [str(self.executable), "api", "--hostname", "github.com", "--method", "GET",
                    "--header", "Accept: application/vnd.github+json", "--header",
                    "X-GitHub-Api-Version: " + API_VERSION, endpoint]
            process = subprocess.Popen(argv, cwd=scratch, env=env, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            deadline = min(self._deadline, time.monotonic() + 60)
            counts = {"stdout": 0, "stderr": 0}
            try:
                with destination.open("xb") as output, selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
                    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
                    while selector.get_map():
                        require(time.monotonic() < deadline, "native transport timed out")
                        for key, _ in selector.select(timeout=min(0.1, max(0, deadline - time.monotonic()))):
                            block = os.read(key.fileobj.fileno(), 65536)
                            if not block:
                                selector.unregister(key.fileobj)
                                continue
                            counts[key.data] += len(block)
                            require(counts[key.data] <= (limit if key.data == "stdout" else 1024 * 1024),
                                    "native transport output exceeded limit")
                            if key.data == "stdout":
                                output.write(block)
                    process.wait(timeout=max(0.001, deadline - time.monotonic()))
                    require(process.returncode == 0 and counts["stdout"] > 0, "native transport read failed")
                    output.flush()
                    os.fsync(output.fileno())
                destination.chmod(0o400)
            except (OSError, subprocess.SubprocessError) as error:
                raise Failure("native transport read failed") from error
            finally:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except PermissionError as error:
                        # macOS can deny signaling a group whose leader has just exited.
                        try:
                            process.wait(timeout=0.1)
                        except subprocess.TimeoutExpired:
                            raise Failure("native transport termination denied") from error
                process.wait()
                process.stdout.close()
                process.stderr.close()

    def json(self, endpoint: str) -> dict:
        """Parse bounded provider JSON only after an actual fixed-origin native read."""
        with tempfile.TemporaryDirectory(prefix="armorer-provider-json-") as temporary:
            path = Path(temporary) / "response.json"
            self._read(endpoint, path, MAX_JSON)
            result = parse_json(path.read_bytes())
            require(isinstance(result, dict), "provider response is not an object")
            return result

    def archive(self, repository: str, artifact_id: int, destination: Path) -> None:
        """Download only a validated numeric artifact ID from a fixed GitHub repository route."""
        self._read(f"repos/{repository}/actions/artifacts/{artifact_id}/zip", destination, MAX_ZIP)


@dataclass(frozen=True)
class ExpectedRun:
    """Independent controller intent; downloaded records may never supply these expectations."""
    repository: str
    repository_id: int
    head_commit: str
    source_commit: str
    head_branch: str
    event: str
    caller_path: str
    caller_workflow_id: int
    run_id: int
    run_attempt: int
    runtime_commit: str
    builder_path: str = ".github/workflows/rust-build-v3.yml"
    max_age_seconds: int = 3600

    def validate(self) -> None:
        """Reject ambiguous intent and unsupported scope before any provider or payload operation."""
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}",
                             self.repository) is not None, "invalid independent repository")
        require(all(type(value) is int and 0 < value <= 2**63 - 1 for value in
                    (self.repository_id, self.caller_workflow_id, self.run_id, self.run_attempt)),
                "invalid independent provider identity")
        require(all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value)
                    for value in (self.head_commit, self.source_commit, self.runtime_commit)),
                "independent source and runtime require immutable commits")
        require(isinstance(self.head_branch, str) and 0 < len(self.head_branch) <= 255 and
                not any(ord(char) < 33 or ord(char) == 127 for char in self.head_branch), "invalid expected branch")
        require(self.event in ("push", "workflow_dispatch", "pull_request"), "unsupported transport observation event")
        require(self.event == "pull_request" or self.source_commit == self.head_commit,
                "release observation source differs from provider head")
        require(re.fullmatch(r"\.github/workflows/[A-Za-z0-9_.-]+\.yml", self.caller_path) is not None and
                self.builder_path == ".github/workflows/rust-build-v3.yml", "unsupported expected workflow")
        require(type(self.max_age_seconds) is int and 0 < self.max_age_seconds <= 86400,
                "invalid transport freshness policy")


def _timestamp(value: str) -> int:
    """Accept one canonical UTC provider timestamp form, never booleans or local-time coercion."""
    require(isinstance(value, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value),
            "invalid provider timestamp")
    try:
        return int(datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
    except ValueError as error:
        raise Failure("invalid provider timestamp") from error


def _run(value: dict, expected: ExpectedRun, now: int) -> int:
    """Check exact latest/attempt identity and freshness without claiming producer-job authentication."""
    require(all(type(value.get(name)) is int and value[name] == wanted for name, wanted in
                (("id", expected.run_id), ("run_attempt", expected.run_attempt),
                 ("workflow_id", expected.caller_workflow_id))), "provider run or attempt mismatch")
    require(value.get("head_sha") == expected.head_commit and value.get("head_branch") == expected.head_branch and
            value.get("event") == expected.event and value.get("path") == expected.caller_path,
            "provider source, trigger or caller mismatch")
    for name in ("repository", "head_repository"):
        repository = value.get(name)
        require(isinstance(repository, dict) and type(repository.get("id")) is int and
                repository["id"] == expected.repository_id and repository.get("full_name") == expected.repository and
                repository.get("fork") is False, "provider repository or fork mismatch")
    require((value.get("status"), value.get("conclusion")) in (("completed", "success"), ("in_progress", None)),
            "provider run is failed, pending or unsupported")
    wanted = "brianluby/armorer-workflows/" + expected.builder_path + "@" + expected.runtime_commit
    referenced = value.get("referenced_workflows")
    require(isinstance(referenced, list) and 0 < len(referenced) <= 64, "missing bounded reusable workflow identities")
    prefix = "brianluby/armorer-workflows/" + expected.builder_path + "@"
    matches = [item for item in referenced if isinstance(item, dict) and
               isinstance(item.get("path"), str) and item["path"].startswith(prefix)]
    require(len(matches) == 1 and matches[0].get("path") == wanted and
            matches[0].get("sha") == expected.runtime_commit, "executing builder pin mismatch")
    start = _timestamp(value.get("run_started_at"))
    require(0 < start <= now and now - start <= expected.max_age_seconds, "provider attempt is stale or future")
    return start


def _artifact(value: dict, expected: ExpectedRun, name: str, start: int, now: int) -> dict:
    """Bind one provider storage object to the exact independent source/run/attempt upload window."""
    require(isinstance(value, dict) and type(value.get("id")) is int and 0 < value["id"] <= 2**63 - 1 and
            value.get("name") == name and value.get("expired") is False, "artifact identity, name or expiry mismatch")
    require(type(value.get("size_in_bytes")) is int and 0 < value["size_in_bytes"] <= MAX_ZIP and
            isinstance(value.get("digest"), str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value["digest"]),
            "missing bounded provider archive byte identity")
    run = value.get("workflow_run")
    require(isinstance(run, dict) and all(type(run.get(key)) is int and run[key] == wanted for key, wanted in
                (("id", expected.run_id), ("repository_id", expected.repository_id),
                 ("head_repository_id", expected.repository_id))) and
            run.get("head_sha") == expected.head_commit and run.get("head_branch") == expected.head_branch,
            "artifact belongs to another run or source")
    created, updated, expires = (_timestamp(value.get(key)) for key in ("created_at", "updated_at", "expires_at"))
    require(start <= created <= updated <= now < expires, "artifact is outside the exact attempt upload window")
    return {key: value[key] for key in ("id", "name", "expired", "size_in_bytes", "digest", "workflow_run",
                                      "created_at", "updated_at", "expires_at")}


def _listing(value: dict, expected: ExpectedRun, names: set[str], start: int, now: int) -> dict:
    """Require one complete bounded exact artifact set; pagination, duplicates and extras fail closed."""
    rows = value.get("artifacts")
    require(type(value.get("total_count")) is int and value["total_count"] == len(names) and
            isinstance(rows, list) and len(rows) == len(names), "incomplete or extra provider artifact set")
    result = {}
    ids = set()
    for row in rows:
        require(isinstance(row, dict) and row.get("name") in names and row["name"] not in result,
                "unexpected or duplicate provider artifact name")
        record = _artifact(row, expected, row["name"], start, now)
        require(record["id"] not in ids, "duplicate provider artifact ID")
        ids.add(record["id"])
        result[record["name"]] = record
    require(set(result) == names, "missing provider artifact")
    return result


def _unpack_provider_zip(path: Path, destination: Path, selection: dict) -> dict:
    """Read exactly five inert provider ZIP leaves; never execute or unpack a nested .crate/.bin payload."""
    names = _names(selection)
    size = path.stat().st_size
    require(size >= 22, "invalid provider ZIP")
    with path.open("rb") as stream:
        stream.seek(-22, os.SEEK_END)
        record = struct.unpack("<4s4H2LH", stream.read(22))
    magic, disk, central_disk, disk_count, count, central_size, offset, comment = record
    require(magic == b"PK\x05\x06" and disk == central_disk == comment == 0 and
            disk_count == count == 5 and 0 < central_size <= 65536 and offset + central_size == size - 22,
            "unsupported, ambiguous or unbounded provider ZIP directory")
    destination.mkdir(mode=0o700)
    identities = {}
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        require(len(entries) == 5 and {entry.filename for entry in entries} == set(names), "provider ZIP leaf set mismatch")
        for entry in entries:
            mode = entry.external_attr >> 16
            require(entry.orig_filename == entry.filename and not entry.is_dir() and not entry.flag_bits & 1 and
                    stat.S_IFMT(mode) in (0, stat.S_IFREG) and not entry.external_attr & 0x10 and
                    entry.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) and
                    0 < entry.file_size <= names[entry.filename], "unsafe provider ZIP member")
            output = destination / entry.filename
            digest = hashlib.sha256()
            total = 0
            with archive.open(entry) as incoming, output.open("xb") as outgoing:
                while block := incoming.read(65536):
                    total += len(block)
                    require(total <= names[entry.filename], "provider ZIP expansion exceeded limit")
                    digest.update(block)
                    outgoing.write(block)
                require(total == entry.file_size, "provider ZIP member size mismatch")
                outgoing.flush()
                os.fsync(outgoing.fileno())
            output.chmod(0o400)
            identities[entry.filename] = {"sha256": digest.hexdigest(), "size": total}
    return identities


@contextmanager
def collect_handoffs(api: QualifiedGhApi, expected: ExpectedRun, selections: list[dict]):
    """Yield a private live provider snapshot after preflight, digest verification and mutable rereads.

The snapshot is transport evidence only, never a credential permit. Callers must
separately check v3 semantics, whole SBOMs, qualified job evidence and protected
source/environment approval. No arbitrary JSON adapter may issue this result.
"""
    require(type(api) is QualifiedGhApi and type(expected) is ExpectedRun, "unqualified transport adapter or intent")
    expected.validate()
    require(isinstance(selections, list) and 0 < len(selections) <= MAX_SELECTIONS, "unsupported transport selection count")
    by_name = {}
    for selection in selections:
        _names(selection)
        name = selection["artifact_id"] + f"-handoff-v3-run-{expected.run_id}-attempt-{expected.run_attempt}"
        require(len(name) <= 255 and name not in by_name, "invalid or duplicate expected transport name")
        by_name[name] = selection
    route = f"repos/{expected.repository}/actions/runs/{expected.run_id}"
    now = int(time.time())
    latest = api.json(route)
    start = _run(latest, expected, now)
    attempt = api.json(route + f"/attempts/{expected.run_attempt}")
    require(_run(attempt, expected, now) == start, "latest and explicit attempt differ")
    records = _listing(api.json(route + "/artifacts?per_page=100"), expected, set(by_name), start, now)
    with tempfile.TemporaryDirectory(prefix="armorer-provider-handoff-") as temporary:
        root = Path(temporary)
        observations = {}
        directories = {}
        for name, selection in by_name.items():
            record = records[name]
            path = root / (str(record["id"]) + ".zip")
            api.archive(expected.repository, record["id"], path)
            identity = _identity(path, MAX_ZIP)
            require(identity == {"sha256": record["digest"][7:], "size": record["size_in_bytes"]},
                    "downloaded provider archive byte mismatch")
            directory = root / selection["artifact_id"]
            try:
                leaves = _unpack_provider_zip(path, directory, selection)
            except (zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError, NotImplementedError,
                    OSError, EOFError, zlib.error) as error:
                raise Failure("provider ZIP failed closed") from error
            observations[selection["artifact_id"]] = {"provider": record, "archive": identity, "leaves": leaves}
            directories[selection["artifact_id"]] = directory
        final_run = api.json(route)
        final_attempt = api.json(route + f"/attempts/{expected.run_attempt}")
        final_listing = api.json(route + "/artifacts?per_page=100")
        final_now = int(time.time())
        require(final_now >= now and time.monotonic() < api._deadline, "transport stage expired or clock reversed")
        require(_run(final_run, expected, final_now) == start and
                _run(final_attempt, expected, final_now) == start,
                "provider rerun changed the attempt")
        require(_listing(final_listing, expected, set(by_name), start, final_now) == records,
                "provider artifacts changed during download")
        receipt = {"schema_version": 1, "state": "provider-transport-observed", "authority": "github-rest-via-pinned-native-gh",
                   "gh_version": GH_VERSION, "gh_source_commit": GH_SOURCE, "gh_native": {
                       "sha256": GH_PINS[platform_target()][1], "size": GH_PINS[platform_target()][0]},
                   "authentication_mode": "operator-readonly-qualification" if api._operator else "isolated-workflow-token",
                   "repository": expected.repository, "head_commit": expected.head_commit,
                   "source_commit": expected.source_commit, "runtime_commit": expected.runtime_commit,
                   "run_id": expected.run_id, "run_attempt": expected.run_attempt,
                   "observed_at": final_now, "artifacts": observations, "signing_authorized": False,
                   "producer_job_authenticated": False, "cryptographic_release_authenticated": False}
        yield MappingProxyType(directories), receipt
