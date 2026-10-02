"""Fixed native provider collection of seven-leaf unsigned policy observations, without signing authority."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import tempfile
import time
from types import MappingProxyType
import zipfile
import zlib

from . import common, policy_v1 as policy
from .common import Failure, require
from .transport_v1 import (
    GH_PINS, GH_SOURCE, GH_VERSION, MAX_ZIP, QualifiedGhApi,
    _artifact, _identity, _listing, _timestamp, platform_target,
)

MAX_SELECTIONS = 64
POLICY_WORKFLOW = ".github/workflows/rust-policy-v1.yml"


@dataclass(frozen=True)
class ExpectedPolicyRun:
    """Independent controller intent; source merge/tree ancestry must be checked before construction.

The provider run head identifies a PR head, while the report source identifies its
merge checkout. This collector compares the supplied identities but cannot prove
Git ancestry from run/artifact metadata. It never supplies a credential permit.
"""

    repository: str
    repository_id: int
    head_commit: str
    source_commit: str
    head_branch: str
    event: str
    ref: str
    caller_path: str
    caller_workflow_id: int
    run_id: int
    run_attempt: int
    runtime_commit: str
    max_age_seconds: int = 3600

    def validate(self) -> None:
        """Reject ambiguous independent intent before provider calls or report decoding."""
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}",
                             self.repository) is not None, "invalid independent policy repository")
        require(all(type(value) is int and 0 < value <= 2**63 - 1 for value in
                    (self.repository_id, self.caller_workflow_id, self.run_id, self.run_attempt)),
                "invalid independent policy provider identity")
        policy.context(self.context())
        require(isinstance(self.head_commit, str) and re.fullmatch(r"[0-9a-f]{40}", self.head_commit) is not None and
                isinstance(self.head_branch, str) and 0 < len(self.head_branch) <= 255 and
                not any(ord(char) < 33 or ord(char) == 127 for char in self.head_branch),
                "invalid independent policy head")
        require(isinstance(self.caller_path, str) and
                re.fullmatch(r"\.github/workflows/[A-Za-z0-9_.-]+\.yml", self.caller_path) is not None,
                "invalid independent policy caller")
        require(type(self.max_age_seconds) is int and 0 < self.max_age_seconds <= 3600,
                "invalid policy transport freshness")
        require((self.event == "pull_request" and re.fullmatch(r"refs/pull/[1-9][0-9]*/merge", self.ref) is not None) or
                (self.event in ("push", "workflow_dispatch") and self.source_commit == self.head_commit and
                 self.ref in ("refs/heads/" + self.head_branch, "refs/tags/" + self.head_branch)),
                "policy source/ref/event mismatch")

    def context(self) -> dict:
        """Return only independently supplied report context, never values from an offered envelope."""
        return {"source": {"repository": self.repository, "commit": self.source_commit},
                "runtime_commit": self.runtime_commit, "run_id": str(self.run_id),
                "run_attempt": str(self.run_attempt), "event": self.event, "ref": self.ref}


def _run(value: dict, expected: ExpectedPolicyRun, now: int) -> int:
    """Bind a completed successful standalone policy caller to its exact reusable pin and attempt."""
    require(all(type(value.get(key)) is int and value[key] == wanted for key, wanted in
                (("id", expected.run_id), ("run_attempt", expected.run_attempt),
                 ("workflow_id", expected.caller_workflow_id))), "policy provider run/attempt mismatch")
    require(value.get("head_sha") == expected.head_commit and value.get("head_branch") == expected.head_branch and
            value.get("event") == expected.event and value.get("path") == expected.caller_path and
            value.get("status") == "completed" and value.get("conclusion") == "success",
            "policy provider source/caller/result mismatch")
    for key in ("repository", "head_repository"):
        repository = value.get(key)
        require(isinstance(repository, dict) and type(repository.get("id")) is int and
                repository["id"] == expected.repository_id and repository.get("full_name") == expected.repository and
                repository.get("fork") is False, "policy provider repository/fork mismatch")
    references = value.get("referenced_workflows")
    require(isinstance(references, list) and len(references) == 1 and isinstance(references[0], dict) and
            references[0].get("path") == "brianluby/armorer-workflows/" + POLICY_WORKFLOW + "@" + expected.runtime_commit and
            references[0].get("sha") == expected.runtime_commit, "policy reusable workflow pin mismatch")
    if expected.event == "pull_request":
        requests = value.get("pull_requests")
        number = int(expected.ref.split("/")[2])
        require(isinstance(requests, list) and len(requests) == 1 and isinstance(requests[0], dict) and
                type(requests[0].get("number")) is int and requests[0]["number"] == number,
                "policy pull request ref mismatch")
        head = requests[0].get("head")
        require(isinstance(head, dict) and head.get("sha") == expected.head_commit and head.get("ref") == expected.head_branch and
                isinstance(head.get("repo"), dict) and type(head["repo"].get("id")) is int and
                head["repo"]["id"] == expected.repository_id, "policy pull request head mismatch")
    started = _timestamp(value.get("run_started_at"))
    require(0 < started <= now and now - started <= expected.max_age_seconds, "policy provider attempt expired or future")
    return started


def _names(selection: dict) -> dict[str, int]:
    """Require a safe independent native selection and exactly seven bounded report leaves."""
    require(isinstance(selection, dict) and selection.get("target") in common.RUNNERS and
            selection.get("runner") == common.RUNNERS[selection["target"]] and selection.get("toolchain") == "1.95.0" and
            all(isinstance(selection.get(key), str) and common.IDENTIFIER.fullmatch(selection[key])
                for key in ("id", "feature_set")) and
            selection.get("artifact_id") == selection["id"] + "--" + selection["target"] + "--" + selection["feature_set"] and
            len(selection["artifact_id"]) <= 160, "invalid independent policy selection")
    return {name: policy.MAX_DATABASE if name == "advisory-db.json" else policy.MAX_REPORT
            for name in policy.REPORT_NAMES | {"policy-v1.json"}}


def _unpack(path: Path, destination: Path, selection: dict) -> dict:
    """Decode only seven regular inert leaves after caller-authenticated whole ZIP identity checks."""
    names = _names(selection)
    size = path.stat().st_size
    require(size >= 22, "invalid policy provider ZIP")
    with path.open("rb") as incoming:
        incoming.seek(-22, os.SEEK_END)
        magic, disk, central_disk, disk_count, count, central_size, offset, comment = struct.unpack("<4s4H2LH", incoming.read(22))
    require(magic == b"PK\x05\x06" and disk == central_disk == comment == 0 and disk_count == count == 7 and
            0 < central_size <= 65536 and offset + central_size == size - 22,
            "unsupported policy provider ZIP directory")
    destination.mkdir(mode=0o700)
    identities = {}
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        require(len(entries) == 7 and {entry.filename for entry in entries} == set(names) and archive.comment == b"",
                "policy provider ZIP leaf mismatch")
        for entry in entries:
            require(entry.orig_filename == entry.filename and not entry.is_dir() and not entry.flag_bits & 1 and
                    stat.S_IFMT(entry.external_attr >> 16) in (0, stat.S_IFREG) and not entry.external_attr & 0x10 and
                    entry.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) and
                    0 < entry.file_size <= names[entry.filename], "unsafe policy provider ZIP member")
            digest = hashlib.sha256()
            total = 0
            destination_file = destination / entry.filename
            with archive.open(entry) as incoming, destination_file.open("xb") as outgoing:
                while block := incoming.read(65536):
                    total += len(block)
                    require(total <= names[entry.filename], "policy ZIP expansion exceeded bound")
                    digest.update(block)
                    outgoing.write(block)
                require(total == entry.file_size, "policy ZIP member size mismatch")
                outgoing.flush()
                os.fsync(outgoing.fileno())
            destination_file.chmod(0o400)
            identities[entry.filename] = {"sha256": digest.hexdigest(), "size": total}
    return identities


@contextmanager
def collect_policy(api: QualifiedGhApi, expected: ExpectedPolicyRun, selections: list[dict], source_inputs: dict,
                   runtime_inputs: dict, catalog: dict, project_policy: dict):
    """Yield a private complete current snapshot after native provider and independent semantic checks.

Source expectations, merge ancestry and catalog trust belong to an independent
controller. Provider storage proof and matching unsigned reports never identify
the writer job, authenticate release signatures or permit signing credentials.
The private directories cease to exist when this context exits.
"""
    require(type(api) is QualifiedGhApi and type(expected) is ExpectedPolicyRun, "unqualified policy transport adapter/intent")
    expected.validate()
    require(isinstance(selections, list) and 0 < len(selections) <= MAX_SELECTIONS, "unsupported policy selection count")
    by_name = {}
    for selection in selections:
        _names(selection)
        name = f"policy-v1-{selection['artifact_id']}-{expected.run_id}-{expected.run_attempt}"
        require(len(name) <= 255 and name not in by_name, "duplicate or oversized policy artifact name")
        by_name[name] = selection
    route = f"repos/{expected.repository}/actions/runs/{expected.run_id}"
    now = int(time.time())
    start = _run(api.json(route), expected, now)
    require(_run(api.json(route + f"/attempts/{expected.run_attempt}"), expected, now) == start,
            "policy latest and explicit attempt differ")
    records = _listing(api.json(route + "/artifacts?per_page=100"), expected, set(by_name), start, now)
    with tempfile.TemporaryDirectory(prefix="armorer-provider-policy-") as temporary:
        root = Path(temporary)
        directories = {}
        observations = {}
        oldest = None
        for name, selection in by_name.items():
            record = records[name]
            require(_artifact(api.json(f"repos/{expected.repository}/actions/artifacts/{record['id']}"),
                              expected, name, start, int(time.time())) == record, "policy artifact detail changed")
            archive = root / (str(record["id"]) + ".zip")
            api.archive(expected.repository, record["id"], archive)
            identity = _identity(archive, MAX_ZIP)
            require(identity == {"sha256": record["digest"][7:], "size": record["size_in_bytes"]},
                    "policy provider archive bytes mismatch")
            directory = root / selection["artifact_id"]
            try:
                leaves = _unpack(archive, directory, selection)
            except (zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError, NotImplementedError, OSError, EOFError, zlib.error) as error:
                raise Failure("policy provider ZIP failed closed") from error
            envelope = policy.verify(directory, expected.context(), selection, source_inputs, runtime_inputs, catalog, project_policy)
            require(start <= envelope["observed"]["started_at"] <= envelope["observed"]["finished_at"] <= _timestamp(record["created_at"]),
                    "policy observation is outside the exact upload window")
            directories[selection["artifact_id"]] = directory
            observations[selection["artifact_id"]] = {"provider": record, "archive": identity, "leaves": leaves,
                                                       "checks": envelope["checks"]}
            oldest = envelope["observed"]["started_at"] if oldest is None else min(oldest, envelope["observed"]["started_at"])
        final_run = api.json(route)
        final_attempt = api.json(route + f"/attempts/{expected.run_attempt}")
        final_listing = api.json(route + "/artifacts?per_page=100")
        final_now = int(time.time())
        require(final_now >= now and time.monotonic() < api._deadline, "policy transport clock reversed or expired")
        require(_run(final_run, expected, final_now) == start and _run(final_attempt, expected, final_now) == start,
                "policy provider attempt changed")
        require(_listing(final_listing, expected, set(by_name), start, final_now) == records,
                "policy provider artifacts changed")
        for selection in selections:
            policy.verify(directories[selection["artifact_id"]], expected.context(), selection, source_inputs,
                          runtime_inputs, catalog, project_policy)
        end_now = int(time.time())
        require(end_now >= final_now and time.monotonic() < api._deadline and oldest is not None and
                end_now - oldest <= expected.max_age_seconds, "policy snapshot expired during final verification")
        receipt = {"schema_version": 1, "state": "policy-provider-transport-observed",
                   "authority": "github-rest-via-pinned-native-gh", "gh_version": GH_VERSION, "gh_source_commit": GH_SOURCE,
                   "gh_native": {"sha256": GH_PINS[platform_target()][1], "size": GH_PINS[platform_target()][0]},
                   "authentication_mode": "operator-readonly-qualification" if api._operator else "isolated-workflow-token",
                   **expected.context(), "head_commit": expected.head_commit, "caller_path": expected.caller_path,
                   "caller_workflow_id": expected.caller_workflow_id, "repository_id": expected.repository_id,
                   "max_age_seconds": expected.max_age_seconds,
                   "observed_at": end_now, "artifacts": observations, "signing_authorized": False,
                   "producer_job_authenticated": False, "cryptographic_release_authenticated": False}
        yield MappingProxyType(directories), receipt
