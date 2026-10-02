"""Read-only native source-control observations; never grant credential authority."""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import tempfile
import time
from urllib.parse import quote

from .common import Failure, require
from .transport_v1 import API_VERSION, QualifiedGhApi, _timestamp

MAX_CALLER = 128 * 1024


def _route(endpoint):
    """Permit fixed GitHub source/run routes only; artifacts, mutations and arbitrary origins fail."""
    matched = re.fullmatch(r"repos/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}(?:/actions/runs/[1-9][0-9]*(?:/attempts/[1-9][0-9]*)?|/git/(?:commits|trees|blobs|tags)/[0-9a-f]{40}|/git/ref/(?:heads|tags)/[A-Za-z0-9_./-]+|/pulls/[1-9][0-9]*|/collaborators/[A-Za-z0-9-]+/permission|/compare/[0-9a-f]{40}\.\.\.[0-9a-f]{40}\?per_page=1)?", endpoint)
    return matched is not None and ("/git/ref/" not in endpoint or _ref("refs/" + endpoint.split("/git/ref/", 1)[1]))


class SourceGhApi(QualifiedGhApi):
    """Explicit successor preserves v1 routes and qualifies the same pinned sterile native process."""
    def _read(self, endpoint: str, destination: Path, limit: int) -> None:
        """Stream fixed native GET output with hard byte/time bounds and discard all diagnostic text."""
        require(_route(endpoint), "unsupported source-control endpoint")
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


def _sha(value):
    """Admit only one immutable lower-case Git object identity."""
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def _ref(value):
    """Bound supported Git refs before URL encoding; reject aliases, controls and refspecs."""
    return (isinstance(value, str) and 0 < len(value) <= 255 and
            re.fullmatch(r"refs/(?:heads|tags)/[A-Za-z0-9_./-]+", value) is not None and
            all(part and not part.startswith(".") and not part.endswith((".", ".lock"))
                for part in value.split("/")) and ".." not in value)


@dataclass(frozen=True)
class SourceIntent:
    """Independent reviewed/platform intent; offered artifacts must never establish these values."""
    repository: str
    repository_id: int
    owner_id: int
    default_branch: str
    run_id: int
    run_attempt: int
    workflow_id: int
    caller_path: str
    caller_commit: str
    caller_sha256: str
    head_commit: str
    source_commit: str
    head_branch: str
    event: str
    ref: str
    actor_id: int
    actor_login: str
    triggering_actor_id: int
    triggering_actor_login: str
    referenced_workflows: tuple[tuple[str, str], ...] = ()
    pull_request: int | None = None
    base_commit: str | None = None
    base_branch: str | None = None
    max_age_seconds: int = 3600

    def validate(self):
        """Reject unsupported or ambiguous source/actor intent before any native provider read."""
        require(isinstance(self.repository, str) and re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", self.repository),
            "invalid source-control repository")
        require(all(type(value) is int and 0 < value <= 2**63 - 1 for value in
            (self.repository_id, self.owner_id, self.run_id, self.run_attempt, self.workflow_id,
             self.actor_id, self.triggering_actor_id)), "invalid source-control numeric identity")
        require(all(_sha(value) for value in (self.caller_commit, self.head_commit, self.source_commit)),
                "source-control immutable commit required")
        require(isinstance(self.caller_path, str) and re.fullmatch(r"\.github/workflows/[A-Za-z0-9_-][A-Za-z0-9_.-]*\.yml", self.caller_path)
                and ".." not in self.caller_path and isinstance(self.caller_sha256, str)
                and re.fullmatch(r"[0-9a-f]{64}", self.caller_sha256), "invalid independent caller identity")
        require(all(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", value)
                    for value in (self.actor_login, self.triggering_actor_login)), "invalid independent actor")
        require(isinstance(self.default_branch, str) and isinstance(self.head_branch, str) and
                _ref("refs/heads/" + self.default_branch) and _ref("refs/heads/" + self.head_branch),
                "invalid independent branch")
        require(type(self.max_age_seconds) is int and 0 < self.max_age_seconds <= 3600,
                "invalid source-control freshness")
        require(type(self.referenced_workflows) is tuple and len(self.referenced_workflows) <= 64 and all(
                    type(row) is tuple and len(row) == 2 and isinstance(row[0], str) and _sha(row[1]) and
                    re.fullmatch(r"brianluby/armorer-workflows/\.github/workflows/[A-Za-z0-9_.-]+\.yml@" + row[1], row[0])
                    for row in self.referenced_workflows) and
                len(set(self.referenced_workflows)) == len(self.referenced_workflows), "invalid independent reusable workflow set")
        require(self.event in ("pull_request", "push", "workflow_dispatch"), "unsupported source-control event")
        if self.event == "pull_request":
            require(type(self.pull_request) is int and 0 < self.pull_request <= 2**63 - 1 and
                    _sha(self.base_commit) and isinstance(self.base_branch, str) and
                    _ref("refs/heads/" + self.base_branch) and
                    self.ref == f"refs/pull/{self.pull_request}/merge" and
                    self.caller_commit == self.source_commit, "invalid independent PR merge intent")
        else:
            require(self.pull_request is self.base_commit is self.base_branch is None and _ref(self.ref) and
                    self.source_commit == self.head_commit and self.caller_commit == self.source_commit,
                    "invalid independent release source intent")
            require((self.event == "push" and self.ref.startswith("refs/tags/") and
                     re.fullmatch(r"refs/tags/v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", self.ref)) or
                    (self.event == "workflow_dispatch" and self.ref == "refs/heads/" + self.default_branch),
                    "unsupported release trigger or ref")
            require(self.head_branch == self.ref.split("/", 2)[2], "source-control branch or tag name mismatch")


def _repository(value, expected):
    """Authenticate the independently named non-fork repository and immutable owner ID."""
    require(isinstance(value, dict) and type(value.get("id")) is int and value["id"] == expected.repository_id and
            value.get("full_name") == expected.repository and value.get("fork") is False and
            isinstance(value.get("owner"), dict) and type(value["owner"].get("id")) is int and
            value["owner"]["id"] == expected.owner_id and
            value["owner"].get("login") == expected.repository.split("/")[0], "source-control repository mismatch")


def _actor(value, ident, login):
    """Bind an actor by numeric identity and exact login; renamed or substituted accounts fail."""
    require(isinstance(value, dict) and type(value.get("id")) is int and value["id"] == ident and
            value.get("login") == login and value.get("type") == "User", "source-control actor mismatch")


def _run(value, expected, now):
    """Require exact original/rerun actors, reusable pins and active/successful current attempt."""
    require(isinstance(value, dict) and all(type(value.get(key)) is int and value[key] == wanted for key, wanted in
            (("id", expected.run_id), ("run_attempt", expected.run_attempt), ("workflow_id", expected.workflow_id))) and
            value.get("path") == expected.caller_path and value.get("head_sha") == expected.head_commit and
            value.get("head_branch") == expected.head_branch and value.get("event") == expected.event,
            "source-control run or source mismatch")
    for name in ("repository", "head_repository"):
        _repository(value.get(name), expected)
    _actor(value.get("actor"), expected.actor_id, expected.actor_login)
    _actor(value.get("triggering_actor"), expected.triggering_actor_id, expected.triggering_actor_login)
    referenced = value.get("referenced_workflows", [])
    require(isinstance(referenced, list) and len(referenced) == len(expected.referenced_workflows) and
            all(isinstance(row, dict) for row in referenced), "source-control reusable set mismatch")
    actual = [(row.get("path"), row.get("sha")) for row in referenced]
    require(all(type(path) is str and _sha(sha) for path, sha in actual) and
            len(set(actual)) == len(actual) and set(actual) == set(expected.referenced_workflows),
            "source-control reusable identity mismatch")
    require((value.get("status"), value.get("conclusion")) in (("in_progress", None), ("completed", "success")),
            "source-control attempt not active or successful")
    start = _timestamp(value.get("run_started_at"))
    require(0 < start <= now and now - start <= expected.max_age_seconds, "source-control attempt stale or future")
    return start


def _commit(api, root, sha):
    """Read an exact immutable commit object and its bounded parent/tree identities."""
    value = api.json(root + "/git/commits/" + sha)
    require(value.get("sha") == sha and isinstance(value.get("tree"), dict) and _sha(value["tree"].get("sha")) and
            isinstance(value.get("parents"), list) and len(value["parents"]) <= 16 and
            all(isinstance(row, dict) and _sha(row.get("sha")) for row in value["parents"]),
            "source-control commit identity mismatch")
    return {"sha": sha, "tree": value["tree"]["sha"], "parents": [row["sha"] for row in value["parents"]]}


def _caller(api, root, expected):
    """Walk three exact regular Git tree entries, then verify bounded blob bytes against reviewed SHA-256."""
    tree = _commit(api, root, expected.caller_commit)["tree"]
    for index, name in enumerate(expected.caller_path.split("/")):
        value = api.json(root + "/git/trees/" + tree)
        rows = value.get("tree")
        require(value.get("sha") == tree and value.get("truncated") is False and isinstance(rows, list) and
                0 < len(rows) <= 4096 and all(isinstance(row, dict) and isinstance(row.get("path"), str)
                for row in rows), "source-control incomplete Git tree")
        selected = [row for row in rows if row["path"] == name]
        require(len(selected) == 1 and _sha(selected[0].get("sha")) and
                (selected[0].get("type"), selected[0].get("mode")) ==
                (("tree", "040000") if index < 2 else ("blob", "100644")), "source-control caller entry unsafe")
        tree = selected[0]["sha"]
    blob = api.json(root + "/git/blobs/" + tree)
    require(blob.get("sha") == tree and blob.get("encoding") == "base64" and type(blob.get("size")) is int and
            0 < blob["size"] <= MAX_CALLER and isinstance(blob.get("content"), str) and
            len(blob["content"]) <= MAX_CALLER * 2, "source-control caller blob unsupported")
    try:
        compact = blob["content"].replace("\n", "")
        data = base64.b64decode(compact, validate=True)
    except (ValueError, binascii.Error) as error:
        raise Failure("source-control caller encoding invalid") from error
    identity = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "git_blob": tree}
    require(base64.b64encode(data).decode() == compact and len(data) == blob["size"] and
            hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == tree and
            identity["sha256"] == expected.caller_sha256, "source-control reviewed caller bytes mismatch")
    return identity


def _resolve(api, root, ref):
    """Resolve an exact branch or bounded annotated-tag chain; cycles and non-commit leaves reject."""
    value = api.json(root + "/git/ref/" + quote(ref[5:], safe="/"))
    require(value.get("ref") == ref and isinstance(value.get("object"), dict), "source-control ref mismatch")
    obj = value["object"]
    chain = []
    for _ in range(9):
        require(isinstance(obj, dict) and _sha(obj.get("sha")) and obj["sha"] not in chain,
                "source-control tag cycle or object mismatch")
        if obj.get("type") == "commit":
            return {"ref": ref, "commit": obj["sha"], "tag_objects": chain}
        require(ref.startswith("refs/tags/") and obj.get("type") == "tag" and len(chain) < 8,
                "source-control unsupported ref object")
        chain.append(obj["sha"])
        tag = api.json(root + "/git/tags/" + obj["sha"])
        require(tag.get("sha") == obj["sha"], "source-control annotated tag identity mismatch")
        obj = tag.get("object")
    raise Failure("source-control tag chain exceeded bound")


def _snapshot(api, expected, now):
    """Collect independently bound source, actor permissions, caller bytes and mutable refs without execution."""
    root = "repos/" + expected.repository
    repository = api.json(root)
    _repository(repository, expected)
    require(repository.get("default_branch") == expected.default_branch and repository.get("archived") is False and
            repository.get("disabled") is False, "source-control repository unavailable or default changed")
    route = root + f"/actions/runs/{expected.run_id}"
    starts = [_run(api.json(path), expected, now) for path in (route, route + f"/attempts/{expected.run_attempt}")]
    require(starts[0] == starts[1], "source-control attempt start changed")
    permissions = {}
    for ident, login in ((expected.actor_id, expected.actor_login), (expected.triggering_actor_id, expected.triggering_actor_login)):
        row = api.json(root + "/collaborators/" + login + "/permission")
        _actor(row.get("user"), ident, login)
        require(row.get("permission") in ("write", "admin"), "source-control actor lacks current write permission")
        permissions[login] = row["permission"]
    caller = _caller(api, root, expected)
    source = _commit(api, root, expected.source_commit)
    if expected.event == "pull_request":
        pull = api.json(root + f"/pulls/{expected.pull_request}")
        require(type(pull.get("number")) is int and pull["number"] == expected.pull_request and
                pull.get("state") == "open" and pull.get("merge_commit_sha") == expected.source_commit,
                "source-control current PR merge mismatch")
        for side, sha, branch in (("head", expected.head_commit, expected.head_branch),
                                  ("base", expected.base_commit, expected.base_branch)):
            row = pull.get(side)
            require(isinstance(row, dict) and row.get("sha") == sha and row.get("ref") == branch,
                    "source-control PR head or base changed")
            _repository(row.get("repo"), expected)
        require(source["parents"] == [expected.base_commit, expected.head_commit], "source-control PR merge parents mismatch")
        reference = {"ref": expected.ref, "commit": expected.source_commit, "head": expected.head_commit,
                     "base": expected.base_commit, "base_branch": expected.base_branch}
        default = None
    else:
        reference = _resolve(api, root, expected.ref)
        require(reference["commit"] == expected.source_commit, "source-control release ref moved")
        default = _resolve(api, root, "refs/heads/" + expected.default_branch)
        if expected.event == "workflow_dispatch":
            require(default["commit"] == expected.source_commit, "source-control dispatch default moved")
        comparison = api.json(root + "/compare/" + expected.source_commit + "..." + default["commit"] + "?per_page=1")
        require(comparison.get("status") in ("ahead", "identical") and
                isinstance(comparison.get("base_commit"), dict) and comparison["base_commit"].get("sha") == expected.source_commit and
                isinstance(comparison.get("merge_base_commit"), dict) and comparison["merge_base_commit"].get("sha") == expected.source_commit,
                "source-control release source not default ancestor")
    return {"run_started_at": starts[0], "source": source, "caller": caller,
            "actors": permissions, "reference": reference, "default": default}


def observe_source(api: SourceGhApi, expected: SourceIntent):
    """Reread all mutable prerequisites and yield a short-lived audit observation, never a signing permit."""
    require(type(api) is SourceGhApi and type(expected) is SourceIntent, "source-control adapter or intent invalid")
    expected.validate()
    now = int(time.time())
    before = _snapshot(api, expected, now)
    final_now = int(time.time())
    require(final_now >= now and time.monotonic() < api._deadline, "source-control stage or clock expired")
    after = _snapshot(api, expected, final_now)
    final_now = int(time.time())
    require(final_now >= now and time.monotonic() < api._deadline and
            final_now - before["run_started_at"] <= expected.max_age_seconds and before == after,
            "source-control mutable prerequisites changed or expired")
    route = "repos/" + expected.repository + f"/actions/runs/{expected.run_id}"
    for path in (route, route + f"/attempts/{expected.run_attempt}"):
        require(_run(api.json(path), expected, int(time.time())) == before["run_started_at"],
                "source-control final attempt changed")
    final_now = int(time.time())
    require(final_now >= now and final_now - before["run_started_at"] <= expected.max_age_seconds and
            time.monotonic() < api._deadline, "source-control final freshness expired")
    return {"schema_version": 1, "state": "source-control-observed", "repository": expected.repository,
            "repository_id": expected.repository_id, "run_id": expected.run_id, "run_attempt": expected.run_attempt,
            "event": expected.event, "observed_at": final_now, "source_control": after,
            "authentication_mode": "operator-readonly-qualification" if api._operator else "isolated-workflow-token",
            "source_provider_authenticated": True, "producer_job_authenticated": False,
            "protected_ref_authenticated": False, "protected_environment_authenticated": False,
            "production_catalog_accepted": False, "cryptographic_release_authenticated": False,
            "signing_authorized": False, "publication_authorized": False}
