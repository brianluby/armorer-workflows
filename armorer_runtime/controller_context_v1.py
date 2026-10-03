"""Read-only current-job and environment observations; no signing or publication authority."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import tempfile
import time

from .common import Failure, require
from .source_transport_v1 import SourceGhApi, SourceIntent, _run, observe_source
from .transport_v1 import API_VERSION, QualifiedGhApi, _timestamp

MAX_JOBS = 1000
RUNNERS = ("ubuntu-24.04", "ubuntu-24.04-arm", "macos-15")


def _route(endpoint):
    """Admit only fixed native GET routes for jobs, attempts and the two release environments."""
    root = r"repos/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}"
    tail = (r"(?:/actions/jobs/[1-9][0-9]*|/actions/runs/[1-9][0-9]*(?:/attempts/[1-9][0-9]*(?:/jobs\?per_page=100&page=(?:[1-9]|10))?)?"
            r"|/environments/release-(?:signing|publish)(?:/deployment-branch-policies\?per_page=100&page=1)?)")
    return isinstance(endpoint, str) and re.fullmatch(root + tail, endpoint) is not None


class ControllerGhApi(QualifiedGhApi):
    """Versioned route extension with the same pinned native bytes and isolated read-token process."""
    def _read(self, endpoint: str, destination: Path, limit: int) -> None:
        """Stream fixed native GET output with hard byte/time bounds and discard all diagnostic text."""
        require(_route(endpoint), "unsupported controller endpoint")
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


def _id(value):
    """Accept positive numeric provider IDs without booleans, floats or string coercion."""
    return type(value) is int and 0 < value <= 2**63 - 1


def _text(value, limit=255):
    """Bound opaque display identities while rejecting controls and leading/trailing whitespace."""
    return (type(value) is str and 0 < len(value) <= limit and value == value.strip() and
            all(ord(char) >= 32 and ord(char) != 127 for char in value))


@dataclass(frozen=True)
class JobIntent:
    """Reviewed source and exact static job name; token claims and artifacts cannot choose the job."""
    source: SourceIntent
    workflow_name: str
    job_name: str
    runner_label: str
    qualification_only: bool = False

    def validate(self):
        """Validate independent mapping scope before any source or job provider read."""
        require(type(self.source) is SourceIntent and type(self.qualification_only) is bool,
                "invalid controller source intent")
        self.source.validate()
        require(_text(self.workflow_name) and _text(self.job_name) and self.runner_label in RUNNERS,
                "unsupported controller job or native runner")
        require(self.qualification_only or self.source.event in ("push", "workflow_dispatch"),
                "unsafe controller producer trigger")


@dataclass(frozen=True)
class EnvironmentIntent:
    """Independently reviewed environment identity and exact personal-repository controls."""
    name: str
    environment_id: int
    node_id: str
    reviewer_ids: tuple[int, ...]
    default_branch: str
    wait_minutes: int = 0

    def validate(self, source):
        """Reject unsupported policies, teams and implicit identity discovery before provider access."""
        require(self.name in ("release-signing", "release-publish") and _id(self.environment_id) and
                _text(self.node_id) and re.fullmatch(r"[A-Za-z0-9_+=/-]+", self.node_id) is not None,
                "invalid independent environment identity")
        require(type(self.reviewer_ids) is tuple and 1 <= len(self.reviewer_ids) <= 6 and
                all(_id(value) for value in self.reviewer_ids) and
                len(set(self.reviewer_ids)) == len(self.reviewer_ids), "invalid independent reviewers")
        require(self.default_branch == source.default_branch and type(self.wait_minutes) is int and
                0 <= self.wait_minutes <= 43200, "unsupported independent environment policy")


def _jobs(api, expected):
    """Read every bounded attempt page before selecting one unique reviewed job name."""
    source = expected.source
    root = "repos/" + source.repository + f"/actions/runs/{source.run_id}/attempts/{source.run_attempt}/jobs"
    rows, total = [], None
    for page in range(1, 11):
        value = api.json(root + f"?per_page=100&page={page}")
        count, jobs = value.get("total_count"), value.get("jobs")
        require(type(count) is int and 0 < count <= MAX_JOBS and (total is None or total == count) and
                type(jobs) is list and len(jobs) == min(100, count - len(rows)),
                "controller job listing incomplete or changed")
        total = count
        for job in jobs:
            require(type(job) is dict and _id(job.get("id")) and _text(job.get("name")) and
                    all(type(job.get(key)) is int and job[key] == wanted for key, wanted in
                        (("run_id", source.run_id), ("run_attempt", source.run_attempt))) and
                    job.get("head_sha") == source.head_commit and job.get("head_branch") == source.head_branch and
                    job.get("workflow_name") == expected.workflow_name, "controller attempt job identity mismatch")
        rows.extend(jobs)
        if len(rows) == total:
            break
    require(len(rows) == total and len({job["id"] for job in rows}) == total,
            "controller job listing ambiguous or duplicated")
    selected = [job for job in rows if job["name"] == expected.job_name]
    require(len(selected) == 1, "controller intended job missing or ambiguous")
    return selected[0], sorted((job["id"], job["name"]) for job in rows)


def _job(value, expected, now, run_started):
    """Bind one active attempt job and parse its separate canonical check-run identity."""
    source = expected.source
    require(type(value) is dict and _id(value.get("id")) and
            all(type(value.get(key)) is int and value[key] == wanted for key, wanted in
                (("run_id", source.run_id), ("run_attempt", source.run_attempt))) and
            value.get("head_sha") == source.head_commit and value.get("head_branch") == source.head_branch and
            value.get("workflow_name") == expected.workflow_name and value.get("name") == expected.job_name,
            "controller intended job identity mismatch")
    job_id = value["id"]
    origin = "https://api.github.com/repos/" + source.repository
    require(value.get("url") == origin + f"/actions/jobs/{job_id}" and
            value.get("run_url") == origin + f"/actions/runs/{source.run_id}", "controller intended job URL mismatch")
    check_url = value.get("check_run_url")
    match = re.fullmatch(re.escape(origin) + r"/check-runs/([1-9][0-9]{0,18})", check_url) if type(check_url) is str else None
    require(match is not None and _id(int(match[1])), "controller check-run identity unavailable")
    require(value.get("status") == "in_progress" and value.get("conclusion") is None and
            value.get("completed_at") is None, "controller intended job is not active")
    started = _timestamp(value.get("started_at"))
    require(run_started <= started <= now and now - started <= source.max_age_seconds,
            "controller intended job stale or future")
    require(value.get("labels") == [expected.runner_label] and _id(value.get("runner_id")) and
            _text(value.get("runner_name")) and type(value.get("runner_group_id")) is int and
            value["runner_group_id"] == 0 and value.get("runner_group_name") == "GitHub Actions",
            "controller native runner metadata mismatch")
    return {"job_id": job_id, "check_run_id": int(match[1]), "name": expected.job_name,
            "workflow_name": expected.workflow_name, "head_commit": source.head_commit,
            "source_commit": source.source_commit, "started_at": started,
            "runner_label": expected.runner_label, "runner_id": value["runner_id"],
            "runner_name": value["runner_name"], "runner_group_id": 0}


def _environment(api, source, expected):
    """Observe exact required controls without treating configuration as current-attempt approval."""
    root = "repos/" + source.repository + "/environments/" + expected.name
    row = api.json(root)
    require(type(row.get("id")) is int and row["id"] == expected.environment_id and
            row.get("node_id") == expected.node_id and row.get("name") == expected.name and
            row.get("url") == "https://api.github.com/" + root, "controller environment identity mismatch")
    rules = row.get("protection_rules")
    kinds = {"required_reviewers", "branch_policy"} | ({"wait_timer"} if expected.wait_minutes else set())
    require(type(rules) is list and len(rules) == len(kinds) and all(type(rule) is dict and
            _id(rule.get("id")) and rule.get("type") in kinds for rule in rules) and
            len({rule["id"] for rule in rules}) == len(rules) and
            {rule["type"] for rule in rules} == kinds, "controller environment controls unsupported or missing")
    reviewers = next(rule for rule in rules if rule["type"] == "required_reviewers")
    users = reviewers.get("reviewers")
    require(reviewers.get("prevent_self_review") is True and type(users) is list and
            len(users) == len(expected.reviewer_ids) and all(type(user) is dict and user.get("type") == "User" and
            type(user.get("reviewer")) is dict and _id(user["reviewer"].get("id")) and
            user["reviewer"].get("type") == "User" for user in users) and
            sorted(user["reviewer"]["id"] for user in users) == sorted(expected.reviewer_ids),
            "controller required reviewers differ or self review allowed")
    if expected.wait_minutes:
        timer = next(rule for rule in rules if rule["type"] == "wait_timer")
        require(type(timer.get("wait_timer")) is int and timer["wait_timer"] == expected.wait_minutes,
                "controller environment wait timer mismatch")
    require(row.get("deployment_branch_policy") == {"protected_branches": False, "custom_branch_policies": True},
            "controller environment deployment restrictions mismatch")
    policies = api.json(root + "/deployment-branch-policies?per_page=100&page=1")
    branches = policies.get("branch_policies")
    require(type(policies.get("total_count")) is int and policies["total_count"] == 2 and
            type(branches) is list and len(branches) == 2 and
            all(type(branch) is dict and _id(branch.get("id")) and type(branch.get("type")) is str and
                type(branch.get("name")) is str for branch in branches) and
            len({branch["id"] for branch in branches}) == 2 and
            {(branch["type"], branch["name"]) for branch in branches} ==
                {("branch", expected.default_branch), ("tag", "v*")},
            "controller environment exact branch or tag policies mismatch")
    bypass = row.get("can_admins_bypass")
    require("can_admins_bypass" not in row or type(bypass) is bool, "controller admin bypass value unsupported")
    # This field is not guaranteed by the documented REST contract. Absence is unknown.
    bypass_state = "unknown" if "can_admins_bypass" not in row else "disabled" if bypass else "configured"
    controls = {"rule_ids": sorted((rule["type"], rule["id"]) for rule in rules),
                "reviewer_ids": sorted(expected.reviewer_ids), "prevent_self_review": True,
                "wait_minutes": expected.wait_minutes,
                "branch_policies": sorted((branch["type"], branch["name"], branch["id"]) for branch in branches),
                "admin_bypass_state": bypass_state}
    digest = hashlib.sha256(json.dumps(controls, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"name": expected.name, "id": expected.environment_id, "node_id": expected.node_id,
            "controls": controls, "configuration_sha256": digest,
            "state": bypass_state, "current_attempt_approval": "unsupported",
            "effective_enforcement": "unsupported"}


def _active_run(value, source, now):
    """Require a currently active run as well as the complete source/attempt identity."""
    started = _run(value, source, now)
    require(value.get("status") == "in_progress" and value.get("conclusion") is None,
            "controller intended run is not active")
    return started


def _snapshot(api, expected, environment, now):
    """Bind latest run, explicit attempt, complete job listing and fresh direct job metadata."""
    source = expected.source
    root = "repos/" + source.repository + f"/actions/runs/{source.run_id}"
    starts = [_active_run(api.json(route), source, now) for route in (root, root + f"/attempts/{source.run_attempt}")]
    require(starts[0] == starts[1], "controller attempt start changed")
    selected, listing = _jobs(api, expected)
    mapped = _job(selected, expected, now, starts[0])
    direct = _job(api.json("repos/" + source.repository + f"/actions/jobs/{mapped['job_id']}"),
                  expected, now, starts[0])
    require(mapped == direct, "controller intended job changed between listing and direct read")
    return {"run_started_at": starts[0], "job": mapped, "attempt_jobs": listing,
            "environment": None if environment is None else _environment(api, source, environment)}


def observe_controller(source_api: SourceGhApi, api: ControllerGhApi, expected: JobIntent,
                       environment: EnvironmentIntent | None = None):
    """Join source observations and independently mapped job context; serialized receipts grant no authority."""
    require(type(source_api) is SourceGhApi and type(api) is ControllerGhApi and type(expected) is JobIntent,
            "invalid controller adapter or intent")
    expected.validate()
    require(source_api._operator == api._operator, "controller authentication modes differ")
    if environment is not None:
        require(type(environment) is EnvironmentIntent and not expected.qualification_only,
                "protected controls require release intent")
        environment.validate(expected.source)
    start = int(time.time())
    source_before = observe_source(source_api, expected.source)
    before = _snapshot(api, expected, environment, int(time.time()))
    after = _snapshot(api, expected, environment, int(time.time()))
    source_after = observe_source(source_api, expected.source)
    now = int(time.time())
    require(now >= start and before == after and source_before["source_control"] == source_after["source_control"] and
            before["run_started_at"] == source_after["source_control"]["run_started_at"] and
            time.monotonic() < min(api._deadline, source_api._deadline) and
            now - before["run_started_at"] <= expected.source.max_age_seconds,
            "controller prerequisites changed or expired")
    # Re-read the active job after the final complete source preflight.
    direct = api.json("repos/" + expected.source.repository + f"/actions/jobs/{after['job']['job_id']}")
    require(_job(direct, expected, int(time.time()), before["run_started_at"]) == after["job"],
            "controller final intended job changed")
    root = "repos/" + expected.source.repository + f"/actions/runs/{expected.source.run_id}"
    for route in (root, root + f"/attempts/{expected.source.run_attempt}"):
        require(_active_run(api.json(route), expected.source, int(time.time())) == before["run_started_at"],
                "controller final attempt changed")
    if environment is not None:
        require(_environment(api, expected.source, environment) == after["environment"],
                "controller final environment changed")
    final_now = int(time.time())
    require(final_now >= now and final_now - before["run_started_at"] <= expected.source.max_age_seconds and
            time.monotonic() < min(api._deadline, source_api._deadline), "controller final freshness expired")
    return {"schema_version": 1, "state": "controller-context-observed", "observed_at": final_now,
            "repository": expected.source.repository, "repository_id": expected.source.repository_id,
            "run_id": expected.source.run_id, "run_attempt": expected.source.run_attempt,
            "event": expected.source.event, "source_control": source_after["source_control"],
            "controller": after, "authentication_mode": source_after["authentication_mode"],
            "candidate_qualification_only": expected.qualification_only,
            "source_provider_authenticated": True, "current_job_mapping_observed": True,
            "producer_job_authenticated": False, "protected_ref_authenticated": False,
            "protected_environment_authenticated": False, "production_catalog_accepted": False,
            "cryptographic_release_authenticated": False, "signing_authorized": False,
            "publication_authorized": False}
