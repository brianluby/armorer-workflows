"""Native GET-only release prerequisite observations; no signing or publication grant.

The independent repository identity precedes every capability read. HTTP status
is retained privately so missing and denied capabilities cannot become success.
Environment configuration is never evidence of current-attempt approval.
"""
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

from .build import BuildError, parse_json
from .common import Failure, require
from .controller_context_v1 import EnvironmentIntent, _environment, _id, _text
from .transport_v1 import API_VERSION, MAX_JSON, QualifiedGhApi

MAX_HEADERS = 65536
ENVIRONMENTS = ("release-signing", "release-publish")


def _route(endpoint):
    """Admit repository metadata and only the named release prerequisite GET routes."""
    return type(endpoint) is str and re.fullmatch(
        r"repos/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}"
        r"(?:/immutable-releases|/environments/release-(?:signing|publish)"
        r"(?:/deployment-branch-policies\?per_page=100&page=1)?)?", endpoint) is not None


@dataclass(frozen=True)
class NativeResponse:
    """One bounded parsed native HTTP response, never serialized as authorization."""
    status: int
    body: dict


def _parse_response(data, exit_code):
    """Reject ambiguous headers, JSON and process outcomes without reflecting diagnostics."""
    require(type(data) is bytes and 0 < len(data) <= MAX_HEADERS + MAX_JSON,
            "capability response size unsupported")
    parts = re.split(rb"\r?\n\r?\n", data, maxsplit=1)
    require(len(parts) == 2 and 0 < len(parts[0]) <= MAX_HEADERS and
            0 < len(parts[1]) <= MAX_JSON, "capability response framing unsupported")
    lines = parts[0].splitlines()
    require(bool(lines), "capability response headers unsupported")
    match = re.fullmatch(rb"HTTP/(?:1\.[01]|2(?:\.0)?) ([1-5][0-9]{2})(?: [\x20-\x7e]*)?", lines[0])
    require(match is not None and all(re.fullmatch(rb"[A-Za-z0-9-]+: [\x20-\x7e]*", line)
                                     is not None for line in lines[1:]),
            "capability response headers unsupported")
    status = int(match[1])
    require(type(exit_code) is int and ((status == 200 and exit_code == 0) or
            (400 <= status <= 599 and exit_code == 1)), "capability native response failed")
    try:
        body = parse_json(parts[1])
    except (BuildError, RecursionError) as error:
        raise Failure("capability response JSON unsupported") from error
    require(type(body) is dict, "capability response is not an object")
    return NativeResponse(status, body)


class CapabilityGhApi(QualifiedGhApi):
    """Pinned native transport preserving status while isolating read credentials and output."""

    def _read(self, endpoint, destination, limit):
        """Disable inherited artifact downloads and all status-discarding transport entry points."""
        raise Failure("unsupported capability transport operation")

    def response(self, endpoint):
        """Execute one fixed GET with closed stdin, sterile environment and hard pipe/time bounds."""
        require(_route(endpoint), "unsupported capability endpoint")
        require(time.monotonic() < self._deadline, "capability stage expired")
        self._check_native()
        with tempfile.TemporaryDirectory(prefix="armorer-capability-read-") as temporary:
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
            argv = [str(self.executable), "api", "--hostname", "github.com", "--method", "GET", "--include",
                    "--header", "Accept: application/vnd.github+json", "--header",
                    "X-GitHub-Api-Version: " + API_VERSION, endpoint]
            process = subprocess.Popen(argv, cwd=scratch, env=env, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            deadline = min(self._deadline, time.monotonic() + 60)
            counts, blocks = {"stdout": 0, "stderr": 0}, []
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
                    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
                    while selector.get_map():
                        require(time.monotonic() < deadline, "capability native read timed out")
                        for key, _ in selector.select(timeout=min(0.1, max(0, deadline - time.monotonic()))):
                            block = os.read(key.fileobj.fileno(), 65536)
                            if not block:
                                selector.unregister(key.fileobj)
                                continue
                            counts[key.data] += len(block)
                            require(counts[key.data] <= (MAX_HEADERS + MAX_JSON if key.data == "stdout"
                                                       else 1024 * 1024), "capability native output exceeded limit")
                            if key.data == "stdout":
                                blocks.append(block)
                    process.wait(timeout=max(0.001, deadline - time.monotonic()))
                return _parse_response(b"".join(blocks), process.returncode)
            except (OSError, subprocess.SubprocessError) as error:
                raise Failure("capability native read failed") from error
            finally:
                # The leader may exit while a descendant still holds a pipe open.
                # Reap the entire private group even when poll() already has an exit code.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except PermissionError as error:
                    try:
                        process.wait(timeout=0.1)
                    except subprocess.TimeoutExpired:
                        raise Failure("capability native termination denied") from error
                process.wait()
                process.stdout.close()
                process.stderr.close()

    def json(self, endpoint):
        """Expose successful bounded JSON only to the existing exact environment validator."""
        result = self.response(endpoint)
        require(result.status == 200, "capability prerequisite unavailable")
        return result.body


@dataclass(frozen=True)
class RepositoryIntent:
    """Independently reviewed repository identity and branch, never discovered authority."""
    repository: str
    repository_id: int
    default_branch: str

    def validate(self):
        """Validate fixed-route identity before any credentialed provider process is started."""
        require(type(self.repository) is str and re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", self.repository) is not None
            and all(part not in (".", "..") and not part.endswith(".git") for part in self.repository.split("/"))
            and _id(self.repository_id), "invalid independent capability repository")
        require(type(self.default_branch) is str and re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_/-]{0,99}", self.default_branch) is not None and
            "//" not in self.default_branch and not self.default_branch.endswith("/"),
            "invalid independent capability branch")


def _repository(api, expected):
    """Require exact native repository identity before reading or rechecking mutable prerequisites."""
    root = "repos/" + expected.repository
    response = api.response(root)
    row = response.body
    require(response.status == 200 and type(row.get("id")) is int and row["id"] == expected.repository_id
            and row.get("full_name") == expected.repository and row.get("url") == "https://api.github.com/" + root
            and row.get("default_branch") == expected.default_branch and row.get("fork") is False
            and row.get("archived") is False and row.get("disabled") is False and
            type(row.get("private")) is bool, "capability repository identity or state mismatch")
    return {"repository": expected.repository, "repository_id": expected.repository_id,
            "default_branch": expected.default_branch, "private": row["private"]}


def _unavailable(status):
    """Keep denied, invisible, throttled and provider-error states distinct without error body text."""
    if status in (401, 403):
        return {"state": "denied", "reason": "read-access-denied", "http_status": status}
    if status == 404:
        # Native 404 alone cannot distinguish disabled from permission-hidden or absent resources.
        return {"state": "unknown", "reason": "not-visible-or-not-enabled", "http_status": status}
    if status == 429:
        return {"state": "error", "reason": "provider-throttled", "http_status": status}
    return {"state": "error", "reason": "provider-read-failed", "http_status": status}


def _immutable(api, expected):
    """Observe explicit immutable configuration; no response authorizes a release transition."""
    response = api.response("repos/" + expected.repository + "/immutable-releases")
    if response.status != 200:
        return _unavailable(response.status)
    row = response.body
    require(set(row) == {"enabled", "enforced_by_owner"} and all(type(value) is bool for value in row.values()),
            "immutable capability response unsupported")
    return {"state": "configured" if row["enabled"] else "disabled", "http_status": 200,
            "enabled": row["enabled"], "enforced_by_owner": row["enforced_by_owner"]}


def _observe_environment(api, expected, name, policy):
    """Read only named environment controls; require independent identity for configuration acceptance."""
    root = "repos/" + expected.repository + "/environments/" + name
    response = api.response(root)
    if response.status != 200:
        return {"name": name, **_unavailable(response.status)}
    row = response.body
    require(_id(row.get("id")) and _text(row.get("node_id")) and row.get("name") == name and
            row.get("url") == "https://api.github.com/" + root, "capability environment identity malformed")
    if policy is None:
        digest = hashlib.sha256(json.dumps(row, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return {"name": name, "id": row["id"], "node_id": row["node_id"], "state": "unknown",
                "reason": "independent-environment-policy-unavailable", "configuration_sha256": digest,
                "current_attempt_approval": "unsupported", "effective_enforcement": "unsupported"}
    observed = _environment(api, expected, policy)
    # Reread equality includes provider metadata as well as the individually validated controls.
    require(api.json(root) == row, "capability environment changed during control validation")
    return observed


def _snapshot(api, expected, policies):
    """Surround immutable and environment reads with exact repository identity checks."""
    before = _repository(api, expected)
    result = {"repository": before, "immutable_releases": _immutable(api, expected),
              "environments": {name: _observe_environment(api, expected, name, policies.get(name))
                               for name in ENVIRONMENTS}}
    require(_repository(api, expected) == before, "capability repository changed during observation")
    return result


def observe_capabilities(api, expected, environments=()):
    """Return stable native prerequisite observations with every operational authority explicitly false."""
    require(type(api) is CapabilityGhApi and type(expected) is RepositoryIntent and type(environments) is tuple,
            "invalid capability adapter or intent")
    expected.validate()
    require(len(environments) <= 2 and all(type(policy) is EnvironmentIntent for policy in environments),
            "invalid independent environment policies")
    for policy in environments:
        policy.validate(expected)
    policies = {policy.name: policy for policy in environments}
    require(len(policies) == len(environments), "duplicate independent environment policy")
    started, monotonic_started = time.time(), time.monotonic()
    api._deadline = min(api._deadline, monotonic_started + 120)
    first = _snapshot(api, expected, policies)
    second = _snapshot(api, expected, policies)
    finished = time.time()
    require(first == second, "capability prerequisites changed between reads")
    require(0 <= finished - started <= 120 and time.monotonic() - monotonic_started <= 120,
            "capability observation expired or clock rolled back")
    return {"format_version": 1, "kind": "publication-prerequisite-observation",
            "observation_mode": "operator-qualification" if api._operator else "workflow-read-token",
            "observed_at_unix_seconds": finished, "prerequisites": second,
            "native_read_observed": True, "run_bound": False,
            "protected_environment_authenticated": False, "signing_authorized": False,
            "publication_authorized": False, "immutable_release_verified": False,
            "release_attestation_verified": False}
