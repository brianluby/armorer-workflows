"""Qualify actual fixed native GETs without signing, payload execution or publication."""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import tempfile
import time

from armorer_runtime.common import Failure, require
from armorer_runtime.tools import platform_target
from armorer_runtime.transport_tools_v1 import install_gh
from armorer_runtime.transport_v1 import QualifiedGhApi, _artifact, _identity, _listing, _timestamp

REPOSITORY = "brianluby/armorer-workflows"
REPOSITORY_ID = 1398918288
WORKFLOW_ID = 371830961
CALLER_PATH = ".github/workflows/development.yml"
RUNNERS = ("ubuntu-24.04", "ubuntu-24.04-arm", "macos-15")
MAX_QUALIFICATION_ARCHIVE = 32 * 1024 * 1024


@dataclass(frozen=True)
class ExpectedRead:
    """Test-controller intent comes from GitHub job context, never offered artifact JSON."""
    repository: str
    repository_id: int
    head_commit: str
    head_branch: str
    event: str
    run_id: int
    run_attempt: int

    def validate(self):
        """Limit qualification to this repository's exact supported workflow execution."""
        require(self.repository == REPOSITORY and type(self.repository_id) is int and
                self.repository_id == REPOSITORY_ID, "native qualification repository mismatch")
        require(all(type(value) is int and 0 < value <= 2**63 - 1 for value in (self.run_id, self.run_attempt)),
                "native qualification run identity invalid")
        require(isinstance(self.head_commit, str) and re.fullmatch(r"[0-9a-f]{40}", self.head_commit) and
                isinstance(self.head_branch, str) and 0 < len(self.head_branch) <= 255 and
                not any(ord(char) < 33 or ord(char) == 127 for char in self.head_branch), "native qualification source invalid")
        require(self.event in ("pull_request", "push", "workflow_dispatch"), "native qualification trigger unsupported")


def _run(value, expected, now):
    """Bind actual provider records to independent job context without claiming writing-job identity."""
    require(isinstance(value, dict) and all(type(value.get(key)) is int and value[key] == wanted for key, wanted in
            (("id", expected.run_id), ("run_attempt", expected.run_attempt), ("workflow_id", WORKFLOW_ID))),
            "native qualification provider run mismatch")
    require(value.get("head_sha") == expected.head_commit and value.get("head_branch") == expected.head_branch and
            value.get("event") == expected.event and value.get("path") == CALLER_PATH,
            "native qualification source or caller mismatch")
    require((value.get("status"), value.get("conclusion")) in (("in_progress", None), ("completed", "success")),
            "native qualification run is not successful or active")
    for name in ("repository", "head_repository"):
        repository = value.get(name)
        require(isinstance(repository, dict) and type(repository.get("id")) is int and
                repository["id"] == expected.repository_id and repository.get("full_name") == expected.repository and
                repository.get("fork") is False, "native qualification provider repository mismatch")
    start = _timestamp(value.get("run_started_at"))
    require(0 < start <= now and now - start <= 3600, "native qualification attempt stale or future")
    return start


def qualify(api, expected, distribution):
    """Recheck three actual qualification archive identities using the existing bounded fixed native adapter."""
    require(type(api) is QualifiedGhApi and type(expected) is ExpectedRead, "native qualification adapter or intent invalid")
    expected.validate()
    names = {f"policy-native-v1-{runner}-{expected.run_id}-{expected.run_attempt}" for runner in RUNNERS}
    route = f"repos/{expected.repository}/actions/runs/{expected.run_id}"
    now = int(time.time())
    start = _run(api.json(route), expected, now)
    require(_run(api.json(route + f"/attempts/{expected.run_attempt}"), expected, now) == start, "native qualification attempts differ")
    records = _listing(api.json(route + "/artifacts?per_page=100"), expected, names, start, now)
    observed = {}
    with tempfile.TemporaryDirectory(prefix="armorer-native-get-qualification-") as temporary:
        for name, record in sorted(records.items()):
            require(record["size_in_bytes"] <= MAX_QUALIFICATION_ARCHIVE, "native qualification archive exceeds bound")
            detail = api.json(f"repos/{expected.repository}/actions/artifacts/{record['id']}")
            require(_artifact(detail, expected, name, start, int(time.time())) == record, "native qualification artifact detail changed")
            archive = Path(temporary) / (str(record["id"]) + ".zip")
            api.archive(expected.repository, record["id"], archive)
            identity = _identity(archive, MAX_QUALIFICATION_ARCHIVE)
            require(identity == {"size": record["size_in_bytes"], "sha256": record["digest"][7:]}, "native qualification archive bytes mismatch")
            observed[name] = {"provider": record, "archive": identity}
        latest = api.json(route)
        attempt = api.json(route + f"/attempts/{expected.run_attempt}")
        listing = api.json(route + "/artifacts?per_page=100")
        final_now = int(time.time())
        require(final_now >= now and time.monotonic() < api._deadline and
                _run(latest, expected, final_now) == start and _run(attempt, expected, final_now) == start and
                _listing(listing, expected, names, start, final_now) == records, "native qualification provider state changed")
    return {"schema_version": 1, "state": "native-get-adapter-qualified", "distribution": distribution,
            "authentication_mode": "operator-readonly-qualification" if api._operator else "isolated-workflow-token",
            "repository": expected.repository, "repository_id": expected.repository_id,
            "head_commit": expected.head_commit, "head_branch": expected.head_branch, "event": expected.event,
            "run_id": expected.run_id, "run_attempt": expected.run_attempt, "workflow_id": WORKFLOW_ID,
            "caller_path": CALLER_PATH, "observed_at": final_now, "artifacts": observed,
            "payload_decoded": False, "artifact_executed": False, "producer_job_authenticated": False,
            "signing_authorized": False, "cryptographic_release_authenticated": False,
            "policy_snapshot_authenticated": False, "production_catalog_accepted": False}


def main():
    """Use only the ephemeral read token for real native qualification and emit a credential-free whitelist."""
    expected = ExpectedRead(os.environ["GITHUB_REPOSITORY"], int(os.environ["GITHUB_REPOSITORY_ID"]),
                            os.environ["EXPECTED_HEAD"], os.environ["EXPECTED_BRANCH"], os.environ["GITHUB_EVENT_NAME"],
                            int(os.environ["GITHUB_RUN_ID"]), int(os.environ["GITHUB_RUN_ATTEMPT"]))
    expected.validate()
    token = os.environ.pop("ARMORER_READ_TOKEN")
    with tempfile.TemporaryDirectory(prefix="armorer-native-cli-qualification-") as temporary:
        root = Path(temporary)
        executable, distribution = install_gh(root / "native")
        api = QualifiedGhApi(executable, token)
        del token
        receipt = qualify(api, expected, distribution)
        denied = QualifiedGhApi(executable, "armorer-test-only-invalid-token")
        try:
            denied.json(f"repos/{expected.repository}/actions/runs/{expected.run_id}")
        except Failure:
            receipt["actual_invalid_authentication_rejected"] = True
        else:
            raise Failure("native qualification accepted invalid authentication")
        inert = root / "inert-not-gh"
        inert.write_text("#!/bin/sh\ntouch " + shlex.quote(str(root / "executed")) + "\n")
        inert.chmod(0o500)
        wrong = QualifiedGhApi(inert, "armorer-test-only-invalid-token")
        try:
            wrong.json(f"repos/{expected.repository}/actions/runs/{expected.run_id}")
        except Failure:
            require(not (root / "executed").exists(), "native qualification executed rejected bytes")
            receipt["native_byte_substitution_rejected_before_execution"] = True
        else:
            raise Failure("native qualification accepted substituted CLI")
        receipt["native_target"] = platform_target()
        receipt["qualification_sources"] = {
            name: {"sha256": hashlib.sha256(Path(name).read_bytes()).hexdigest(), "size": Path(name).stat().st_size}
            for name in ("armorer_runtime/transport_v1.py", "armorer_runtime/transport_tools_v1.py", "tests/transport_cases_v1.py")}
        print(json.dumps(receipt, sort_keys=True), flush=True)
        summary = Path(os.environ["GITHUB_STEP_SUMMARY"])
        with summary.open("a") as stream:
            stream.write("### Native GET adapter qualification\n\n```json\n" + json.dumps(receipt, indent=2) + "\n```\n")


if __name__ == "__main__":
    main()
