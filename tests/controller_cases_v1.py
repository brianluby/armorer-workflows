"""Qualify the independently intended current job using actual read-only native GitHub APIs."""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import tempfile

from armorer_runtime.common import Failure, require
from armorer_runtime.source_transport_v1 import SourceGhApi, SourceIntent, wait_for_source
from armorer_runtime.controller_context_v1 import ControllerGhApi, JobIntent, observe_controller
from armorer_runtime.tools import platform_target
from armorer_runtime.transport_tools_v1 import install_gh


def main():
    """Map this exact native qualification job without live OIDC, protected environments or mutations."""
    require(os.environ["GITHUB_REPOSITORY"] == "brianluby/armorer-workflows" and
            os.environ["GITHUB_REPOSITORY_ID"] == "1398918288" and
            os.environ["GITHUB_EVENT_NAME"] == "pull_request" and
            os.environ["GITHUB_ACTOR_ID"] == "3779002" and os.environ["GITHUB_ACTOR"] == "brianluby" and
            os.environ["EXPECTED_TRIGGERING_ACTOR"] == "brianluby", "source qualification scope unsupported")
    match = re.fullmatch(r"refs/pull/([1-9][0-9]*)/merge", os.environ["GITHUB_REF"])
    require(match is not None, "source qualification PR ref unsupported")
    path = ".github/workflows/development.yml"
    require(os.environ["GITHUB_WORKFLOW_SHA"] == os.environ["GITHUB_SHA"], "source qualification caller checkout differs")
    expected = SourceIntent("brianluby/armorer-workflows", 1398918288, 3779002, "main",
        int(os.environ["GITHUB_RUN_ID"]), int(os.environ["GITHUB_RUN_ATTEMPT"]), 371830961,
        path, os.environ["GITHUB_WORKFLOW_SHA"], hashlib.sha256(Path(path).read_bytes()).hexdigest(),
        os.environ["EXPECTED_HEAD"], os.environ["GITHUB_SHA"], os.environ["GITHUB_HEAD_REF"],
        "pull_request", os.environ["GITHUB_REF"], 3779002, "brianluby", 3779002, "brianluby",
        pull_request=int(match[1]), base_commit=os.environ["EXPECTED_BASE"], base_branch=os.environ["GITHUB_BASE_REF"])
    expected.validate()
    label = os.environ["EXPECTED_RUNNER_LABEL"]
    target = platform_target()
    require({"ubuntu-24.04": "x86_64-unknown-linux-gnu", "ubuntu-24.04-arm": "aarch64-unknown-linux-gnu",
             "macos-15": "aarch64-apple-darwin"}.get(label) == target and
            os.environ["GITHUB_JOB"] == "transport-evidence" and
            os.environ["GITHUB_WORKFLOW"] == "Workflow runtime validation", "controller qualification job scope unsupported")
    intent = JobIntent(expected, "Workflow runtime validation", "transport-evidence (" + label + ")",
                       label, qualification_only=True)
    intent.validate()
    token = os.environ.pop("ARMORER_READ_TOKEN")
    with tempfile.TemporaryDirectory(prefix="armorer-source-provider-qualification-") as temporary:
        root = Path(temporary)
        executable, distribution = install_gh(root / "native")
        api = SourceGhApi(executable, token)
        controller_api = ControllerGhApi(executable, token)
        del token
        start = wait_for_source(api, expected)
        receipt = observe_controller(api, controller_api, intent)
        require(receipt["source_control"]["run_started_at"] == start, "source qualification attempt changed after readiness")
        denied = ControllerGhApi(executable, "armorer-test-only-invalid-token")
        try:
            denied.json("repos/" + expected.repository + f"/actions/jobs/{receipt['controller']['job']['job_id']}")
        except Failure:
            receipt["actual_invalid_authentication_rejected"] = True
        else:
            raise Failure("source qualification accepted invalid authentication")
        inert = root / "inert-not-gh"
        inert.write_text("#!/bin/sh\ntouch " + shlex.quote(str(root / "executed")) + "\n")
        inert.chmod(0o500)
        try:
            ControllerGhApi(inert, "test-only-token").json("repos/" + expected.repository + f"/actions/jobs/{receipt['controller']['job']['job_id']}")
        except Failure:
            require(not (root / "executed").exists(), "source qualification executed rejected native bytes")
            receipt["native_byte_substitution_rejected_before_execution"] = True
        else:
            raise Failure("source qualification accepted substituted native bytes")
        receipt["native_target"] = platform_target()
        receipt["distribution"] = distribution
        receipt["candidate_qualification_only"] = True
        receipt["qualification_sources"] = {
            name: {"sha256": hashlib.sha256(Path(name).read_bytes()).hexdigest(), "size": Path(name).stat().st_size}
            for name in ("armorer_runtime/controller_context_v1.py", "armorer_runtime/source_transport_v1.py", "tests/controller_cases_v1.py")}
        print(json.dumps(receipt, sort_keys=True), flush=True)
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as stream:
            stream.write("### Current-job controller qualification\n\n```json\n" + json.dumps(receipt, indent=2) + "\n```\n")


if __name__ == "__main__":
    main()
