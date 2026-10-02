"""Qualify source-provider reads using independent job context; never grant release authority."""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import tempfile

from armorer_runtime.common import Failure, require
from armorer_runtime.source_transport_v1 import SourceGhApi, SourceIntent, observe_source, wait_for_source
from armorer_runtime.tools import platform_target
from armorer_runtime.transport_tools_v1 import install_gh


def main():
    """Use an actual isolated read token to verify this candidate's exact PR merge and caller bytes."""
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
    token = os.environ.pop("ARMORER_READ_TOKEN")
    with tempfile.TemporaryDirectory(prefix="armorer-source-provider-qualification-") as temporary:
        root = Path(temporary)
        executable, distribution = install_gh(root / "native")
        api = SourceGhApi(executable, token)
        del token
        start = wait_for_source(api, expected)
        receipt = observe_source(api, expected)
        require(receipt["source_control"]["run_started_at"] == start, "source qualification attempt changed after readiness")
        denied = SourceGhApi(executable, "armorer-test-only-invalid-token")
        try:
            denied.json("repos/" + expected.repository)
        except Failure:
            receipt["actual_invalid_authentication_rejected"] = True
        else:
            raise Failure("source qualification accepted invalid authentication")
        inert = root / "inert-not-gh"
        inert.write_text("#!/bin/sh\ntouch " + shlex.quote(str(root / "executed")) + "\n")
        inert.chmod(0o500)
        try:
            SourceGhApi(inert, "test-only-token").json("repos/" + expected.repository)
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
            for name in ("armorer_runtime/source_transport_v1.py", "tests/source_cases_v1.py")}
        print(json.dumps(receipt, sort_keys=True), flush=True)
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as stream:
            stream.write("### Source provider qualification\n\n```json\n" + json.dumps(receipt, indent=2) + "\n```\n")


if __name__ == "__main__":
    main()
