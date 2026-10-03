"""Qualify actual pinned native prerequisite reads with the unprivileged hosted workflow token."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import tempfile

from armorer_runtime.common import Failure, require
from armorer_runtime.publication_capabilities_v1 import CapabilityGhApi, RepositoryIntent, observe_capabilities
from armorer_runtime.tools import platform_target
from armorer_runtime.transport_tools_v1 import install_gh


def main():
    """Retain genuine native denial/unknown observations and bad-auth/tool negatives without approval claims."""
    require(os.environ["GITHUB_REPOSITORY"] == "brianluby/armorer-workflows" and
            os.environ["GITHUB_REPOSITORY_ID"] == "1398918288" and
            os.environ["GITHUB_EVENT_NAME"] == "pull_request" and
            os.environ["GITHUB_ACTOR_ID"] == "3779002" and os.environ["GITHUB_ACTOR"] == "brianluby" and
            os.environ["EXPECTED_TRIGGERING_ACTOR"] == "brianluby", "capability qualification scope unsupported")
    expected = RepositoryIntent("brianluby/armorer-workflows", 1398918288, "main")
    token = os.environ.pop("ARMORER_READ_TOKEN")
    with tempfile.TemporaryDirectory(prefix="armorer-native-capability-qualification-") as temporary:
        root = Path(temporary)
        executable, distribution = install_gh(root / "native")
        receipt = observe_capabilities(CapabilityGhApi(executable, token), expected)
        del token
        denied = CapabilityGhApi(executable, "armorer-test-only-invalid-token")
        response = denied.response("repos/" + expected.repository + "/immutable-releases")
        require(response.status in (401, 403), "capability qualification accepted invalid authentication")
        receipt["actual_invalid_authentication_rejected"] = True
        inert = root / "inert-not-gh"
        executed = root / "substituted-tool-executed"
        inert.write_text("#!/bin/sh\n: > " + shlex.quote(str(executed)) + "\n")
        inert.chmod(0o500)
        try:
            CapabilityGhApi(inert, "test-only-token").response("repos/" + expected.repository)
        except Failure:
            require(not executed.exists(), "capability qualification executed substituted native bytes")
            receipt["native_byte_substitution_rejected_before_execution"] = True
        else:
            raise Failure("capability qualification accepted substituted native bytes")
        receipt["native_target"] = platform_target()
        receipt["distribution"] = distribution
        receipt["candidate_qualification_only"] = True
        receipt["qualification_sources"] = {
            name: {"sha256": hashlib.sha256(Path(name).read_bytes()).hexdigest(), "size": Path(name).stat().st_size}
            for name in ("armorer_runtime/publication_capabilities_v1.py", "tests/capability_cases_v1.py")}
        destination = Path(os.environ["RUNNER_TEMP"]) / "armorer-capability-qualification-v1"
        destination.mkdir(exist_ok=False)
        (destination / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps(receipt, sort_keys=True), flush=True)
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as stream:
            stream.write("### Native publication prerequisite qualification\n\n```json\n" +
                         json.dumps(receipt, indent=2) + "\n```\n")


if __name__ == "__main__":
    main()
