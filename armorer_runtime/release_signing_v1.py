"""Protected Apple signing handoff v1: digest-pinned approval, canonical repackaging, evidence chain.

This module never reads credential values. Apple secrets exist only inside the
native environment-gated signing job's credential step, which adapts the proven
apple-signing command sequence under the producer startup boundary. Every
function here is credential-free and fails closed on missing or mismatched
independent expectations.

The owner approval file is committed before the release run exists, so it binds
source/selection/team/catalog/workflow pins but never a run id. The executing
workflow injects the live run/attempt and its own immutable commit, then requires
the approval's workflow pin to equal the actually executing reusable workflow.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import time

from .apple_payload_v1 import APPLE, _expectations, prepare_apple_payloads
from .build import BuildError, _regular_bytes, parse_json
from .build_v3 import MAX_ARTIFACT
from .common import Failure, IDENTIFIER, require
from .final_payload_v1 import MAX_METADATA, PayloadExpectation, _byte_identity, _fields, _inputs, _json
from .transport_v1 import ExpectedRun

APPROVAL_STATE = "release-signing-approval"
SIGNING_INPUT_SUFFIX = "-signing-input"
SIGNING_PLAN_NAME = "release-signing-plan-v1"
SIGNED_RELEASE_SUFFIX = "-signed-release-v1"
PACKAGE_DIR = "pkg"
SIGN_WORKFLOW = ".github/workflows/rust-release-sign.yml"
BUILD_WORKFLOW = ".github/workflows/rust-build-v3.yml"
WORKFLOW_REPOSITORY = "brianluby/armorer-workflows"
EVIDENCE_FIELDS = {"schema_version", "inputs", "selection", "catalog", "runner_label", "runner_image",
                   "recorded_at", "tools", "coverage", "exceptions", "steps", "apple_assertions"}
STEP_FIELDS = {"kind", "inputs", "output", "run", "started_at", "finished_at", "outcome", "platform_evidence"}
ASSERTION_FIELDS = {"team_id", "certificate_sha256", "hardened_runtime", "secure_timestamp",
                    "notarization_submission_id", "notarization_outcome", "notarization_log", "ticket_mode"}
APPROVAL_FIELDS = {"schema_version", "state", "repository", "repository_id", "head_commit", "head_branch",
                   "source_commit", "git_ref", "event", "caller_path", "caller_workflow_id",
                   "signing_workflow_commit", "build_workflow_commit", "team_id", "signing_identity",
                   "catalog", "inputs", "build_inputs", "selections", "max_age_seconds"}


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _identity(data: bytes) -> dict:
    require(type(data) is bytes and 0 < len(data) <= MAX_ARTIFACT, "invalid signing byte identity")
    return {"sha256": _digest(data), "size": len(data)}


def _epoch(value: str) -> int:
    """Parse one canonical notarytool UTC timestamp without local-time coercion."""
    require(type(value) is str and
            re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z", value),
            "invalid notarization timestamp")
    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())


@dataclass(frozen=True)
class SigningApproval:
    """Independent owner-reviewed intent; its digest pin is the only activation permit."""
    run: ExpectedRun
    items: tuple
    apple_items: tuple
    inputs: dict
    catalog: dict
    build_inputs: tuple
    team_id: str
    signing_identity: str
    signing_workflow_commit: str
    max_age_seconds: int


def load_approval(data: bytes, expected_digest: str, *, run_id: int, run_attempt: int,
                  repository: str, event_name: str, workflow_commit: str) -> SigningApproval:
    """Require the exact owner-pinned approval bytes bound to this live run before any signing stage."""
    require(type(data) is bytes and 0 < len(data) <= MAX_METADATA, "missing or oversized signing approval")
    require(type(expected_digest) is str and re.fullmatch(r"[0-9a-f]{64}", expected_digest) and
            _digest(data) == expected_digest, "signing approval digest mismatch")
    require(type(workflow_commit) is str and re.fullmatch(r"[0-9a-f]{40}", workflow_commit),
            "missing immutable signing workflow commit")
    record = parse_json(data)
    _fields(record, APPROVAL_FIELDS)
    require(type(record["schema_version"]) is int and record["schema_version"] == 1 and
            record["state"] == APPROVAL_STATE, "unsupported signing approval")
    require(record["repository"] == repository and record["event"] == event_name and
            event_name in ("push", "workflow_dispatch"), "signing approval repository or event mismatch")
    require(record["signing_workflow_commit"] == workflow_commit,
            "signing approval pins a different signing workflow commit")
    require(type(record["team_id"]) is str and re.fullmatch(r"[A-Z0-9]{10}", record["team_id"]) and
            type(record["signing_identity"]) is str and 0 < len(record["signing_identity"]) <= 255,
            "invalid approved Apple team or identity")
    require(type(record["build_workflow_commit"]) is str and
            re.fullmatch(r"[0-9a-f]{40}", record["build_workflow_commit"]),
            "invalid approved build workflow commit")
    run = ExpectedRun(repository=record["repository"], repository_id=record["repository_id"],
                      head_commit=record["head_commit"], source_commit=record["source_commit"],
                      head_branch=record["head_branch"], event=record["event"],
                      caller_path=record["caller_path"], caller_workflow_id=record["caller_workflow_id"],
                      run_id=run_id, run_attempt=run_attempt,
                      runtime_commit=record["build_workflow_commit"], max_age_seconds=record["max_age_seconds"])
    run.validate()
    require(type(record["inputs"]) is dict and "run" not in record["inputs"],
            "approval inputs must not pre-bind a run")
    inputs = dict(record["inputs"])
    inputs["run"] = {"id": run_id, "attempt": run_attempt,
                     "workflow": {"repository": WORKFLOW_REPOSITORY, "path": SIGN_WORKFLOW,
                                  "commit": workflow_commit}}
    _inputs(inputs)
    require(inputs["source"]["commit"] == record["source_commit"] and
            inputs["source"]["git_ref"] == record["git_ref"], "approval source identity mismatch")
    _byte_identity(record["catalog"])
    require(type(record["build_inputs"]) is list and 0 < len(record["build_inputs"]) <= 128,
            "missing approved build inputs")
    for identity in record["build_inputs"]:
        _byte_identity(identity)
    require(type(record["selections"]) is list and 0 < len(record["selections"]) <= 64,
            "missing approved selections")
    items = []
    for raw in record["selections"]:
        _fields(raw, {"selection", "context", "input_sha256", "root_component_name",
                      "package_version", "tool_sha256"})
        context = dict(raw["context"])
        require(set(context) == {"source", "runtime_commit"}, "approval context must not pre-bind a run")
        require(context["runtime_commit"] == record["build_workflow_commit"],
                "approval selection builder commit mismatch")
        context["run_id"] = str(run_id)
        context["run_attempt"] = str(run_attempt)
        items.append(PayloadExpectation(selection=raw["selection"], context=context,
                                        input_sha256=raw["input_sha256"],
                                        root_component_name=raw["root_component_name"],
                                        package_version=raw["package_version"],
                                        tool_sha256=raw["tool_sha256"]))
    copied = _expectations(tuple(items))
    apple_items = tuple(item for item in copied
                        if item.selection["target"] == APPLE and item.selection["profile"] != "library")
    require(apple_items, "signing approval contains no Apple executable selection")
    return SigningApproval(run=run, items=copied, apple_items=apple_items, inputs=inputs,
                           catalog=record["catalog"], build_inputs=tuple(record["build_inputs"]),
                           team_id=record["team_id"], signing_identity=record["signing_identity"],
                           signing_workflow_commit=workflow_commit, max_age_seconds=record["max_age_seconds"])


def signing_matrix(approval: SigningApproval) -> list[dict]:
    """Derive one isolated signing call per Apple executable; names never come from offered bytes."""
    rows = []
    for item in approval.apple_items:
        key = item.selection["artifact_id"]
        binary = item.selection["binary"]
        rows.append({"key": key, "binary": binary,
                     "artifact_name": key + SIGNING_INPUT_SUFFIX,
                     "archive_name": key + ".tar.gz",
                     "binary_path": PACKAGE_DIR + "/" + binary,
                     "signing_identity": approval.signing_identity, "team_id": approval.team_id})
    return rows


def package_signing_input(payload: Path, binary: str, destination: Path) -> dict:
    """Wrap one inspected unsigned Mach-O in the package-directory layout apple-signing v1 requires."""
    require(IDENTIFIER.fullmatch(binary) is not None, "unsafe signing binary name")
    data = payload.read_bytes()
    identity = _identity(data)
    with destination.open("xb") as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                directory = tarfile.TarInfo(PACKAGE_DIR)
                directory.type = tarfile.DIRTYPE
                directory.mode = 0o755
                directory.uid = directory.gid = directory.mtime = 0
                directory.uname = directory.gname = ""
                archive.addfile(directory)
                member = tarfile.TarInfo(PACKAGE_DIR + "/" + binary)
                member.size = identity["size"]
                member.mode = 0o755
                member.uid = member.gid = member.mtime = 0
                member.uname = member.gname = ""
                with payload.open("rb") as incoming:
                    archive.addfile(member, incoming)
        output.flush()
    destination.chmod(0o400)
    return identity


def extract_signed_binary(archive: Path, binary: str) -> bytes:
    """Read exactly the one signed executable from the apple-signing output archive."""
    require(IDENTIFIER.fullmatch(binary) is not None, "unsafe signed binary name")
    expected = PACKAGE_DIR + "/" + binary
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        require(0 < len(members) <= 2, "unexpected signed archive member count")
        found, size = None, None
        for member in members:
            if member.name == PACKAGE_DIR:
                require(member.isdir(), "signed package entry is not a directory")
            elif member.name == expected:
                require(member.isfile() and found is None and 0 < member.size <= MAX_ARTIFACT,
                        "duplicate or oversized signed binary")
                found = source.extractfile(member).read()
                size = member.size
            else:
                require(False, "unexpected signed archive member")
        require(found is not None and len(found) == size, "signed executable missing")
        return found


def extract_release_binary(archive: Path, binary: str) -> bytes:
    """Read the one executable from the consumer-canonical single-leaf release archive.

    Distinct from extract_signed_binary: the apple-signing output carries pkg/<binary>, while
    repackage_signed emits the single leaf named <binary> that the armorer consumer unpacks.
    """
    require(IDENTIFIER.fullmatch(binary) is not None, "unsafe release binary name")
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        require(len(members) == 1, "unexpected release archive member count")
        member = members[0]
        require(member.name == binary and member.isfile() and 0 < member.size <= MAX_ARTIFACT,
                "unexpected or oversized release archive member")
        found = source.extractfile(member).read()
        require(len(found) == member.size, "release executable truncated")
        return found


def repackage_signed(data: bytes, binary: str, destination: Path) -> dict:
    """Rebuild the consumer-canonical single-leaf USTAR archive from the exact signed bytes."""
    require(IDENTIFIER.fullmatch(binary) is not None and 0 < len(data) <= MAX_ARTIFACT,
            "unsafe signed repackaging input")
    with destination.open("xb") as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                member = tarfile.TarInfo(binary)
                member.size = len(data)
                member.mode = 0o755
                member.uid = member.gid = member.mtime = 0
                member.uname = member.gname = ""
                archive.addfile(member, io.BytesIO(data))
        output.flush()
    destination.chmod(0o400)
    return _identity(destination.read_bytes())


def _codesign(binary: Path, *arguments: str) -> str:
    result = subprocess.run(["codesign", *arguments, str(binary)], capture_output=True, text=True, timeout=120)
    require(result.returncode == 0, "codesign inspection failed")
    return result.stdout + result.stderr


def signing_platform_evidence(binary: Path, work: Path, team_id: str) -> dict:
    """Measure public signature facts and certificate identity; never read or log credential values."""
    prefix = work / "certificate"
    result = subprocess.run(["codesign", "--extract-certificates=" + str(prefix), str(binary)],
                            capture_output=True, text=True, timeout=120)
    leaf = prefix.with_name("certificate0")
    require(result.returncode == 0 and leaf.is_file(), "signing certificate extraction failed")
    certificate = leaf.read_bytes()
    require(0 < len(certificate) <= MAX_METADATA, "invalid signing certificate bytes")
    description = _codesign(binary, "-d", "--verbose=4")
    require("(runtime)" in description, "signed executable lacks hardened runtime")
    require("Timestamp=" in description and "Timestamp=none" not in description,
            "signed executable lacks a secure timestamp")
    require("TeamIdentifier=" + team_id in description, "signed executable team mismatch")
    _codesign(binary, "--verify", "--strict", "--check-notarization", "-R=notarized")
    return {"certificate_sha256": _digest(certificate),
            "certificate": {"sha256": _digest(certificate), "size": len(certificate)}}


def apple_evidence(*, approval: SigningApproval, item: PayloadExpectation, workflow_commit: str,
                   unsigned: dict, signed_binary: dict, final: dict, handoff: dict,
                   notarization_log: bytes, submission: dict, notarization: dict,
                   platform: dict, tools: list, runner_image: str, recorded_at: int) -> bytes:
    """Assemble the exact ArtifactEvidence shape the armorer consumer validates for macOS executables."""
    require(re.fullmatch(r"[0-9a-f]{40}", workflow_commit) is not None, "invalid signing workflow commit")
    case = item.selection
    selection = {"deliverable_id": case["id"], "profile": case["profile"], "package": case["package"],
                 "package_version": item.package_version, "binary": case["binary"], "target": case["target"],
                 "feature_set": case["feature_set"], "default_features": case["default_features"],
                 "features": case["features"], "toolchain": case["toolchain"]}
    run = {"id": approval.run.run_id, "attempt": approval.run.run_attempt,
           "workflow": {"repository": WORKFLOW_REPOSITORY, "path": SIGN_WORKFLOW, "commit": workflow_commit}}
    build_run = {"id": run["id"], "attempt": run["attempt"],
                 "workflow": {"repository": WORKFLOW_REPOSITORY, "path": BUILD_WORKFLOW,
                              "commit": approval.run.runtime_commit}}
    build_finished = handoff["observed_build"]["finished_at"]
    created = _epoch(submission["createdDate"])
    uploaded = _epoch(notarization.get("uploadDate", submission["createdDate"]))
    require(submission.get("status") == "Accepted" and notarization.get("status") == "Accepted" and
            type(submission.get("id")) is str and IDENTIFIER.fullmatch(submission["id"]) and
            submission["id"] == notarization.get("jobId"), "notarization evidence not accepted")
    require(build_finished <= created <= uploaded <= recorded_at, "signing evidence clock order invalid")
    log_identity = _identity(notarization_log)
    handoff_identity = _identity(_json(handoff))
    steps = [
        {"kind": "build", "inputs": list(approval.build_inputs), "output": unsigned, "run": build_run,
         "started_at": handoff["observed_build"]["started_at"], "finished_at": build_finished,
         "outcome": "passed", "platform_evidence": [handoff_identity]},
        {"kind": "sign", "inputs": [unsigned], "output": signed_binary, "run": run,
         "started_at": build_finished, "finished_at": created,
         "outcome": "passed", "platform_evidence": [platform["certificate"]]},
        {"kind": "notarize", "inputs": [signed_binary], "output": signed_binary, "run": run,
         "started_at": created, "finished_at": uploaded,
         "outcome": "passed", "platform_evidence": [log_identity]},
        {"kind": "package", "inputs": [signed_binary], "output": final, "run": run,
         "started_at": uploaded, "finished_at": recorded_at,
         "outcome": "passed", "platform_evidence": [log_identity]},
    ]
    record = {"schema_version": 1, "inputs": approval.inputs, "selection": selection,
              "catalog": approval.catalog, "runner_label": "macos-15", "runner_image": runner_image,
              "recorded_at": recorded_at, "tools": tools,
              "coverage": [{"capability": "apple-signing", "scope": "developer-id-signing-and-notarization",
                            "tested_subject": final, "omissions": [], "outcome": "passed",
                            "enforcement": "enforced", "exception_ids": []}],
              "exceptions": [], "steps": steps,
              "apple_assertions": {"team_id": approval.team_id,
                                   "certificate_sha256": platform["certificate_sha256"],
                                   "hardened_runtime": True, "secure_timestamp": True,
                                   "notarization_submission_id": submission["id"],
                                   "notarization_outcome": "passed", "notarization_log": log_identity,
                                   "ticket_mode": "online-standalone-mach-o"}}
    _fields(record, EVIDENCE_FIELDS)
    for step in record["steps"]:
        _fields(step, STEP_FIELDS)
    _fields(record["apple_assertions"], ASSERTION_FIELDS)
    require(type(record["runner_image"]) is str and 0 < len(record["runner_image"].strip()) <= 4096 and
            type(record["tools"]) is list and 0 < len(record["tools"]) <= 128,
            "invalid signing evidence runner or tools")
    return _json(record)



def _tool_observation(path: Path, name: str) -> dict:
    """Identify one fixed hosted signing executable actually used; no upstream approval claim."""
    require(type(name) is str and IDENTIFIER.fullmatch(name) is not None, "invalid signing tool name")
    data = path.read_bytes()
    identity = _identity(data)
    return {"name": name, "kind": "tool", "version": "hosted-image", "bytes": identity,
            "authentication_record": identity, "observed_at": int(time.time()), "max_age_seconds": None}


def prepare_signing(*, approval: SigningApproval, handoffs: dict, work: Path) -> dict:
    """Freeze the complete unsigned set and stage one canonical signing input per Apple executable.

    Runs credential-free before the environment-gated credential step. The plan binds the exact
    staged archive bytes and the independently verified build observations; offered bytes never
    choose names, identities or the signing permit.
    """
    require(type(handoffs) is dict and set(handoffs) == {item.selection["artifact_id"] for item in approval.items},
            "signing handoff set does not match the approved selections")
    require(work.is_dir() and not work.is_symlink(), "signing work directory unavailable")
    rows = []
    with prepare_apple_payloads(handoffs, approval.items, max_age_seconds=approval.max_age_seconds) as intake:
        audit = intake.audit()
        for row in signing_matrix(approval):
            key, binary = row["key"], row["binary"]
            inspection = audit["apple_payloads"][key]["inspection"]
            require(inspection["embedded_signature_range"] is None,
                    "unsigned Apple payload already carries an embedded signature")
            archive = work / row["archive_name"]
            unsigned = package_signing_input(intake.unsigned_payload_path(key), binary, archive)
            require(unsigned == inspection["bytes"], "signing input identity mismatch")
            rows.append({**row, "unsigned": unsigned, "archive": _identity(_regular_bytes(archive, MAX_ARTIFACT)),
                         "sbom": audit["handoff_leaf_identities"][key][key + ".cdx.json"],
                         "observed_build": audit["apple_payloads"][key]["observed_build"]})
    return {"schema_version": 1, "state": SIGNING_PLAN_NAME,
            "run": {"id": approval.run.run_id, "attempt": approval.run.run_attempt},
            "signing_workflow_commit": approval.signing_workflow_commit, "rows": rows}


def finalize_signing(*, approval: SigningApproval, plan: dict, work: Path, signed_directory: Path,
                     runner_image: str) -> dict:
    """Join each accepted notarization to its exact signed bytes and emit the consumer evidence chain.

    Credential-free: reads only public signature facts and Apple's acceptance records. Each plan
    row must match the approval-derived matrix exactly; signing legitimately changes the bytes, so
    the chain binds the extracted executable identity, not the staged input archive. Per-key
    notarization records live under work/<key>/ so a multi-target release never shares one submission.
    """
    require(type(plan) is dict and plan.get("schema_version") == 1 and plan.get("state") == SIGNING_PLAN_NAME and
            plan.get("signing_workflow_commit") == approval.signing_workflow_commit and
            plan.get("run") == {"id": approval.run.run_id, "attempt": approval.run.run_attempt},
            "signing plan identity mismatch")
    require(signed_directory.is_dir() and not signed_directory.is_symlink(), "signed directory unavailable")
    rows = plan["rows"]
    expected_rows = signing_matrix(approval)
    require(type(rows) is list and len(rows) == len(expected_rows), "signing plan row count mismatch")
    recorded_at = int(time.time())
    tools = [_tool_observation(Path("/usr/bin/codesign"), "codesign"),
             _tool_observation(Path("/usr/bin/xcrun"), "xcrun")]
    results = {}
    for row, expected in zip(rows, expected_rows):
        require(type(row) is dict and all(row.get(name) == value for name, value in expected.items()),
                "signing plan row does not match the approved matrix")
        key, binary = row["key"], row["binary"]
        item = next(value for value in approval.apple_items if value.selection["artifact_id"] == key)
        _byte_identity(row["unsigned"])
        _byte_identity(row["archive"])
        observed = row["observed_build"]
        require(type(observed) is dict and set(observed) == {"started_at", "finished_at"} and
                all(type(value) is int and 0 < value <= recorded_at for value in observed.values()) and
                observed["started_at"] <= observed["finished_at"], "invalid plan build observation")
        archive = signed_directory / row["archive_name"]
        signed_bytes = extract_signed_binary(archive, binary)
        signed_binary = _identity(signed_bytes)
        require(signed_binary != row["unsigned"], "signed executable bytes unchanged after signing")
        staging = work / key
        # The gated credential step already created this directory to stage submission.json and
        # notarization.json; reuse it rather than failing on the pre-existing evidence directory.
        staging.mkdir(mode=0o700, exist_ok=True)
        executable = staging / binary
        executable.write_bytes(signed_bytes)
        executable.chmod(0o700)
        platform = signing_platform_evidence(executable, staging, approval.team_id)
        submission = parse_json(_regular_bytes(staging / "submission.json", MAX_METADATA))
        notarization_log = _regular_bytes(staging / "notarization.json", MAX_METADATA)
        notarization = parse_json(notarization_log)
        final_path = work / (key + SIGNED_RELEASE_SUFFIX + ".tar.gz")
        final = repackage_signed(signed_bytes, binary, final_path)
        evidence = apple_evidence(approval=approval, item=item, workflow_commit=approval.signing_workflow_commit,
                                  unsigned=row["unsigned"], signed_binary=signed_binary, final=final,
                                  handoff={"observed_build": observed}, notarization_log=notarization_log,
                                  submission=submission, notarization=notarization, platform=platform,
                                  tools=tools, runner_image=runner_image, recorded_at=recorded_at)
        # The consumer reads Apple transformation evidence from <key>.apple.json; .build.json is
        # the separate BuildEvidence role, which must carry no Apple assertions.
        (work / (key + ".apple.json")).write_bytes(evidence)
        results[key] = {"final": final, "signed_binary": signed_binary,
                        "release_artifact": key + SIGNED_RELEASE_SUFFIX,
                        "release_archive": final_path.name}
    return {"schema_version": 1, "state": "release-signing-finalized", "results": results}


def verify_signed_release(*, approval: SigningApproval, plan: dict, release_directory: Path) -> dict:
    """Guard the attestation producer: admit only the exact final signed bytes the signing job produced.

    Credential-free and read-only. Each release archive must rehash to the plan's recorded final
    identity and unpack to exactly the one declared executable; unsigned or substituted bytes fail
    before any attestation subject is exposed. This never authenticates a signature or grants authority.
    """
    require(type(plan) is dict and plan.get("schema_version") == 1 and plan.get("state") == SIGNING_PLAN_NAME and
            plan.get("signing_workflow_commit") == approval.signing_workflow_commit and
            plan.get("run") == {"id": approval.run.run_id, "attempt": approval.run.run_attempt},
            "signing plan identity mismatch")
    require(release_directory.is_dir() and not release_directory.is_symlink(), "signed release directory unavailable")
    rows = plan["rows"]
    require(type(rows) is list and len(rows) == len(approval.apple_items), "signing plan row count mismatch")
    subjects = {}
    for row, expected in zip(rows, signing_matrix(approval)):
        require(type(row) is dict and all(row.get(name) == value for name, value in expected.items()),
                "signing plan row does not match the approved matrix")
        key, binary = row["key"], row["binary"]
        final = row["final"]
        _byte_identity(final)
        archive = release_directory / (key + SIGNED_RELEASE_SUFFIX + ".tar.gz")
        require(_identity(_regular_bytes(archive, MAX_ARTIFACT)) == final,
                "signed release archive bytes differ from the finalized signing output")
        signed_bytes = extract_release_binary(archive, binary)
        require(_identity(signed_bytes) == row["signed_binary"],
                "signed release executable differs from the finalized signing output")
        sbom = release_directory / (key + ".cdx.json")
        require(_identity(_regular_bytes(sbom, MAX_METADATA)) == row["sbom"],
                "signed release SBOM differs from the verified unsigned build SBOM")
        subjects[key] = {"archive": archive.name, "sbom": sbom.name, "final": final,
                         "signed_binary": row["signed_binary"]}
    return {"schema_version": 1, "state": "release-signing-verified", "subjects": subjects}


def main() -> None:
    """Fixed credential-free signing orchestration; credentials live only in the gated shell step."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "finalize", "verify"))
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--approval-sha256", required=True)
    parser.add_argument("--handoffs", type=Path)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--signed", type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.operation == "verify":
            require(arguments.plan is not None and arguments.signed is not None,
                    "verify requires plan and signed release paths")
            plan = parse_json(_regular_bytes(arguments.plan, MAX_METADATA))
            # The attest job executes a different workflow commit; bind the digest-pinned approval
            # to the signing commit the plan claims, then re-check that claim against the approval.
            workflow_commit = plan.get("signing_workflow_commit")
        else:
            workflow_commit = os.environ["ARMORER_SIGN_WORKFLOW_COMMIT"]
        approval = load_approval(_regular_bytes(arguments.approval, MAX_METADATA), arguments.approval_sha256,
                                 run_id=int(os.environ["GITHUB_RUN_ID"]),
                                 run_attempt=int(os.environ["GITHUB_RUN_ATTEMPT"]),
                                 repository=os.environ["GITHUB_REPOSITORY"],
                                 event_name=os.environ["GITHUB_EVENT_NAME"],
                                 workflow_commit=workflow_commit)
        if arguments.operation == "prepare":
            require(arguments.handoffs is not None and arguments.output is not None,
                    "prepare requires handoff and output paths")
            directories = {item.selection["artifact_id"]: arguments.handoffs /
                           (item.selection["artifact_id"] + "-handoff-v3-run-" +
                            str(approval.run.run_id) + "-attempt-" + str(approval.run.run_attempt))
                           for item in approval.items}
            plan = prepare_signing(approval=approval, handoffs=directories, work=arguments.work)
            arguments.output.write_bytes(_json(plan))
        elif arguments.operation == "finalize":
            require(arguments.plan is not None and arguments.signed is not None,
                    "finalize requires plan and signed paths")
            plan = parse_json(_regular_bytes(arguments.plan, MAX_METADATA))
            result = finalize_signing(approval=approval, plan=plan, work=arguments.work,
                                      signed_directory=arguments.signed,
                                      runner_image=os.environ["ARMORER_RUNNER_IMAGE"])
            print(json.dumps(result, sort_keys=True))
        else:
            result = verify_signed_release(approval=approval, plan=plan, release_directory=arguments.signed)
            print(json.dumps(result, sort_keys=True))
    except (BuildError, Failure, ValueError, OSError, KeyError, TypeError, AttributeError, subprocess.SubprocessError):
        parser.exit(1, "Armorer release signing failed closed; no credential, signing or publication authority.\n")


if __name__ == "__main__":
    main()