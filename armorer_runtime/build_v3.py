"""Explicit unsigned handoff v3. Consistency checks never authenticate GitHub transport or signatures."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time

from .build import BuildError, _regular_bytes, build_v2, parse_json, verify_inventory_v2
from .common import Failure
from .graph import version

HANDOFF_NAME = "handoff-v3.json"
MAX_HANDOFF = 1024 * 1024
MAX_METADATA = 16 * 1024 * 1024
MAX_ARTIFACT = 1024 * 1024 * 1024


def _require(condition: bool, message: str) -> None:
    """Fail a complete handoff on a static contract error, never return a verified subset."""
    if not condition:
        raise BuildError(message)


def _names(selection: dict) -> dict[str, int]:
    """Derive exactly five leaf names solely from the independently expected selection."""
    key = selection["artifact_id"]
    _require(isinstance(key, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,238}", key),
             "invalid expected handoff selection")
    suffix = ".crate" if selection["profile"] == "library" else ".bin"
    return {key + suffix: MAX_ARTIFACT, key + ".cdx.json": MAX_METADATA,
            key + ".cargo-graph.json": MAX_METADATA, "inventory.json": MAX_METADATA,
            HANDOFF_NAME: MAX_HANDOFF}


def _compare_directory(directory: Path, names: dict[str, int]) -> None:
    """Bound enumeration and reject symlinks, extra/missing leaves and nested or special files."""
    _require(stat.S_ISDIR(directory.lstat().st_mode), "handoff directory must be regular")
    actual = set()
    with os.scandir(directory) as entries:
        for entry in entries:
            _require(len(actual) < 5 and entry.name in names and entry.is_file(follow_symlinks=False),
                     "unexpected handoff entry")
            actual.add(entry.name)
    _require(actual == set(names), "incomplete handoff file set")


def _copy_regular(source: Path, destination: Path, limit: int) -> dict:
    """Copy one bounded regular opened inode to a new private snapshot while hashing exact bytes."""
    before = source.lstat()
    _require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= limit,
             "handoff file type or size")
    digest = hashlib.sha256()
    size = 0
    with source.open("rb") as incoming, destination.open("xb") as outgoing:
        opened = os.fstat(incoming.fileno())
        _require(stat.S_ISREG(opened.st_mode) and
                 (opened.st_dev, opened.st_ino, opened.st_size) ==
                 (before.st_dev, before.st_ino, before.st_size), "handoff file changed during open")
        while True:
            block = incoming.read(min(65536, limit + 1 - size))
            if not block:
                break
            size += len(block)
            _require(size <= limit, "handoff file grew beyond limit")
            digest.update(block)
            outgoing.write(block)
        outgoing.flush()
        os.fsync(outgoing.fileno())
    _require(size == before.st_size, "handoff file size changed")
    destination.chmod(0o400)
    return {"sha256": digest.hexdigest(), "size": size}


def _metadata_identity(directory: Path) -> dict:
    """Hash the exact bounded v2 inventory bytes, without treating its claims as independent authority."""
    data = _regular_bytes(directory / "inventory.json", MAX_METADATA)
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def verify_handoff_v3(directory: Path, expected_selection: dict, expected_context: dict,
                      expected_inputs: dict, expected_root_name: str, expected_package_version: str,
                      expected_tools: dict, *, max_age_seconds: int = 3600,
                      now: int | None = None) -> dict:
    """Match unsigned snapshots to independently supplied source/run/selection/root/tool expectations.

    This does not authenticate artifact transport, claims, timestamps or hosted execution.
    A trusted credentialed finalizer must separately authenticate its exact run-bound transport.
    """
    observed_now = int(time.time()) if now is None else now
    _require(type(observed_now) is int and observed_now > 0 and
             type(max_age_seconds) is int and 0 < max_age_seconds <= 86400,
             "invalid handoff clock or age policy")
    names = _names(expected_selection)
    _compare_directory(directory, names)
    with tempfile.TemporaryDirectory(prefix="armorer-handoff-v3-") as temporary:
        snapshot = Path(temporary)
        identities = {name: _copy_regular(directory / name, snapshot / name, cap)
                      for name, cap in names.items()}
        handoff = parse_json(_regular_bytes(snapshot / HANDOFF_NAME, MAX_HANDOFF))
        required = {"schema_version", "state", "signing_status", "provenance_status", "source",
                    "runtime_commit", "run_id", "run_attempt", "selection", "input_sha256",
                    "build_inventory", "root_component_name", "package_version", "tool_sha256",
                    "observed_build"}
        _require(isinstance(handoff, dict) and set(handoff) == required and
                 type(handoff["schema_version"]) is int and handoff["schema_version"] == 3 and
                 handoff["state"] == "unsigned-handoff" and handoff["signing_status"] == "unsigned" and
                 handoff["provenance_status"] == "not-attested", "unsupported unsigned handoff")
        _require(handoff["selection"] == expected_selection and handoff["input_sha256"] == expected_inputs and
                 all(handoff[key] == expected_context[key]
                     for key in ("source", "runtime_commit", "run_id", "run_attempt")),
                 "handoff source, workflow, run, input or selection mismatch")
        for name in ("run_id", "run_attempt"):
            _require(isinstance(handoff[name], str) and re.fullmatch(r"[1-9][0-9]{0,19}", handoff[name]),
                     "handoff requires explicit bounded run identity")
        _require(handoff["build_inventory"] == identities["inventory.json"], "handoff inventory byte mismatch")
        _require(handoff["root_component_name"] == expected_root_name and
                 isinstance(expected_root_name, str) and 0 < len(expected_root_name) <= 1024 and
                 not any(ord(char) < 32 or ord(char) == 127 for char in expected_root_name) and
                 handoff["package_version"] == expected_package_version and
                 version(expected_package_version, stable=True), "handoff root or version mismatch")
        _require(isinstance(expected_tools, dict) and set(expected_tools) == {"cargo-cyclonedx", "cyclonedx"} and
                 all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
                     for value in expected_tools.values()) and handoff["tool_sha256"] == expected_tools,
                 "handoff independently approved tools mismatch")
        observation = handoff["observed_build"]
        _require(isinstance(observation, dict) and set(observation) == {"started_at", "finished_at"},
                 "invalid handoff build observation")
        start, finish = observation["started_at"], observation["finished_at"]
        _require(type(start) is int and type(finish) is int and
                 0 < start <= finish <= observed_now and observed_now - start <= max_age_seconds,
                 "expired, future or invalid handoff observation")
        # The unchanged v2 reader requires exactly four files. Its private view excludes only the v3 envelope.
        (snapshot / HANDOFF_NAME).unlink()
        inventory = parse_json(_regular_bytes(snapshot / "inventory.json", MAX_METADATA))
        _require(inventory.get("tool_sha256") == expected_tools, "v2 tool identity mismatch")
        verify_inventory_v2(snapshot, inventory, expected_selection, expected_context, expected_inputs,
                            expected_root_name, expected_package_version)
        _compare_directory(directory, names)
        final_now = int(time.time()) if now is None else now
        _require(0 < start <= finish <= final_now and final_now - start <= max_age_seconds,
                 "handoff observation expired during verification")
        return handoff


def build_v3(root: Path, armorer: Path, artifact_id: str, output: Path) -> dict:
    """Retain actual unsigned builder wall-clock observations around the unchanged v2 build operation."""
    started = int(time.time())
    inventory = build_v2(root, armorer, artifact_id, output)
    finished = int(time.time())
    graph = parse_json(_regular_bytes(output / (artifact_id + ".cargo-graph.json"), MAX_METADATA))
    context = {key: inventory[key] for key in ("source", "runtime_commit", "run_id", "run_attempt")}
    handoff = {"schema_version": 3, "state": "unsigned-handoff", "signing_status": "unsigned",
               "provenance_status": "not-attested", **context, "selection": inventory["selection"],
               "input_sha256": inventory["input_sha256"], "build_inventory": _metadata_identity(output),
               "root_component_name": graph["root_component_name"],
               "package_version": graph["selection"]["package_version"],
               "tool_sha256": inventory["tool_sha256"],
               "observed_build": {"started_at": started, "finished_at": finished}}
    with (output / HANDOFF_NAME).open("x") as stream:
        stream.write(json.dumps(handoff, sort_keys=True, indent=2) + "\n")
    verify_handoff_v3(output, inventory["selection"], context, inventory["input_sha256"],
                      handoff["root_component_name"], handoff["package_version"], inventory["tool_sha256"])
    return handoff


def main() -> None:
    """Expose only fixed build selection/output paths; never caller shell, provenance, subjects or signing."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--armorer", type=Path, required=True)
    parser.add_argument("--artifact-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        handoff = build_v3(args.root, args.armorer, args.artifact_id, args.output)
        print(json.dumps({"artifact_id": handoff["selection"]["artifact_id"], "state": handoff["state"],
                          "signing_status": "unsigned", "provenance_status": "not-attested"}, sort_keys=True))
    except (BuildError, Failure, ValueError, OSError, KeyError, TypeError, AttributeError, subprocess.SubprocessError):
        parser.exit(1, "Armorer v3 unsigned handoff failed closed; no authentication or signing performed.\n")


if __name__ == "__main__":
    main()
