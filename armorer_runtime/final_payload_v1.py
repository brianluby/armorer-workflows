"""Own final payload bytes and the acyclic release layout; this is not an authorization adapter.

The credential-free assembler snapshots a complete v3 handoff set, packages Linux
executables without running them, and retains library archives without extracting
them. Its internal inputs must be independently derived by the release controller.
Bundle shape checks never substitute for the separate strict Sigstore consumer.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import dataclass
import gzip
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import tarfile
import tempfile
import time

from .build import parse_json
from .build_v3 import MAX_ARTIFACT, MAX_METADATA, _copy_regular, _names, verify_handoff_v3
from .common import Failure, IDENTIFIER, RUNNERS, require
from .source_transport_v1 import _ref
from .transport_v1 import _identity

INVENTORY = "armorer-release-inventory.json"
INVENTORY_BUNDLE = "armorer-release-inventory.provenance.sigstore.json"
PROVENANCE = "https://slsa.dev/provenance/v1"
SBOM = "https://cyclonedx.org/bom"
MAX_BUNDLE = 16 * 1024 * 1024
MAX_SELECTIONS = 64
MAX_TOTAL = 4 * 1024 * 1024 * 1024
SUFFIXES = {".cdx.json": "cargo-sbom", ".cargo-graph.json": "cargo-graph",
            ".build.json": "build-evidence", ".package.json": "package-evidence",
            ".diagnostic.json": "diagnostic"}


def _json(value: object) -> bytes:
    """Write stable bounded UTF-8 JSON without unsupported numeric values or coercion hooks."""
    import json
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8") + b"\n"
    require(len(data) <= MAX_METADATA, "final metadata exceeds limit")
    return data


def _fields(value: object, names: set[str]) -> None:
    """Reject incomplete records and unrecognized keys before reading producer claims."""
    require(type(value) is dict and set(value) == names, "unsupported final record fields")


def _bytes_identity(data: bytes) -> dict:
    """Identify exact retained bytes without assigning authenticity to their contents."""
    require(type(data) is bytes and 0 < len(data) <= MAX_TOTAL, "invalid final bytes")
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def _byte_identity(value: object) -> None:
    """Require canonical nonempty bounded byte identities, rejecting booleans as sizes."""
    _fields(value, {"sha256", "size"})
    require(type(value["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) and
            type(value["size"]) is int and 0 < value["size"] <= MAX_TOTAL, "invalid final byte identity")


def _workflow(value: object) -> None:
    """Require a complete SHA and the fixed workflow repository with a flat workflow path."""
    _fields(value, {"repository", "path", "commit"})
    require(value["repository"] == "brianluby/armorer-workflows" and
            type(value["path"]) is str and re.fullmatch(r"\.github/workflows/[A-Za-z0-9][A-Za-z0-9_.-]*\.yml", value["path"]) and
            type(value["commit"]) is str and re.fullmatch(r"[0-9a-f]{40}", value["commit"]),
            "invalid final workflow expectation")


def _inputs(value: object) -> None:
    """Check an independently supplied input identity without accepting its review or trust implicitly."""
    _fields(value, {"source", "config_sha256", "lock_sha256", "cargo_lock_sha256", "runtime", "runtime_version", "run"})
    _fields(value["source"], {"repository", "commit", "git_ref"})
    source = value["source"]
    require(type(source["repository"]) is str and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", source["repository"]) and
            type(source["commit"]) is str and re.fullmatch(r"[0-9a-f]{40}", source["commit"]) and
            type(source["git_ref"]) is str and
            (re.fullmatch(r"refs/tags/v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", source["git_ref"]) or
             (source["git_ref"].startswith("refs/heads/") and _ref(source["git_ref"]))),
                "unsupported final source identity")
    for name in ("config_sha256", "lock_sha256", "cargo_lock_sha256"):
        require(type(value[name]) is str and re.fullmatch(r"[0-9a-f]{64}", value[name]), "invalid final input digest")
    _byte_identity(value["runtime"])
    require(value["runtime_version"] == "0.1.0", "unsupported final runtime version")
    _fields(value["run"], {"id", "attempt", "workflow"})
    for name in ("id", "attempt"):
        require(type(value["run"][name]) is int and 0 < value["run"][name] < 2**64, "invalid final run identity")
    _workflow(value["run"]["workflow"])


@dataclass(frozen=True)
class PayloadExpectation:
    """Internal independent source selection; never a public workflow input or credential permit."""
    selection: dict
    context: dict
    input_sha256: dict
    root_component_name: str
    package_version: str
    tool_sha256: dict


@dataclass(frozen=True)
class ReleaseExpectation:
    """Independent controller intent whose syntax does not establish policy or catalog acceptance."""
    inputs: dict
    catalog: dict
    build_workflow: dict
    package_workflow: dict
    selections: tuple[PayloadExpectation, ...]
    build_inputs: tuple[dict, ...]


def _validate_expected(expected: ReleaseExpectation) -> ReleaseExpectation:
    """Copy exact independent expectations before offered bytes; reject Apple executables as a whole set."""
    require(type(expected) is ReleaseExpectation and type(expected.selections) is tuple and
            0 < len(expected.selections) <= MAX_SELECTIONS, "invalid complete final expectation")
    _inputs(expected.inputs)
    _byte_identity(expected.catalog)
    _workflow(expected.build_workflow)
    _workflow(expected.package_workflow)
    require(expected.build_workflow["path"] == ".github/workflows/rust-build-v3.yml", "unsupported handoff builder")
    require(type(expected.build_inputs) is tuple and 0 < len(expected.build_inputs) <= 128, "missing final build input identities")
    for identity in expected.build_inputs:
        _byte_identity(identity)
    keys = set()
    selections = []
    for item in expected.selections:
        require(type(item) is PayloadExpectation, "unsupported final selection expectation")
        case = parse_json(_json(item.selection))
        required = {"id", "profile", "package", "binary", "targets", "target", "feature_set", "default_features",
                    "features", "runner", "artifact_id", "toolchain"}
        _fields(case, required)
        require(case["profile"] in ("library", "cli", "service") and case["target"] in RUNNERS and
                case["runner"] == RUNNERS[case["target"]] and case["toolchain"] == "1.95.0" and
                type(case["default_features"]) is bool and type(case["features"]) is list and
                len(case["features"]) <= 128 and all(type(f) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_+.-]{0,99}", f) for f in case["features"]) and
                case["features"] == sorted(set(case["features"])) and
                type(case["targets"]) is list and case["target"] in case["targets"] and
                len(case["targets"]) == len(set(case["targets"])) and all(t in RUNNERS for t in case["targets"]),
                "invalid final selection")
        for name in ("id", "package", "feature_set"):
            require(type(case[name]) is str and IDENTIFIER.fullmatch(case[name]), "unsafe final selection identifier")
        require((case["profile"] == "library" and case["binary"] is None) or
                (case["profile"] != "library" and type(case["binary"]) is str and IDENTIFIER.fullmatch(case["binary"])),
                "unsafe final binary name")
        require(case["profile"] == "library" or case["target"] != "aarch64-apple-darwin",
                "protected Apple finalization required before final payload assembly")
        key = f'{case["id"]}--{case["target"]}--{case["feature_set"]}'
        require(case["artifact_id"] == key and key not in keys, "duplicate or inconsistent final selection")
        keys.add(key)
        context = parse_json(_json(item.context))
        _fields(context, {"source", "runtime_commit", "run_id", "run_attempt"})
        require(context == {"source": {"repository": expected.inputs["source"]["repository"], "commit": expected.inputs["source"]["commit"]},
                            "runtime_commit": expected.build_workflow["commit"], "run_id": str(expected.inputs["run"]["id"]),
                            "run_attempt": str(expected.inputs["run"]["attempt"])}, "final handoff run/source mismatch")
        inputs = parse_json(_json(item.input_sha256))
        require(inputs.get("armorer.toml") == expected.inputs["config_sha256"] and
                inputs.get("armorer.lock") == expected.inputs["lock_sha256"] and
                inputs.get("Cargo.lock") == expected.inputs["cargo_lock_sha256"], "final handoff input identity mismatch")
        selections.append(PayloadExpectation(case, context, inputs, item.root_component_name,
                                             item.package_version, parse_json(_json(item.tool_sha256))))
    # The strict v3 reader checks root/version/tool/input details against these copies.
    return ReleaseExpectation(parse_json(_json(expected.inputs)), parse_json(_json(expected.catalog)),
                              parse_json(_json(expected.build_workflow)), parse_json(_json(expected.package_workflow)),
                              tuple(selections), tuple(parse_json(_json(v)) for v in expected.build_inputs))


def _elf(path: Path, target: str) -> None:
    """Inspect the fixed ELF64 machine header without executing or loading an offered binary."""
    with path.open("rb") as stream:
        header = stream.read(64)
    require(len(header) == 64 and header[:7] == b"\x7fELF\x02\x01\x01" and
            struct.unpack_from("<H", header, 16)[0] in (2, 3) and
            struct.unpack_from("<H", header, 18)[0] == (62 if target == "x86_64-unknown-linux-gnu" else 183) and
            struct.unpack_from("<I", header, 20)[0] == 1 and struct.unpack_from("<H", header, 52)[0] == 64,
            "offered executable is not the selected Linux ELF64 machine")


def _package(source: Path, destination: Path, item: PayloadExpectation) -> dict:
    """Copy inert crate bytes or archive exactly one regular Linux executable with fixed headers."""
    started = int(time.time())
    before = _identity(source, MAX_ARTIFACT)
    if item.selection["profile"] == "library":
        _copy_regular(source, destination, MAX_ARTIFACT)
    else:
        _elf(source, item.selection["target"])
        with source.open("rb") as incoming, destination.open("xb") as output:
            with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0, compresslevel=9) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                    member = tarfile.TarInfo(item.selection["binary"])
                    member.size = before["size"]
                    member.mode = 0o755
                    member.uid = member.gid = member.mtime = 0
                    member.uname = member.gname = ""
                    archive.addfile(member, incoming)
            output.flush()
            os.fsync(output.fileno())
        destination.chmod(0o400)
    require(_identity(source, MAX_ARTIFACT) == before, "unsigned payload changed during packaging")
    finished = int(time.time())
    require(0 < started <= finished, "package clock rollback")
    return {"input": before, "output": _identity(destination, MAX_ARTIFACT),
            "started_at": started, "finished_at": finished}


def _slot(raw: bytes, name: str, identity: dict, predicate_type: str, predicate: dict | None = None) -> None:
    """Check one exact bundle subject and SBOM document structurally; never claim signature verification."""
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BUNDLE, "invalid final bundle bytes")
    bundle = parse_json(raw)
    _fields(bundle, {"mediaType", "verificationMaterial", "dsseEnvelope"})
    require(bundle["mediaType"] == "application/vnd.dev.sigstore.bundle.v0.3+json" and
            type(bundle["verificationMaterial"]) is dict and bool(bundle["verificationMaterial"]),
            "unsupported final Sigstore material")
    envelope = bundle.get("dsseEnvelope")
    _fields(envelope, {"payload", "payloadType", "signatures"})
    require(envelope.get("payloadType") == "application/vnd.in-toto+json" and
            type(envelope.get("payload")) is str and len(envelope["payload"]) <= MAX_BUNDLE,
            "unsupported final attestation envelope")
    require(type(envelope["signatures"]) is list and len(envelope["signatures"]) == 1 and
            type(envelope["signatures"][0]) is dict and
            {"sig"} <= set(envelope["signatures"][0]) <= {"sig", "keyid"} and
            type(envelope["signatures"][0]["sig"]) is str and
            0 < len(envelope["signatures"][0]["sig"]) <= 16384, "invalid final bundle signature encoding")
    try:
        signature = base64.b64decode(envelope["signatures"][0]["sig"], validate=True)
        require(0 < len(signature) <= 8192, "invalid final bundle signature length")
        payload = base64.b64decode(envelope["payload"], validate=True)
    except (ValueError, TypeError) as error:
        raise Failure("invalid final attestation payload") from error
    statement = parse_json(payload)
    _fields(statement, {"_type", "subject", "predicateType", "predicate"})
    require(statement["_type"] == "https://in-toto.io/Statement/v1" and
            statement["subject"] == [{"name": name, "digest": {"sha256": identity["sha256"]}}] and
            statement["predicateType"] == predicate_type and type(statement["predicate"]) is dict,
            "final bundle subject or predicate mismatch")
    if predicate is not None:
        require(_json(statement["predicate"]) == _json(predicate), "final SBOM predicate document mismatch")


class FinalPayloadSet:
    """A private inert workspace with fixed assembly transitions, never a signing/publication permission."""

    def __init__(self, root: Path, expected: ReleaseExpectation, observations: dict, packages: dict, reserved: int):
        """Retain copied expectations and locally measured transformations inside the managed workspace."""
        self._root, self._expected = root, expected
        self._observations, self._packages = observations, packages
        self._reserved = reserved
        self._files = {p.name: _identity(p, MAX_ARTIFACT if p.name.endswith((".tar.gz", ".crate")) else MAX_METADATA)
                       for p in root.iterdir()}
        self._specs = {}
        self._metadata = set()
        self._state = "payloads-prepared"
        self._inventory = None
        self._inventory_bundle = None
        for item in expected.selections:
            key = item.selection["artifact_id"]
            final = key + (".crate" if item.selection["profile"] == "library" else ".tar.gz")
            self._specs[final] = self._spec(final, "distributable", [], None, None)
            for suffix, role in SUFFIXES.items():
                name = key + suffix
                self._specs[name] = self._spec(name, role, [final], None, None)
            for name in [final, *[key + suffix for suffix in SUFFIXES]]:
                bundle = name + ".provenance.sigstore.json"
                self._specs[bundle] = self._spec(bundle, "attestation-bundle", [name], PROVENANCE, None)
            bundle = final + ".sbom.sigstore.json"
            self._specs[bundle] = self._spec(bundle, "attestation-bundle", [final], SBOM, key + ".cdx.json")

    @staticmethod
    def _spec(name: str, role: str, subjects: list[str], predicate: str | None, predicate_asset: str | None) -> dict:
        """Derive one fixed consumer relationship; bytes are filled only from owned local files."""
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}", name), "final asset name exceeds contract")
        return {"name": name, "role": role, "subjects": subjects, "predicate": predicate,
                "predicate_asset": predicate_asset}

    def _unchanged(self) -> None:
        """Reject additions, deletions and byte mutation before every assembly transition."""
        names = set(self._files)
        actual = set()
        with os.scandir(self._root) as entries:
            for entry in entries:
                require(len(actual) < len(names) and entry.name in names and entry.is_file(follow_symlinks=False),
                        "final payload directory changed")
                actual.add(entry.name)
        require(actual == names, "final payload directory changed")
        for name, identity in self._files.items():
            require(_identity(self._root / name, identity["size"]) == identity, "final payload bytes changed")

    def _write(self, name: str, raw: bytes, limit: int) -> None:
        """Create one allowed private leaf exactly once and retain its observed immutable identity."""
        require(name not in self._files and type(raw) is bytes and 0 < len(raw) <= limit, "duplicate or oversized final leaf")
        require(self._reserved + sum(v["size"] for v in self._files.values()) + len(raw) <= MAX_TOTAL,
                "complete final staging budget exceeded")
        with (self._root / name).open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        (self._root / name).chmod(0o400)
        self._files[name] = _bytes_identity(raw)

    def packaging(self, key: str) -> dict:
        """Return copied actual byte/time measurements for the trusted evidence producer to consume."""
        require(key in self._packages, "unknown final package selection")
        return parse_json(_json(self._packages[key]))

    def subject_path(self, name: str) -> Path:
        """Expose only an already produced fixed subject to the controller's pinned attestation action."""
        require((name in self._specs and self._specs[name]["role"] != "attestation-bundle") or
                (name == INVENTORY and self._state == "inventory-frozen"), "unsupported final attestation subject")
        self._unchanged()
        require(name in self._files, "final attestation subject missing")
        return self._root / name

    def add_evidence(self, key: str, evidence: bytes, diagnostic: bytes) -> None:
        """Retain producer records only when their complete source/run and measured two-step byte chain agree."""
        require(self._state == "payloads-prepared" and key not in self._metadata, "final evidence transition conflict")
        self._unchanged()
        item = next((v for v in self._expected.selections if v.selection["artifact_id"] == key), None)
        require(item is not None and type(evidence) is bytes and 0 < len(evidence) <= MAX_METADATA and
                type(diagnostic) is bytes and 0 < len(diagnostic) <= MAX_METADATA, "unknown or oversized final evidence")
        diagnostic_value = parse_json(diagnostic)
        require(type(diagnostic_value) is dict, "invalid retained platform diagnostic")
        record = parse_json(evidence)
        _fields(record, {"schema_version", "inputs", "selection", "catalog", "runner_label", "runner_image", "recorded_at",
                         "tools", "coverage", "exceptions", "steps", "apple_assertions"})
        case = item.selection
        selection = {"deliverable_id": case["id"], "profile": case["profile"], "package": case["package"],
                     "package_version": item.package_version, "binary": case["binary"], "target": case["target"],
                     "feature_set": case["feature_set"], "default_features": case["default_features"],
                     "features": case["features"], "toolchain": case["toolchain"]}
        require(type(record["schema_version"]) is int and record["schema_version"] == 1 and
                _json(record["inputs"]) == _json(self._expected.inputs) and _json(record["selection"]) == _json(selection) and
                _json(record["catalog"]) == _json(self._expected.catalog) and record["runner_label"] == case["runner"] and
                type(record["runner_image"]) is str and 0 < len(record["runner_image"].strip()) <= 4096 and
                type(record["recorded_at"]) is int and 0 < record["recorded_at"] <= int(time.time()) and
                record["apple_assertions"] is None and type(record["steps"]) is list and len(record["steps"]) == 2,
                "final evidence context mismatch")
        for name in ("tools", "coverage"):
            require(type(record[name]) is list and 0 < len(record[name]) <= 128, "final evidence coverage missing")
        require(type(record["exceptions"]) is list and len(record["exceptions"]) <= 128, "invalid final evidence exceptions")
        measurement = self._packages[key]
        reference = _bytes_identity(diagnostic)
        for index, kind in enumerate(("build", "package")):
            step = record["steps"][index]
            _fields(step, {"kind", "inputs", "output", "run", "started_at", "finished_at", "outcome", "platform_evidence"})
            run = {**self._expected.inputs["run"], "workflow": self._expected.build_workflow if index == 0 else self._expected.package_workflow}
            times = self._observations[key] if index == 0 else measurement
            output = measurement["input"] if index == 0 else measurement["output"]
            input_bytes = list(self._expected.build_inputs) if index == 0 else [measurement["input"]]
            require(_json(step) == _json({"kind": kind, "inputs": input_bytes, "output": output, "run": run,
                             "started_at": times["started_at"], "finished_at": times["finished_at"],
                             "outcome": "passed", "platform_evidence": [reference]}) and
                    step["finished_at"] <= record["recorded_at"], "final transformation measurement mismatch")
        require(record["steps"][0]["finished_at"] <= record["steps"][1]["started_at"], "final transformation clock mismatch")
        self._write(key + ".diagnostic.json", diagnostic, MAX_METADATA)
        self._write(key + ".build.json", evidence, MAX_METADATA)
        self._write(key + ".package.json", evidence, MAX_METADATA)
        self._metadata.add(key)

    def attestation_slots(self) -> tuple[dict, ...]:
        """Return fixed local subject slots without accepting caller names, digests or predicates."""
        self._unchanged()
        require(self._state == "payloads-prepared", "final inventory already frozen")
        return tuple({"bundle": name, "subject": spec["subjects"][0],
                      "bytes": dict(self._files[spec["subjects"][0]]), "predicate": spec["predicate"],
                      "predicate_asset": spec["predicate_asset"]}
                     for name, spec in sorted(self._specs.items()) if spec["role"] == "attestation-bundle" and
                     name not in self._files and spec["subjects"][0] in self._files)

    def add_bundle(self, name: str, raw: bytes) -> None:
        """Attach an exact structurally matching producer bundle; the independent consumer still authenticates it."""
        require(self._state == "payloads-prepared" and name in self._specs and
                self._specs[name]["role"] == "attestation-bundle", "unsupported final bundle slot")
        self._unchanged()
        spec = self._specs[name]
        subject = spec["subjects"][0]
        require(subject in self._files, "final attestation subject not yet produced")
        predicate = parse_json((self._root / spec["predicate_asset"]).read_bytes()) if spec["predicate_asset"] else None
        _slot(raw, subject, self._files[subject], spec["predicate"], predicate)
        self._write(name, raw, MAX_BUNDLE)

    def freeze_inventory(self) -> dict:
        """Freeze the complete acyclic asset set before requesting detached inventory provenance."""
        require(self._state == "payloads-prepared" and self._metadata == set(self._packages), "incomplete final metadata set")
        self._unchanged()
        require(set(self._files) == set(self._specs), "missing or extra final attestation assets")
        inventory = {"schema_version": 1, "inputs": self._expected.inputs,
                     "assets": [{**self._specs[name], "bytes": self._files[name]} for name in sorted(self._specs)]}
        self._write(INVENTORY, _json(inventory), MAX_METADATA)
        self._inventory = inventory
        self._state = "inventory-frozen"
        return {"bundle": INVENTORY_BUNDLE, "subject": INVENTORY, "bytes": dict(self._files[INVENTORY]),
                "predicate": PROVENANCE, "predicate_asset": None}

    def finish(self, inventory_bundle: bytes) -> dict:
        """Complete the detached inventory layout; completion of bytes establishes no release authentication."""
        require(self._state == "inventory-frozen", "invalid final inventory transition")
        self._unchanged()
        _slot(inventory_bundle, INVENTORY, self._files[INVENTORY], PROVENANCE)
        self._write(INVENTORY_BUNDLE, inventory_bundle, MAX_BUNDLE)
        self._state = "layout-complete-unverified"
        self._inventory_bundle = self._files[INVENTORY_BUNDLE]
        self._unchanged()
        return {"state": self._state, "inventory": dict(self._files[INVENTORY]),
                "inventory_bundle": dict(self._inventory_bundle), "assets": len(self._specs),
                "cryptographic_release_authenticated": False, "signing_authorized": False,
                "publication_authorized": False}

    def directory(self) -> Path:
        """Expose only the completed private inert directory for the strict independent consumer."""
        require(self._state == "layout-complete-unverified", "final layout incomplete")
        self._unchanged()
        return self._root


@contextmanager
def prepare_final_payloads(handoffs: dict[str, Path], expected: ReleaseExpectation):
    """Prepare the entire independent selection set transactionally, without credentials or payload execution."""
    copied = _validate_expected(expected)
    keys = {item.selection["artifact_id"] for item in copied.selections}
    require(type(handoffs) is dict and set(handoffs) == keys and all(isinstance(p, Path) for p in handoffs.values()),
            "complete final handoff set mismatch")
    with tempfile.TemporaryDirectory(prefix="armorer-final-payload-v1-") as temporary:
        scratch = Path(temporary)
        scratch.chmod(0o700)
        final = scratch / "final"
        final.mkdir(mode=0o700)
        observations, packages = {}, {}
        total = 0
        for item in copied.selections:
            key = item.selection["artifact_id"]
            source = handoffs[key]
            names = _names(item.selection)
            require(stat.S_ISDIR(source.lstat().st_mode), "invalid complete handoff directory")
            actual = set()
            with os.scandir(source) as entries:
                for entry in entries:
                    require(len(actual) < 5 and entry.name in names and entry.is_file(follow_symlinks=False),
                            "invalid complete handoff directory")
                    actual.add(entry.name)
            require(actual == set(names), "invalid complete handoff directory")
            snapshot = scratch / key
            snapshot.mkdir(mode=0o700)
            for name, limit in names.items():
                size = (source / name).lstat().st_size
                total += size
                require(total <= MAX_TOTAL, "complete handoff set exceeds final staging budget")
                _copy_regular(source / name, snapshot / name, limit)
            handoff = verify_handoff_v3(snapshot, item.selection, item.context, item.input_sha256,
                                       item.root_component_name, item.package_version, item.tool_sha256)
            observations[key] = handoff["observed_build"]
            suffix = ".crate" if item.selection["profile"] == "library" else ".bin"
            final_suffix = ".crate" if item.selection["profile"] == "library" else ".tar.gz"
            packages[key] = _package(snapshot / (key + suffix), final / (key + final_suffix), item)
            for suffix in (".cdx.json", ".cargo-graph.json"):
                _copy_regular(snapshot / (key + suffix), final / (key + suffix), MAX_METADATA)
            require(packages[key]["started_at"] >= observations[key]["finished_at"], "final package predates build")
        require(total + sum(p.stat().st_size for p in final.iterdir()) <= MAX_TOTAL,
                "complete final staging budget exceeded")
        yield FinalPayloadSet(final, copied, observations, packages, total)
