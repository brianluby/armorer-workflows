"""Freeze complete unsigned v3 handoffs and inspect Apple payloads without credentials.

The private workspace is an inert byte snapshot, never signing authorization.
Transport, original writer/OIDC proofs, accepted policy and protected-job evidence
remain separate requirements of the release controller.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
import re
import struct
import tempfile
import time
from types import MappingProxyType

from .build import parse_json
from .build_v3 import MAX_ARTIFACT, _compare_directory, _copy_regular, _names, verify_handoff_v3
from .common import IDENTIFIER, RUNNERS, require
from .final_payload_v1 import PayloadExpectation, _fields, _json
from .transport_v1 import _identity

MAX_SELECTIONS = 64
MAX_TOTAL = 4 * 1024 * 1024 * 1024
MAX_COMMANDS = 4096
MAX_COMMAND_BYTES = 16 * 1024 * 1024
APPLE = "aarch64-apple-darwin"


def _name(raw):
    """Read an inert fixed-width Mach-O name without accepting hidden suffixes or controls."""
    head, separator, tail = raw.partition(b"\0")
    require(head and (not separator or not any(tail)) and
            all(32 <= byte < 127 for byte in head), "Apple Mach-O name invalid")
    return head.decode("ascii")


def _segment(command, size):
    """Bound one segment and every file-backed section, without mapping its virtual addresses."""
    require(len(command) >= 72, "Apple Mach-O segment truncated")
    raw, address, virtual, offset, length, maximum, initial, count, flags = struct.unpack_from("<16sQQQQiiII", command, 8)
    name = _name(raw)
    require(len(command) == 72 + count * 80 and count <= 1024 and
            address + virtual < 2**64 and offset + length <= size and length <= virtual and
            0 <= maximum <= 7 and 0 <= initial <= 7 and initial & maximum == initial,
            "Apple Mach-O segment bounds invalid")
    sections = set()
    for index in range(count):
        section, owner, location, extent, position, alignment, relocations, relocation_count, attributes, _, _, reserved = struct.unpack_from(
            "<16s16sQQ8I", command, 72 + index * 80)
        label = _name(section)
        require(label not in sections and _name(owner) == name and reserved == 0 and
                alignment <= 31 and address <= location <= location + extent <= address + virtual and
                (relocation_count == 0 or relocations + relocation_count * 8 <= size),
                "Apple Mach-O section bounds invalid")
        sections.add(label)
        if attributes & 255 not in (1, 12, 18):  # zerofill has no file-backed bytes
            require(offset <= position <= position + extent <= offset + length,
                    "Apple Mach-O section file bounds invalid")
    return {"name": name, "offset": offset, "size": length, "executable": bool(initial & 4)}


def inspect_macho(path):
    """Inspect bounded thin ARM64 executable headers; never load, execute or authenticate code.

    Unknown load commands retain only generic command-bound checks. This is an
    intake format check, not a complete loader/signature/security assessment.
    """
    identity = _identity(path, MAX_ARTIFACT)
    with path.open("rb") as incoming:
        header = incoming.read(32)
        require(len(header) == 32, "Apple Mach-O header truncated")
        magic, cpu, subtype, kind, count, length, flags, reserved = struct.unpack("<8I", header)
        require(magic == 0xFEEDFACF and cpu == 0x0100000C and subtype == 0 and kind == 2 and reserved == 0,
                "Apple payload is not a supported thin ARM64 executable")
        require(0 < count <= MAX_COMMANDS and count * 8 <= length <= MAX_COMMAND_BYTES and
                32 + length <= identity["size"], "Apple Mach-O command table bounds invalid")
        commands = incoming.read(length)
    require(len(commands) == length, "Apple Mach-O command table truncated")
    offset, segments, entry, dynamic_linker, signature = 0, {}, None, False, None
    for _ in range(count):
        require(offset + 8 <= length, "Apple Mach-O load command truncated")
        kind, extent = struct.unpack_from("<II", commands, offset)
        require(extent >= 8 and extent % 8 == 0 and offset + extent <= length,
                "Apple Mach-O load command bounds invalid")
        command = commands[offset:offset + extent]
        if kind == 0x19:
            segment = _segment(command, identity["size"])
            require(segment["name"] not in segments, "Apple Mach-O duplicate segment")
            segments[segment["name"]] = segment
        elif kind == 0x80000028:
            require(extent == 24 and entry is None, "Apple Mach-O entry point ambiguous")
            entry, _ = struct.unpack_from("<QQ", command, 8)
        elif kind == 0xE:
            require(extent >= 16 and not dynamic_linker, "Apple Mach-O dynamic linker ambiguous")
            start = struct.unpack_from("<I", command, 8)[0]
            require(start == 12 and command[start:].startswith(b"/usr/lib/dyld\0") and
                    not any(command[start + 14:]), "Apple Mach-O dynamic linker unsupported")
            dynamic_linker = True
        elif kind == 0x1D:
            require(extent == 16 and signature is None, "Apple Mach-O signature range ambiguous")
            position, size = struct.unpack_from("<II", command, 8)
            require(32 + length <= position and 0 < size <= MAX_COMMAND_BYTES and
                    position + size <= identity["size"], "Apple Mach-O signature range invalid")
            signature = {"offset": position, "size": size}
        else:
            require(kind not in (0x5, 0x21, 0x2C), "Apple Mach-O legacy or encrypted payload unsupported")
        offset += extent
    require(offset == length, "Apple Mach-O command count mismatch")
    text = segments.get("__TEXT")
    require(dynamic_linker and text is not None and text["offset"] == 0 and text["executable"] and
            entry is not None and 32 + length <= entry < text["size"], "Apple Mach-O entry point invalid")
    ranges = sorted((segment["offset"], segment["offset"] + segment["size"])
                    for segment in segments.values() if segment["size"])
    require(all(left[1] <= right[0] for left, right in zip(ranges, ranges[1:])),
            "Apple Mach-O file segments overlap")
    if signature is not None:
        linkedit = segments.get("__LINKEDIT")
        require(linkedit is not None and linkedit["offset"] <= signature["offset"] and
                signature["offset"] + signature["size"] <= linkedit["offset"] + linkedit["size"],
                "Apple Mach-O signature outside linkedit")
    require(_identity(path, MAX_ARTIFACT) == identity, "Apple Mach-O bytes changed during inspection")
    return {"format": "thin-arm64-macho-executable", "bytes": identity, "load_commands": count,
            "entry_offset": entry, "embedded_signature_range": signature,
            "signature_authenticated": False, "executable_was_run": False}


def _expectations(items):
    """Copy the complete independent selection set and cross-bind source/run/tool/input intent."""
    require(type(items) is tuple and 0 < len(items) <= MAX_SELECTIONS and
            all(type(item) is PayloadExpectation for item in items), "Apple intake expectation set unsupported")
    raw = _json([asdict(item) for item in items])
    require(len(raw) <= 1024 * 1024, "Apple intake expectations exceed bound")
    copied, keys = [], set()
    for record in parse_json(raw):
        item = PayloadExpectation(**record)
        case = item.selection
        _fields(case, {"id", "profile", "package", "binary", "targets", "target", "feature_set", "default_features",
                       "features", "runner", "artifact_id", "toolchain"})
        require(case["profile"] in ("library", "cli", "service") and case["target"] in RUNNERS and
                case["runner"] == RUNNERS[case["target"]] and case["toolchain"] == "1.95.0" and
                type(case["default_features"]) is bool and type(case["features"]) is list and len(case["features"]) <= 128 and
                all(type(feature) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_+.-]{0,99}", feature) for feature in case["features"]) and
                case["features"] == sorted(set(case["features"])) and type(case["targets"]) is list and
                case["target"] in case["targets"] and len(case["targets"]) == len(set(case["targets"])) and
                all(target in RUNNERS for target in case["targets"]), "Apple intake selection invalid")
        require(all(type(case[name]) is str and IDENTIFIER.fullmatch(case[name]) for name in ("id", "package", "feature_set")) and
                ((case["profile"] == "library" and case["binary"] is None) or
                 (case["profile"] != "library" and type(case["binary"]) is str and IDENTIFIER.fullmatch(case["binary"]))),
                "Apple intake selection names invalid")
        key = f'{case["id"]}--{case["target"]}--{case["feature_set"]}'
        require(case["artifact_id"] == key and key not in keys, "Apple intake selection duplicate or inconsistent")
        _fields(item.context, {"source", "runtime_commit", "run_id", "run_attempt"})
        _fields(item.context["source"], {"repository", "commit"})
        require(type(item.context["source"]["repository"]) is str and
                re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", item.context["source"]["repository"]),
                "Apple intake source repository invalid")
        require(all(type(value) is str and re.fullmatch(r"[0-9a-f]{40}", value)
                    for value in (item.context["source"]["commit"], item.context["runtime_commit"])),
                "Apple intake source or workflow pin invalid")
        require(all(type(item.context[name]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", item.context[name]) and
                    int(item.context[name]) < 2**64 for name in ("run_id", "run_attempt")), "Apple intake run identity invalid")
        _fields(item.input_sha256, {"armorer.toml", "armorer.lock", "Cargo.lock"})
        require(all(type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest) for digest in item.input_sha256.values()),
                "Apple intake input identity invalid")
        if copied:
            require(item.context == copied[0].context and item.input_sha256 == copied[0].input_sha256 and
                    item.tool_sha256 == copied[0].tool_sha256, "Apple intake complete contexts differ")
        keys.add(key)
        copied.append(item)
    return tuple(copied)


class ApplePayloadIntake:
    """A live credential-free snapshot; its audit record cannot authorize a signing operation."""

    def __init__(self, root, items, identities, handoffs, payloads, max_age, started):
        """Retain only context-owned paths and independently copied expectations within the context manager."""
        self._root, self._items, self._identities = root, items, identities
        self._handoffs, self._payloads = handoffs, payloads
        self._max_age, self._started, self._wall_started, self._live = max_age, started, int(time.time()), True

    def _fresh(self):
        """Reject expired, closed or clock-reversed snapshots before returning any retained bytes."""
        now = int(time.time())
        require(self._live and self._wall_started <= now and time.monotonic() - self._started <= 1200 and
                all(0 < record["observed_build"]["started_at"] <= record["observed_build"]["finished_at"] <= now and
                    now - record["observed_build"]["started_at"] <= self._max_age for record in self._handoffs.values()),
                "Apple intake closed or expired")

    def _unchanged(self, key):
        """Rehash each exact private leaf and reject additional or substituted snapshot members."""
        self._fresh()
        directory = self._root / key
        names = {name: identity["size"] for name, identity in self._identities[key].items()}
        _compare_directory(directory, names)
        require(all(_identity(directory / name, identity["size"]) == identity
                    for name, identity in self._identities[key].items()), "Apple intake snapshot changed")

    def unsigned_payload_path(self, key):
        """Return a rehashed readonly Mach-O leaf; the caller still needs independent signing authorization."""
        require(type(key) is str and key in self._payloads, "Apple intake payload not selected")
        self._unchanged(key)
        return self._root / key / (key + ".bin")

    def audit(self):
        """Recheck the whole set and return detached identity data with every credential authority false."""
        for key in self._identities:
            self._unchanged(key)
        self._fresh()
        return parse_json(_json({"schema_version": 1, "state": "unsigned-apple-payloads-inspected",
            "context": self._items[0].context, "input_sha256": self._items[0].input_sha256,
            "complete_selection_set": sorted(self._identities), "handoff_leaf_identities": self._identities,
            "apple_payloads": self._payloads, "complete_handoff_set_verified": True,
            "producer_job_authenticated": False, "artifact_producer_authenticated": False,
            "production_catalog_accepted": False, "protected_environment_authenticated": False,
            "cryptographic_release_authenticated": False, "signing_authorized": False,
            "publication_authorized": False, "executable_was_run": False}))


@contextmanager
def prepare_apple_payloads(directories, items, *, max_age_seconds=3600):
    """Verify and freeze the whole v3 set before exposing any inert Apple payload; clean up every exit."""
    items = _expectations(items)
    require(type(max_age_seconds) is int and 0 < max_age_seconds <= 86400 and
            type(directories) in (dict, MappingProxyType) and
            set(directories) == {item.selection["artifact_id"] for item in items}, "Apple intake complete file set invalid")
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="armorer-apple-intake-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        identities, handoffs, payloads, total = {}, {}, {}, 0
        intake = None
        try:
            for item in items:
                key = item.selection["artifact_id"]
                source = directories[key]
                require(isinstance(source, Path), "Apple intake directory type invalid")
                names = _names(item.selection)
                _compare_directory(source, names)
                destination = root / key
                destination.mkdir(mode=0o700)
                identities[key] = {}
                for name, bound in names.items():
                    require(total + (source / name).lstat().st_size <= MAX_TOTAL, "Apple intake staging budget exceeded")
                    measured = _copy_regular(source / name, destination / name, min(bound, MAX_TOTAL - total))
                    total += measured["size"]
                    identities[key][name] = measured
                require(total + sum(record["size"] for record in identities[key].values()) <= MAX_TOTAL,
                        "Apple intake verification staging budget exceeded")
                handoffs[key] = verify_handoff_v3(destination, item.selection, item.context, item.input_sha256,
                    item.root_component_name, item.package_version, item.tool_sha256, max_age_seconds=max_age_seconds)
                if item.selection["target"] == APPLE and item.selection["profile"] != "library":
                    payloads[key] = {"binary": item.selection["binary"], "inspection": inspect_macho(destination / (key + ".bin")),
                        "observed_build": handoffs[key]["observed_build"]}
            intake = ApplePayloadIntake(root, items, identities, handoffs, payloads, max_age_seconds, started)
            intake.audit()
            yield intake
            intake.audit()
        finally:
            if intake is not None:
                intake._live = False
