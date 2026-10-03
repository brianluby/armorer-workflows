"""Adversarial Apple intake tests; inert Mach-O fixtures do not establish signing qualification."""
import copy
import hashlib
import json
from pathlib import Path
import stat
import struct
import tempfile
from types import MappingProxyType
import unittest
from unittest import mock

from armorer_runtime import apple_payload_v1 as apple
from armorer_runtime.build import BuildError, _file_record
from armorer_runtime.build_v3 import HANDOFF_NAME, _metadata_identity
from armorer_runtime.common import Failure
from test_build_final_payload_v1 import create, encoded


def segment(name=b"__TEXT", offset=0, size=1024, protection=5, sections=b""):
    """Build one inert segment whose file-backed range can be independently corrupted."""
    return struct.pack("<II16sQQQQiiII", 0x19, 72 + len(sections), name,
        0x100000000 + offset, max(size, 4096), offset, size, 7, protection, len(sections) // 80, 0) + sections


def macho(extra=(), *, header_changes=None, text=None, entry=512, linker=b"/usr/lib/dyld\0", platform=1):
    """Create an inert thin ARM64 executable layout, never a runnable or signed positive control."""
    padded = linker + b"\0" * (-(12 + len(linker)) % 8)
    commands = [text if text is not None else segment(), struct.pack("<III", 0xE, 12 + len(padded), 12) + padded,
                struct.pack("<IIQQ", 0x80000028, 24, entry, 0), *extra]
    if platform is not None:
        commands.append(struct.pack("<6I", 0x32, 24, platform, 0xB0000, 0xF0000, 0))
    joined = b"".join(commands)
    fields = [0xFEEDFACF, 0x0100000C, 0, 2, len(commands), len(joined), 0x200004, 0]
    for index, value in (header_changes or {}).items():
        fields[index] = value
    return (struct.pack("<8I", *fields) + joined).ljust(1024, b"\0")


def fixture(root, *, profile="cli", target=apple.APPLE, name="app", payload=None):
    """Rebind complete synthetic v3 metadata to explicitly supplied inert Apple test bytes."""
    directory, item, handoff = create(root, profile, target, name)
    if profile != "library" and target == apple.APPLE:
        key = item.selection["artifact_id"]
        path = directory / (key + ".bin")
        path.write_bytes(macho() if payload is None else payload)
        inventory_path = directory / "inventory.json"
        inventory = json.loads(inventory_path.read_bytes())
        inventory["files"] = [_file_record(path, "artifact") if value["role"] == "artifact" else value for value in inventory["files"]]
        inventory_path.write_bytes(encoded(inventory))
        handoff["build_inventory"] = _metadata_identity(directory)
        (directory / HANDOFF_NAME).write_bytes(encoded(handoff))
    return directory, item


def rebind(directory, item):
    """Bind synthetic sibling declarations and independently supplied tools to all affected v3 records."""
    inventory_path = directory / "inventory.json"
    inventory = json.loads(inventory_path.read_bytes())
    inventory.update(selection=item.selection, tool_sha256=item.tool_sha256)
    inventory_path.write_bytes(encoded(inventory))
    handoff_path = directory / HANDOFF_NAME
    handoff = json.loads(handoff_path.read_bytes())
    handoff.update(selection=item.selection, tool_sha256=item.tool_sha256, build_inventory=_metadata_identity(directory))
    handoff_path.write_bytes(encoded(handoff))


class ApplePayloadTests(unittest.TestCase):
    """Exercise complete-set snapshots, format limits and expiry with no signing or execution."""

    def inspect(self, data):
        """Inspect exactly the supplied inert bytes in a test-owned regular file."""
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "payload"
            path.write_bytes(data)
            return apple.inspect_macho(path)

    def test_complete_native_profile_set_is_snapshotted_without_authority(self):
        """Bind Apple CLI/service, opaque source libraries and Linux bytes as one unchanged whole set."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases = [fixture(root, name="app"), fixture(root, profile="service", name="daemon"),
                     fixture(root, profile="library", name="library"), fixture(root, target="x86_64-unknown-linux-gnu", name="linux")]
            directories = {item.selection["artifact_id"]: path for path, item in cases}
            with apple.prepare_apple_payloads(directories, tuple(item for _, item in cases)) as intake:
                audit = intake.audit()
                self.assertEqual(len(audit["complete_selection_set"]), 4)
                self.assertEqual(len(audit["apple_payloads"]), 2)
                for key, value in audit["apple_payloads"].items():
                    path = intake.unsigned_payload_path(key)
                    private_root = path.parent.parent
                    self.assertEqual(path.read_bytes(), macho())
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
                    self.assertEqual(stat.S_IMODE(private_root.stat().st_mode), 0o700)
                    self.assertEqual(value["inspection"]["bytes"]["sha256"], hashlib.sha256(macho()).hexdigest())
                self.assertTrue(audit["complete_handoff_set_verified"])
                for field in ("producer_job_authenticated", "artifact_producer_authenticated", "production_catalog_accepted",
                    "protected_environment_authenticated", "cryptographic_release_authenticated", "signing_authorized", "publication_authorized", "executable_was_run"):
                    self.assertIs(audit[field], False)
            self.assertFalse(private_root.exists())
            with self.assertRaises(Failure):
                intake.audit()

    def test_missing_extra_and_duplicate_selections_fail_before_staging(self):
        """Reject incomplete and foreign sets before creating a workspace or exposing a subset."""
        with tempfile.TemporaryDirectory() as temporary:
            directory, item = fixture(Path(temporary))
            key = item.selection["artifact_id"]
            cases = [({}, (item,)), ({key: directory, "extra": directory}, (item,)),
                     ({key: directory}, (item, item)), ({key: directory}, ()), ({key: directory}, (item,) * 65)]
            for directories, items in cases:
                with self.subTest(items=len(items)), mock.patch.object(apple.tempfile, "TemporaryDirectory") as staging:
                    with self.assertRaises(Failure), apple.prepare_apple_payloads(directories, items):
                        self.fail("invalid complete set yielded")
                    staging.assert_not_called()

    def test_independent_contexts_cannot_cross_runs_sources_workflows_tools_or_inputs(self):
        """Reject conflicting intent before offered handoff metadata can define its own expectations."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            one, first = fixture(root)
            two, second = fixture(root, name="other")
            key_one, key_two = first.selection["artifact_id"], second.selection["artifact_id"]
            for field in ("run_id", "run_attempt", "runtime_commit", "source", "tools", "inputs"):
                offered = copy.deepcopy(second)
                if field == "source":
                    offered.context[field]["commit"] = "c" * 40
                elif field == "tools":
                    offered.tool_sha256["cyclonedx"] = "d" * 64
                elif field == "inputs":
                    offered.input_sha256["Cargo.lock"] = "e" * 64
                else:
                    offered.context[field] = "9" if field.startswith("run_") else "f" * 40
                with self.subTest(field=field), mock.patch.object(apple.tempfile, "TemporaryDirectory") as staging:
                    with self.assertRaises(Failure), apple.prepare_apple_payloads({key_one: one, key_two: two}, (first, offered)):
                        self.fail("cross-context set yielded")
                    staging.assert_not_called()

    def test_every_declared_target_requires_a_matching_sibling_before_staging(self):
        """Reject an omitted Linux sibling even when the offered and expected key sets both omit it."""
        with tempfile.TemporaryDirectory() as temporary:
            directory, item = fixture(Path(temporary))
            item.selection["targets"] = [apple.APPLE, "x86_64-unknown-linux-gnu"]
            with mock.patch.object(apple.tempfile, "TemporaryDirectory") as staging:
                with self.assertRaisesRegex(Failure, "target sibling missing"), apple.prepare_apple_payloads(
                    {item.selection["artifact_id"]: directory}, (item,)):
                    self.fail("missing declared target yielded")
                staging.assert_not_called()

    def test_sibling_declarations_cannot_disagree_on_features_or_package_identity(self):
        """Reject same-deliverable target siblings with conflicting declarations or package expectations."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first_path, first = fixture(root)
            second_path, second = fixture(root, target="x86_64-unknown-linux-gnu")
            for item in (first, second):
                item.selection["targets"] = [apple.APPLE, "x86_64-unknown-linux-gnu"]
            for field in ("targets", "features", "default_features", "package_version", "root_component_name"):
                altered = copy.deepcopy(second)
                if field == "targets":
                    altered.selection[field] = ["x86_64-unknown-linux-gnu"]
                elif field == "features":
                    altered.selection[field] = ["other"]
                elif field == "default_features":
                    altered.selection[field] = not altered.selection[field]
                else:
                    from dataclasses import replace
                    altered = replace(altered, **{field: "9.9.9" if field == "package_version" else "other"})
                directories = {first.selection["artifact_id"]: first_path, altered.selection["artifact_id"]: second_path}
                with self.subTest(field=field), mock.patch.object(apple.tempfile, "TemporaryDirectory") as staging:
                    with self.assertRaisesRegex(Failure, "sibling declarations differ"), apple.prepare_apple_payloads(directories, (first, altered)):
                        self.fail("conflicting siblings yielded")
                    staging.assert_not_called()

    def test_complete_target_siblings_allow_independent_native_tool_hashes(self):
        """Retain genuine per-target tool identities without requiring Linux and macOS binaries to hash alike."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases = [fixture(root), fixture(root, target="x86_64-unknown-linux-gnu")]
            for index, (directory, item) in enumerate(cases):
                item.selection["targets"] = [apple.APPLE, "x86_64-unknown-linux-gnu"]
                item.tool_sha256.update({"cargo-cyclonedx": str(index + 7) * 64, "cyclonedx": str(index + 1) * 64})
                rebind(directory, item)
            with apple.prepare_apple_payloads({item.selection["artifact_id"]: directory for directory, item in cases},
                tuple(item for _, item in cases)) as intake:
                self.assertEqual(len(intake.audit()["complete_selection_set"]), 2)
                self.assertEqual(len(intake.audit()["apple_payloads"]), 1)

    def test_offered_run_and_payload_digest_substitutions_fail_closed(self):
        """Detect substitutions in exact v3 metadata and artifact bytes before returning an intake object."""
        for kind in ("run", "payload"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                directory, item = fixture(Path(temporary))
                key = item.selection["artifact_id"]
                if kind == "run":
                    path = directory / HANDOFF_NAME
                    record = json.loads(path.read_bytes())
                    record["run_attempt"] = "3"
                    path.write_bytes(encoded(record))
                else:
                    (directory / (key + ".bin")).write_bytes(macho(entry=520))
                with self.assertRaises((Failure, BuildError)), apple.prepare_apple_payloads({key: directory}, (item,)):
                    self.fail("substituted handoff yielded")

    def test_wrong_binary_formats_architectures_and_file_kinds_are_rejected(self):
        """Reject scripts, ELF, universal/32-bit headers, ARM64e and dylibs without executing them."""
        cases = [b"#!/bin/sh\nexit 0\n", b"\x7fELF" + b"\0" * 100, b"\xca\xfe\xba\xbe" + b"\0" * 100,
            macho(header_changes={0: 0xFEEDFACE}), macho(header_changes={1: 0x01000007}),
            macho(header_changes={2: 2}), macho(header_changes={3: 6}), macho(header_changes={7: 1})]
        for data in cases:
            with self.subTest(prefix=data[:4]), self.assertRaises(Failure):
                self.inspect(data)

    def test_header_and_command_count_bounds_are_independent(self):
        """Reject truncated and overlarge command tables and dishonest command counts."""
        for data in [macho()[:31], macho()[:200], macho(header_changes={4: 0}), macho(header_changes={4: 4097}),
                     macho(header_changes={5: apple.MAX_COMMAND_BYTES + 1}), macho(header_changes={4: 5})]:
            with self.subTest(size=len(data)), self.assertRaises(Failure):
                self.inspect(data)

    def test_macos_platform_is_required_unambiguous_and_structurally_bounded(self):
        """Reject iOS/Catalyst, absent or conflicting platform declarations and malformed build-version tools."""
        legacy = struct.pack("<4I", 0x24, 16, 0xB0000, 0xF0000)
        self.assertEqual(self.inspect(macho())["platform"]["name"], "macos")
        self.assertEqual(self.inspect(macho([legacy], platform=None))["platform"]["name"], "macos")
        commands = [struct.pack("<6I", 0x32, 24, 1, 0xB0000, 0xF0000, 1),
                    struct.pack("<6I", 0x32, 24, 1, 0, 0xF0000, 0),
                    struct.pack("<II", 0x32, 8), struct.pack("<4I", 0x25, 16, 0xB0000, 0xF0000),
                    struct.pack("<4I", 0x2F, 16, 0xB0000, 0xF0000), struct.pack("<4I", 0x30, 16, 0xB0000, 0xF0000)]
        cases = [macho(platform=None), macho(platform=2), macho(platform=6), macho(platform=99),
                 macho([legacy]), macho([legacy, legacy], platform=None),
                 *[macho([command], platform=None) for command in commands]]
        for data in cases:
            with self.subTest(digest=hashlib.sha256(data).hexdigest()), self.assertRaises(Failure):
                self.inspect(data)

    def test_misaligned_short_overrunning_and_unsupported_commands_fail(self):
        """Stop malformed command iteration and explicitly unsupported encrypted or legacy entry layouts."""
        for command in [struct.pack("<II", 7, 0), struct.pack("<II", 7, 9) + b"\0",
            struct.pack("<II", 7, 2048), struct.pack("<II", 0x5, 8),
            struct.pack("<II", 0x21, 8), struct.pack("<II", 0x2C, 8)]:
            with self.subTest(command=command[:4]), self.assertRaises(Failure):
                self.inspect(macho([command]))

    def test_entry_point_must_be_unique_and_inside_executable_text_after_headers(self):
        """Reject entry points in metadata, outside file-backed text or duplicated by a second LC_MAIN."""
        for data in [macho(entry=16), macho(entry=1024), macho(text=segment(protection=3)),
            macho([struct.pack("<IIQQ", 0x80000028, 24, 520, 0)]), macho([struct.pack("<II", 0x80000028, 8)])]:
            with self.assertRaises(Failure):
                self.inspect(data)

    def test_dynamic_linker_is_unique_and_fixed(self):
        """Reject non-system, unterminated or duplicated dynamic-linker command strings."""
        extra = struct.pack("<III", 0xE, 32, 12) + b"/usr/lib/dyld\0" + b"\0" * 6
        for data in [macho(linker=b"/tmp/evil\0"), macho(linker=b"/usr/lib/dyldX"), macho([extra])]:
            with self.assertRaises(Failure):
                self.inspect(data)

    def test_segments_cannot_duplicate_overlap_or_escape_file(self):
        """Reject overlapping segment file ranges and file or virtual range overflows."""
        for data in [macho([segment()]), macho([segment(b"__DATA", 900, 100)]),
                     macho(text=segment(size=2048)), macho(text=segment(protection=8))]:
            with self.assertRaises(Failure):
                self.inspect(data)

    def test_sections_must_belong_to_their_bounded_file_and_virtual_segment(self):
        """Inspect section records while permitting actual zero-fill sections with no file data."""
        valid = struct.pack("<16s16sQQ8I", b"__text", b"__TEXT", 0x100000200, 64, 512, 2, 0, 0, 0, 0, 0, 0)
        self.inspect(macho(text=segment(sections=valid)))
        zero = struct.pack("<16s16sQQ8I", b"__bss", b"__TEXT", 0x100000800, 64, 0, 2, 0, 0, 1, 0, 0, 0)
        self.inspect(macho(text=segment(sections=zero)))
        for change in [("<I", 48, 2000), ("<I", 52, 32), ("<I", 56, 1000), ("<I", 76, 1)]:
            altered = bytearray(valid)
            struct.pack_into(change[0], altered, change[1], change[2])
            if change[1] == 56:
                struct.pack_into("<I", altered, 60, 100)
            with self.subTest(offset=change[1]), self.assertRaises(Failure):
                self.inspect(macho(text=segment(sections=bytes(altered))))

    def test_embedded_signature_range_is_bounded_but_never_authenticated(self):
        """Admit a bounded linkedit range without treating synthetic or ad-hoc bytes as Developer ID."""
        command = struct.pack("<IIII", 0x1D, 16, 900, 100)
        data = macho([segment(b"__LINKEDIT", 800, 224, 1), command], text=segment(size=800))
        result = self.inspect(data)
        self.assertEqual(result["embedded_signature_range"], {"offset": 900, "size": 100})
        self.assertIs(result["signature_authenticated"], False)
        for data in [macho([command]), macho([command, command]), macho([struct.pack("<IIII", 0x1D, 16, 900, 200)])]:
            with self.assertRaises(Failure):
                self.inspect(data)

    def test_unknown_commands_are_only_checked_for_generic_bounds(self):
        """Keep the format-check limitation explicit rather than claiming complete loader validation."""
        self.inspect(macho([struct.pack("<II", 0x777, 8)]))

    def test_mutation_extra_leaf_and_symlink_are_rejected_after_snapshot(self):
        """Rehash retained leaves on use and fail before a modified private payload can be returned."""
        for mode in ("payload", "extra", "symlink"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                directory, item = fixture(Path(temporary))
                key = item.selection["artifact_id"]
                with self.assertRaises((Failure, BuildError)):
                    with apple.prepare_apple_payloads({key: directory}, (item,)) as intake:
                        path = intake.unsigned_payload_path(key)
                        if mode == "extra":
                            (path.parent / "extra").write_bytes(b"extra")
                        else:
                            path.chmod(0o600)
                            path.unlink()
                            if mode == "symlink":
                                path.symlink_to(directory / (key + ".bin"))
                            else:
                                path.write_bytes(macho(entry=520))
                        intake.unsigned_payload_path(key)
                self.assertFalse(intake._root.exists())

    def test_source_and_detached_audit_changes_cannot_mutate_private_snapshot(self):
        """Freeze input bytes and deep-copy expectations and detached audit data before handing paths onward."""
        with tempfile.TemporaryDirectory() as temporary:
            directory, item = fixture(Path(temporary))
            key = item.selection["artifact_id"]
            with apple.prepare_apple_payloads({key: directory}, (item,)) as intake:
                original = intake.unsigned_payload_path(key).read_bytes()
                (directory / (key + ".bin")).write_bytes(b"changed outside private snapshot")
                item.context["run_id"] = "99"
                audit = intake.audit()
                audit["context"]["run_id"] = "99"
                audit["apple_payloads"][key]["inspection"]["bytes"]["sha256"] = "0" * 64
                self.assertEqual(intake.unsigned_payload_path(key).read_bytes(), original)
                self.assertEqual(intake.audit()["context"]["run_id"], "17")

    def test_expiry_and_wall_clock_rollback_block_every_access(self):
        """Revalidate build age, monotonic stage lifetime and non-reversed wall clock before use."""
        for mode in ("age", "wall", "monotonic"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                directory, item = fixture(Path(temporary))
                key = item.selection["artifact_id"]
                with self.assertRaises(Failure):
                    with apple.prepare_apple_payloads({key: directory}, (item,)) as intake:
                        if mode == "monotonic":
                            with mock.patch.object(apple.time, "monotonic", return_value=intake._started + 1201):
                                intake.audit()
                        else:
                            value = intake._wall_started + 86401 if mode == "age" else intake._wall_started - 1
                            with mock.patch.object(apple.time, "time", return_value=value):
                                intake.unsigned_payload_path(key)
                self.assertFalse(intake._root.exists())

    def test_downstream_exception_cleans_up_the_entire_workspace(self):
        """Delete all private leaves on an error after entry without altering the original handoff."""
        with tempfile.TemporaryDirectory() as temporary:
            directory, item = fixture(Path(temporary))
            key = item.selection["artifact_id"]
            with self.assertRaisesRegex(RuntimeError, "downstream"):
                with apple.prepare_apple_payloads({key: directory}, (item,)) as intake:
                    private = intake.unsigned_payload_path(key).parent.parent
                    raise RuntimeError("downstream")
            self.assertFalse(private.exists())
            self.assertTrue((directory / HANDOFF_NAME).exists())

    def test_staging_budget_rejects_without_a_partial_intake(self):
        """Reject insufficient space budget before yielding any payload, even when its metadata is consistent."""
        with tempfile.TemporaryDirectory() as temporary:
            directory, item = fixture(Path(temporary))
            key = item.selection["artifact_id"]
            with mock.patch.object(apple, "MAX_TOTAL", 8), self.assertRaises(Failure):
                with apple.prepare_apple_payloads({key: directory}, (item,)):
                    self.fail("overbudget set yielded")

    def test_malformed_independent_selection_boolean_and_run_ids_fail_before_staging(self):
        """Reject bool/integer equality confusion and malformed source/job expectations before copying bytes."""
        with tempfile.TemporaryDirectory() as temporary:
            directory, item = fixture(Path(temporary))
            key = item.selection["artifact_id"]
            for mode in ("boolean", "run", "source", "binary"):
                offered = copy.deepcopy(item)
                if mode == "boolean":
                    offered.selection["default_features"] = 1
                elif mode == "run":
                    offered.context["run_id"] = True
                elif mode == "source":
                    offered.context["source"]["commit"] = "moving-main"
                else:
                    offered.selection["binary"] = "../escape"
                with self.subTest(mode=mode), mock.patch.object(apple.tempfile, "TemporaryDirectory") as staging:
                    with self.assertRaises(Failure), apple.prepare_apple_payloads({key: directory}, (offered,)):
                        self.fail("invalid intent yielded")
                    staging.assert_not_called()

    def test_library_only_set_does_not_manufacture_an_apple_payload(self):
        """Keep source libraries opaque and deny executable path requests when no Apple binary is selected."""
        with tempfile.TemporaryDirectory() as temporary:
            directory, item = fixture(Path(temporary), profile="library")
            key = item.selection["artifact_id"]
            with apple.prepare_apple_payloads(MappingProxyType({key: directory}), (item,)) as intake:
                self.assertEqual(intake.audit()["apple_payloads"], {})
                with self.assertRaises(Failure):
                    intake.unsigned_payload_path(key)
