"""Final-byte layout and transformation tests; all platform/signature records here are synthetic."""
import base64
import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import time
import unittest
from unittest import mock

from armorer_runtime import final_payload_v1 as final
from armorer_runtime.build import BuildError, _file_record
from armorer_runtime.build_v3 import HANDOFF_NAME, _metadata_identity
from armorer_runtime.common import Failure, RUNNERS
from test_build_graph_v2 import CONTEXT, INPUTS, expectation, fixture
from test_build_handoff_v3 import TOOLS


def encoded(value):
    """Encode explicit test records without using them as policy or platform authority."""
    return json.dumps(value, sort_keys=True).encode() + b"\n"


def identity(data):
    """Hash test-owned bytes independently of the producer's helper."""
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def elf(machine=62):
    """Create an inert ELF64 header and payload; this is not a live compiler or executable qualification."""
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", header, 16, 2, machine, 1)
    struct.pack_into("<H", header, 52, 64)
    return bytes(header) + b"synthetic nonexecuted payload\n"


def create(root, profile="cli", target="x86_64-unknown-linux-gnu", deliverable="app"):
    """Create complete synthetic v3 snapshots with separately fixed selection/source/tool expectations."""
    kind = "zero-library" if profile == "library" else "minimal"
    selected, root_name = expectation(kind)
    selected.update(id=deliverable, profile=profile, target=target, targets=[target], runner=RUNNERS[target],
                    artifact_id=f"{deliverable}--{target}--minimal")
    if profile == "library":
        selected["binary"] = None
    graph, bom = fixture(kind)
    graph["selection"].update(deliverable_id=deliverable, profile=profile, target=target, binary=selected["binary"])
    key = selected["artifact_id"]
    directory = root / key
    directory.mkdir()
    payload = b"opaque source archive, never extracted\n" if profile == "library" else elf(183 if target.startswith("aarch64") else 62)
    suffix = ".crate" if profile == "library" else ".bin"
    paths = [(directory / (key + suffix), "artifact", payload), (directory / (key + ".cdx.json"), "sbom", bom),
             (directory / (key + ".cargo-graph.json"), "cargo-graph", encoded(graph))]
    for path, _, data in paths:
        path.write_bytes(data)
    inventory = {"schema_version": 2, "cargo_graph_version": 2, "state": "build-produced",
                 "signing_status": "unsigned", "provenance_status": "not-attested", **CONTEXT,
                 "selection": selected, "input_sha256": INPUTS, "source_input_sha256": {"Cargo.toml": "6" * 64},
                 "tool_sha256": TOOLS, "tool_pin_authority": "immutable-trusted-workflow-catalog",
                 "graph_scope": "compiled-cargo-target-and-host-build-dependencies",
                 "coverage_gaps": ["native scope incomplete", "host/target units aggregated"],
                 "artifact_kind": "source-package" if profile == "library" else "executable",
                 "files": [_file_record(path, role) for path, role, _ in paths]}
    (directory / "inventory.json").write_bytes(encoded(inventory))
    now = int(time.time())
    envelope = {"schema_version": 3, "state": "unsigned-handoff", "signing_status": "unsigned", "provenance_status": "not-attested",
                **CONTEXT, "selection": selected, "input_sha256": INPUTS, "build_inventory": _metadata_identity(directory),
                "root_component_name": root_name, "package_version": "0.1.0", "tool_sha256": TOOLS,
                "observed_build": {"started_at": now - 3, "finished_at": now - 2}}
    (directory / HANDOFF_NAME).write_bytes(encoded(envelope))
    item = final.PayloadExpectation(copy.deepcopy(selected), copy.deepcopy(CONTEXT), copy.deepcopy(INPUTS), root_name, "0.1.0", copy.deepcopy(TOOLS))
    return directory, item, envelope


def expected(items):
    """Use explicit synthetic authorities, not downloaded metadata, to define the expected full layout."""
    build = {"repository": "brianluby/armorer-workflows", "path": ".github/workflows/rust-build-v3.yml", "commit": "b" * 40}
    package = {"repository": "brianluby/armorer-workflows", "path": ".github/workflows/release-cli.yml", "commit": "b" * 40}
    runtime = identity(b"synthetic reviewed runtime fixture; no acceptance")
    inputs = {"source": {**CONTEXT["source"], "git_ref": "refs/tags/v0.1.0"}, "config_sha256": INPUTS["armorer.toml"],
              "lock_sha256": INPUTS["armorer.lock"], "cargo_lock_sha256": INPUTS["Cargo.lock"], "runtime": runtime,
              "runtime_version": "0.1.0", "run": {"id": 17, "attempt": 2, "workflow": package}}
    return final.ReleaseExpectation(inputs, identity(b"synthetic catalog; no approval"), build, package, tuple(items), (runtime,))


def evidence(plan, item, assembly, envelope):
    """Create schema-consistent synthetic producer assertions from actual package measurements, never a private proof."""
    key = item.selection["artifact_id"]
    measurement = assembly.packaging(key)
    diagnostic = encoded({"scope": "synthetic fixture only", "source": plan.inputs["source"], "run": plan.inputs["run"], "selection": key})
    case = item.selection
    selected = {"deliverable_id": case["id"], "profile": case["profile"], "package": case["package"], "package_version": item.package_version,
                "binary": case["binary"], "target": case["target"], "feature_set": case["feature_set"], "default_features": case["default_features"],
                "features": case["features"], "toolchain": case["toolchain"]}
    steps = []
    for index, kind in enumerate(("build", "package")):
        times = envelope["observed_build"] if index == 0 else measurement
        steps.append({"kind": kind, "inputs": list(plan.build_inputs) if index == 0 else [measurement["input"]],
                      "output": measurement["input"] if index == 0 else measurement["output"],
                      "run": {**plan.inputs["run"], "workflow": plan.build_workflow if index == 0 else plan.package_workflow},
                      "started_at": times["started_at"], "finished_at": times["finished_at"], "outcome": "passed", "platform_evidence": [identity(diagnostic)]})
    now = int(time.time())
    record = {"schema_version": 1, "inputs": plan.inputs, "selection": selected, "catalog": plan.catalog,
              "runner_label": case["runner"], "runner_image": "synthetic fixture; hosted image unqualified", "recorded_at": now,
              "tools": [{"name": "fixture", "kind": "helper", "version": "0.1.0", "bytes": identity(b"fixture helper"),
                         "authentication_record": identity(b"fixture record; not upstream approval"), "observed_at": now, "max_age_seconds": None}],
              "coverage": [{"capability": "cargo-sbom", "scope": "synthetic Cargo graph fixture", "tested_subject": measurement["output"],
                            "omissions": ["synthetic only; does not prove live enforcement"], "outcome": "passed", "enforcement": "enforced", "exception_ids": []}],
              "exceptions": [], "steps": steps, "apple_assertions": None}
    return record, diagnostic


def bundle(slot, predicate=None, **changes):
    """Create structurally matching deliberately invalid signatures; these must never count as crypto qualification."""
    statement = {"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": slot["subject"], "digest": {"sha256": slot["bytes"]["sha256"]}}],
                 "predicateType": slot["predicate"], "predicate": predicate if predicate is not None else {"fixture": "synthetic; no source authenticity"}}
    statement.update(changes)
    return encoded({"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"certificate": {"rawBytes": base64.b64encode(b"not a certificate").decode()}},
                    "dsseEnvelope": {"payloadType": "application/vnd.in-toto+json", "payload": base64.b64encode(encoded(statement)).decode(),
                                     "signatures": [{"sig": base64.b64encode(b"deliberately invalid synthetic signature").decode()}]}})


def attach_all(assembly):
    """Attach every fixed synthetic slot, using the exact retained SBOM predicate document."""
    for slot in assembly.attestation_slots():
        predicate = json.loads(assembly.subject_path(slot["predicate_asset"]).read_bytes()) if slot["predicate_asset"] else None
        assembly.add_bundle(slot["bundle"], bundle(slot, predicate))


class FinalPayloadTests(unittest.TestCase):
    """Exercise real byte transforms and complete-set failures without credentials or release authority."""

    def test_linux_archive_contains_one_exact_executable_with_fixed_headers(self):
        """Preserve exact executable bytes and set only the independent binary name, mode and normalized metadata."""
        with tempfile.TemporaryDirectory() as temporary:
            directory, item, _ = create(Path(temporary))
            key = item.selection["artifact_id"]
            with final.prepare_final_payloads({key: directory}, expected([item])) as assembly:
                path = assembly.subject_path(key + ".tar.gz")
                raw = path.read_bytes()
                self.assertEqual(raw[:3], b"\x1f\x8b\x08")
                self.assertEqual(raw[3], 0)
                self.assertEqual(raw[4:8], b"\x00" * 4)
                with tarfile.open(path, "r:gz") as archive:
                    member, = archive.getmembers()
                    self.assertEqual((member.name, member.mode, member.uid, member.gid, member.mtime), ("app", 0o755, 0, 0, 0))
                    self.assertEqual((member.uname, member.gname, member.type), ("", "", tarfile.REGTYPE))
                    self.assertEqual(archive.extractfile(member).read(), (directory / (key + ".bin")).read_bytes())
                self.assertEqual(path.stat().st_mode & 0o777, 0o400)
                self.assertEqual(assembly._root.stat().st_mode & 0o777, 0o700)

    def test_crate_is_retained_byte_for_byte_on_all_native_targets_without_extraction(self):
        """Keep source packages distinct from executables and do not apply Apple executable semantics to libraries."""
        for target in RUNNERS:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                directory, item, _ = create(Path(temporary), profile="library", target=target)
                key = item.selection["artifact_id"]
                with mock.patch("tarfile.open", side_effect=AssertionError("crate extraction attempted")):
                    with final.prepare_final_payloads({key: directory}, expected([item])) as assembly:
                        self.assertEqual(assembly.subject_path(key + ".crate").read_bytes(), (directory / (key + ".crate")).read_bytes())

    def test_arm_service_uses_target_machine_header_and_declared_binary(self):
        """Package a service on the declared ARM target without relying on the assembler's host architecture."""
        with tempfile.TemporaryDirectory() as temporary:
            directory, item, _ = create(Path(temporary), profile="service", target="aarch64-unknown-linux-gnu")
            key = item.selection["artifact_id"]
            with final.prepare_final_payloads({key: directory}, expected([item])) as assembly:
                with tarfile.open(assembly.subject_path(key + ".tar.gz"), "r:gz") as archive:
                    self.assertEqual(archive.extractfile("app").read(), elf(183))

    def test_wrong_machine_or_script_payload_is_rejected_without_execution(self):
        """Reject script substitution and ELF32/wrong machine headers even after recomputing unsigned metadata."""
        for payload in (b"#!/bin/sh\ntouch executed\n", elf(183), elf()[0:4] + b"\x01" + elf()[5:]):
            with self.subTest(payload=payload[:8]), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                directory, item, envelope = create(root)
                key = item.selection["artifact_id"]
                (directory / (key + ".bin")).write_bytes(payload)
                inventory = json.loads((directory / "inventory.json").read_bytes())
                inventory["files"][0] = _file_record(directory / (key + ".bin"), "artifact")
                (directory / "inventory.json").write_bytes(encoded(inventory))
                envelope["build_inventory"] = _metadata_identity(directory)
                (directory / HANDOFF_NAME).write_bytes(encoded(envelope))
                with self.assertRaises(Failure), mock.patch("subprocess.Popen", side_effect=AssertionError("untrusted execution")):
                    with final.prepare_final_payloads({key: directory}, expected([item])):
                        self.fail("invalid executable accepted")
                self.assertFalse((root / "executed").exists())

    def test_complete_set_rejects_missing_extra_and_duplicate_selections(self):
        """Refuse partial fulfillment or duplicated expectations before creating a final workspace."""
        with tempfile.TemporaryDirectory() as temporary:
            directory, item, _ = create(Path(temporary))
            key = item.selection["artifact_id"]
            for offered, plan in (({}, expected([item])), ({key: directory, "extra": directory}, expected([item])),
                                  ({key: directory}, expected([item, item]))):
                with self.subTest(offered=list(offered)), self.assertRaises(Failure):
                    with final.prepare_final_payloads(offered, plan):
                        self.fail("partial set accepted")

    def test_apple_executable_blocks_the_entire_set_before_any_files_are_read(self):
        """Reject mixed Linux/unsigned Apple sets before packaging a successful subset or reading hostile paths."""
        with tempfile.TemporaryDirectory() as temporary:
            directory, linux, _ = create(Path(temporary))
            apple = copy.deepcopy(linux.selection)
            apple.update(target="aarch64-apple-darwin", targets=["aarch64-apple-darwin"], runner="macos-15", artifact_id="app--aarch64-apple-darwin--minimal")
            item = replace(linux, selection=apple)
            with mock.patch("tempfile.TemporaryDirectory", side_effect=AssertionError("partial staging attempted")), self.assertRaises(Failure):
                with final.prepare_final_payloads({linux.selection["artifact_id"]: directory, apple["artifact_id"]: Path("/unread-hostile-path")}, expected([linux, item])):
                    self.fail("unsigned Apple accepted")

    def test_run_source_and_input_changes_never_fall_back_to_unsigned_claims(self):
        """Reject provider-independent run/config/source substitutions rather than learning expectations from envelopes."""
        mutations = [lambda p: p.inputs["source"].update(commit="f" * 40), lambda p: p.inputs["run"].update(attempt=3),
                     lambda p: p.inputs.update(config_sha256="f" * 64), lambda p: p.inputs["run"].update(id=True),
                     lambda p: p.build_workflow.update(commit="f" * 40)]
        for mutate in mutations:
            with tempfile.TemporaryDirectory() as temporary:
                directory, item, _ = create(Path(temporary))
                plan = expected([item])
                mutate(plan)
                with self.assertRaises(Failure):
                    with final.prepare_final_payloads({item.selection["artifact_id"]: directory}, plan):
                        self.fail("substituted expectation accepted")

    def test_symlink_extra_and_partial_handoffs_fail_as_complete_sets(self):
        """Reject hostile leaf types and directory entries without writing a published candidate."""
        for mutation in ("symlink", "extra", "missing"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                directory, item, _ = create(Path(temporary))
                key = item.selection["artifact_id"]
                path = directory / (key + ".bin")
                if mutation == "symlink":
                    original = directory.parent / "payload"
                    path.rename(original)
                    path.symlink_to(original)
                elif mutation == "extra":
                    (directory / "unexpected").write_bytes(b"extra")
                else:
                    path.unlink()
                with self.assertRaises(Failure):
                    with final.prepare_final_payloads({key: directory}, expected([item])):
                        self.fail("hostile handoff accepted")

    def test_workflow_family_and_package_run_match_before_staging(self):
        """Reject mixed workflow pins or an independent package workflow differing from the declared run before reads."""
        with tempfile.TemporaryDirectory() as temporary:
            _, item, _ = create(Path(temporary))
            plan = expected([item])
            variants = [replace(plan, package_workflow={**plan.package_workflow, "commit": "f" * 40}),
                        replace(plan, package_workflow={**plan.package_workflow, "path": ".github/workflows/other.yml"}),
                        replace(plan, build_workflow={**plan.build_workflow, "commit": "f" * 40})]
            for offered in variants:
                with self.subTest(offered=offered), mock.patch("tempfile.TemporaryDirectory", side_effect=AssertionError("staging attempted")), self.assertRaises(Failure):
                    with final.prepare_final_payloads({item.selection["artifact_id"]: Path("/do-not-read")}, offered):
                        self.fail("incompatible consumer workflow family accepted")

    def test_copied_expectations_and_payloads_do_not_follow_later_source_mutation(self):
        """Keep private snapshots stable when original unsigned files or caller-owned expectation dictionaries change."""
        with tempfile.TemporaryDirectory() as temporary:
            directory, item, envelope = create(Path(temporary))
            key = item.selection["artifact_id"]
            plan = expected([item])
            with final.prepare_final_payloads({key: directory}, plan) as assembly:
                slots = assembly.attestation_slots()
                (directory / (key + ".bin")).write_bytes(b"replaced after snapshot")
                plan.inputs["source"]["commit"] = "f" * 40
                item.selection["binary"] = "attacker"
                self.assertEqual(assembly.attestation_slots(), slots)
                self.assertEqual(assembly.packaging(key)["input"], identity(elf()))

    def test_metadata_must_reference_actual_retained_report_bytes_and_measured_chain(self):
        """Reject missing report bytes, invented output identities, cross-run transforms and failed package assertions."""
        mutations = [lambda r: r["steps"][1].update(output=identity(b"other final bytes")),
                     lambda r: r["steps"][0]["run"].update(attempt=99), lambda r: r["steps"][1].update(outcome="failed"),
                     lambda r: r["steps"][0].update(platform_evidence=[identity(b"missing report")]),
                     lambda r: r.update(apple_assertions={"team_id": "fake"}), lambda r: r["selection"].update(package_version="9.9.9"),
                     lambda r: r["steps"][1].update(started_at=float(r["steps"][1]["started_at"])),
                     lambda r: r["inputs"]["run"].update(attempt=float(r["inputs"]["run"]["attempt"]))]
        for mutate in mutations:
            with tempfile.TemporaryDirectory() as temporary:
                directory, item, envelope = create(Path(temporary))
                key = item.selection["artifact_id"]
                plan = expected([item])
                with final.prepare_final_payloads({key: directory}, plan) as assembly:
                    record, diagnostic = evidence(plan, item, assembly, envelope)
                    mutate(record)
                    with self.assertRaises(Failure):
                        assembly.add_evidence(key, encoded(record), diagnostic)
                    self.assertFalse((assembly._root / (key + ".build.json")).exists())

    def test_fixed_bundle_slots_reject_wrong_subject_predicate_digest_and_extra_subjects(self):
        """Reject substitution across targets/subjects and forged bundle relations before inventory freezing."""
        with tempfile.TemporaryDirectory() as temporary:
            directory, item, _ = create(Path(temporary))
            key = item.selection["artifact_id"]
            with final.prepare_final_payloads({key: directory}, expected([item])) as assembly:
                slot = next(s for s in assembly.attestation_slots() if s["predicate"] == final.PROVENANCE)
                mutations = [{"subject": [{"name": "other.bin", "digest": {"sha256": slot["bytes"]["sha256"]}}]},
                             {"subject": [{"name": slot["subject"], "digest": {"sha256": "f" * 64}}]},
                             {"subject": [{"name": slot["subject"], "digest": {"sha256": slot["bytes"]["sha256"]}}] * 2},
                             {"predicateType": final.SBOM}]
                for changes in mutations:
                    with self.subTest(changes=changes), self.assertRaises(Failure):
                        assembly.add_bundle(slot["bundle"], bundle(slot, **changes))

    def test_sbom_predicate_requires_exact_published_document(self):
        """Reject an internally valid SBOM predicate that differs from the retained target/feature document."""
        with tempfile.TemporaryDirectory() as temporary:
            directory, item, _ = create(Path(temporary))
            key = item.selection["artifact_id"]
            with final.prepare_final_payloads({key: directory}, expected([item])) as assembly:
                slot = next(s for s in assembly.attestation_slots() if s["predicate"] == final.SBOM)
                bom = json.loads(assembly.subject_path(slot["predicate_asset"]).read_bytes())
                for field, value in (("serialNumber", "urn:uuid:ffffffff-ffff-4fff-8fff-ffffffffffff"), ("version", True)):
                    changed = copy.deepcopy(bom)
                    changed[field] = value
                    with self.assertRaises(Failure):
                        assembly.add_bundle(slot["bundle"], bundle(slot, changed))

    def test_complete_layout_has_no_inventory_authentication_hash_cycle(self):
        """Finish exact relationships with detached inventory authentication while keeping every authority flag false."""
        with tempfile.TemporaryDirectory() as temporary:
            directory, item, envelope = create(Path(temporary))
            key = item.selection["artifact_id"]
            plan = expected([item])
            with final.prepare_final_payloads({key: directory}, plan) as assembly:
                record, diagnostic = evidence(plan, item, assembly, envelope)
                assembly.add_evidence(key, encoded(record), diagnostic)
                attach_all(assembly)
                slot = assembly.freeze_inventory()
                inventory = json.loads(assembly.subject_path(final.INVENTORY).read_bytes())
                names = {asset["name"] for asset in inventory["assets"]}
                self.assertEqual(len(names), 13)
                self.assertNotIn(final.INVENTORY, names)
                self.assertNotIn(final.INVENTORY_BUNDLE, names)
                result = assembly.finish(bundle(slot))
                root = assembly.directory()
                self.assertEqual({p.name for p in root.iterdir()}, names | {final.INVENTORY, final.INVENTORY_BUNDLE})
                for asset in inventory["assets"]:
                    self.assertEqual(asset["bytes"], identity((root / asset["name"]).read_bytes()))
                    self.assertTrue(set(asset["subjects"]) <= names)
                    if asset["predicate_asset"]:
                        self.assertIn(asset["predicate_asset"], names)
                self.assertEqual(result["state"], "layout-complete-unverified")
                self.assertFalse(result["cryptographic_release_authenticated"])
                self.assertFalse(result["signing_authorized"])
                self.assertFalse(result["publication_authorized"])
                from jsonschema import Draft202012Validator
                schemas = Path(__file__).parent / 'fixtures/final-payload-v1'
                Draft202012Validator(json.loads((schemas / 'release-inventory-v1.json').read_bytes())).validate(inventory)
                Draft202012Validator(json.loads((schemas / 'artifact-evidence-v1.json').read_bytes())).validate(record)
            self.assertFalse(root.exists())

    def test_inventory_freeze_requires_every_selection_and_bundle(self):
        """Do not admit an artifact-only or partly attested subset as a complete inventory."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory, item, envelope = create(root)
            other, library, _ = create(root, profile="library", deliverable="library")
            key, other_key = item.selection["artifact_id"], library.selection["artifact_id"]
            plan = expected([item, library])
            with final.prepare_final_payloads({key: directory, other_key: other}, plan) as assembly:
                record, diagnostic = evidence(plan, item, assembly, envelope)
                assembly.add_evidence(key, encoded(record), diagnostic)
                attach_all(assembly)
                with self.assertRaises(Failure):
                    assembly.freeze_inventory()
                with self.assertRaises(Failure):
                    assembly.directory()

    def test_mutation_and_extra_files_fail_before_finalization(self):
        """Reject a replaced private payload or extra file instead of refreshing hashes from offered bytes."""
        for mutation in ("bytes", "extra", "symlink"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                directory, item, _ = create(Path(temporary))
                key = item.selection["artifact_id"]
                with final.prepare_final_payloads({key: directory}, expected([item])) as assembly:
                    path = assembly.subject_path(key + ".tar.gz")
                    if mutation == "bytes":
                        path.chmod(0o600)
                        path.write_bytes(b"replaced")
                    elif mutation == "extra":
                        (path.parent / "extra").write_bytes(b"unexpected")
                    else:
                        path.unlink()
                        path.symlink_to(directory / (key + ".bin"))
                    with self.assertRaises(Failure):
                        assembly.attestation_slots()

    def test_no_bundle_or_evidence_replacement_after_inventory_freeze(self):
        """Freeze identity once; conflicting retries cannot append, replace or rehash an existing candidate."""
        with tempfile.TemporaryDirectory() as temporary:
            directory, item, envelope = create(Path(temporary))
            key = item.selection["artifact_id"]
            plan = expected([item])
            with final.prepare_final_payloads({key: directory}, plan) as assembly:
                record, diagnostic = evidence(plan, item, assembly, envelope)
                assembly.add_evidence(key, encoded(record), diagnostic)
                attach_all(assembly)
                slot = assembly.freeze_inventory()
                for attempt in (lambda: assembly.add_evidence(key, encoded(record), diagnostic),
                                lambda: assembly.add_bundle(key + ".tar.gz.provenance.sigstore.json", b"replacement"),
                                assembly.freeze_inventory):
                    with self.assertRaises(Failure):
                        attempt()
                assembly.finish(bundle(slot))
                with self.assertRaises(Failure):
                    assembly.finish(bundle(slot))

    def test_staging_and_metadata_budgets_reject_the_whole_set(self):
        """Bound initial snapshots and later metadata/bundle growth rather than accepting a memory/disk subset."""
        with tempfile.TemporaryDirectory() as temporary:
            directory, item, envelope = create(Path(temporary))
            key = item.selection["artifact_id"]
            plan = expected([item])
            with mock.patch.object(final, "MAX_TOTAL", 256), self.assertRaises(Failure):
                with final.prepare_final_payloads({key: directory}, plan):
                    self.fail("oversized stage accepted")
            with final.prepare_final_payloads({key: directory}, plan) as assembly:
                record, diagnostic = evidence(plan, item, assembly, envelope)
                current = assembly._reserved + sum(v["size"] for v in assembly._files.values())
                with mock.patch.object(final, "MAX_TOTAL", current), self.assertRaises(Failure):
                    assembly.add_evidence(key, encoded(record), diagnostic)

    def test_duplicate_json_invalid_base64_and_missing_signature_material_fail(self):
        """Reject ambiguous bundle bytes and unsupported envelope shapes without attempting credentialed operations."""
        with tempfile.TemporaryDirectory() as temporary:
            directory, item, _ = create(Path(temporary))
            key = item.selection["artifact_id"]
            with final.prepare_final_payloads({key: directory}, expected([item])) as assembly:
                slot = assembly.attestation_slots()[0]
                raw = bundle(slot)
                duplicate = raw.replace(b'"mediaType": ', b'"mediaType":"duplicate","mediaType": ', 1)
                values = [duplicate]
                for mutate in (lambda b: b["dsseEnvelope"].update(payload="%%%"), lambda b: b.update(verificationMaterial={}),
                               lambda b: b["dsseEnvelope"].update(signatures=[]), lambda b: b.update(mediaType="unknown")):
                    data = json.loads(raw)
                    mutate(data)
                    values.append(encoded(data))
                for offered in values:
                    with self.assertRaises((Failure, BuildError)):
                        assembly.add_bundle(slot["bundle"], offered)


if __name__ == "__main__":
    unittest.main()
