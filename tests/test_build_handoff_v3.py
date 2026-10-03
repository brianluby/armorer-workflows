"""Explicit v3 handoff tests establish consistency only, never authenticity or hosted execution."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from armorer_runtime import build_v3 as handoff
from armorer_runtime.build import BuildError, _file_record, verify_inventory_v2
from test_build_graph_v2 import CONTEXT, INPUTS, expectation, fixture
from jsonschema import Draft202012Validator

TOOLS = {"cargo-cyclonedx": "7" * 64, "cyclonedx": "8" * 64}


def create(directory):
    """Create inert synthetic graph/inventory bytes and separately fixed consumer expectations."""
    selected, root = expectation("optional")
    graph, bom = fixture("optional")
    key = selected["artifact_id"]
    paths = [(directory / (key + ".bin"), "artifact", b"#!/bin/sh\ntouch executed\n"),
             (directory / (key + ".cdx.json"), "sbom", bom),
             (directory / (key + ".cargo-graph.json"), "cargo-graph", json.dumps(graph).encode())]
    for path, _, data in paths:
        path.write_bytes(data)
    inventory = {"schema_version": 2, "cargo_graph_version": 2, "state": "build-produced",
                 "signing_status": "unsigned", "provenance_status": "not-attested", **CONTEXT,
                 "selection": selected, "input_sha256": INPUTS, "source_input_sha256": {"Cargo.toml": "6" * 64},
                 "tool_sha256": TOOLS, "tool_pin_authority": "immutable-trusted-workflow-catalog",
                 "graph_scope": "compiled-cargo-target-and-host-build-dependencies",
                 "coverage_gaps": ["native scope incomplete", "host/target units aggregated"],
                 "artifact_kind": "executable", "files": [_file_record(path, role) for path, role, _ in paths]}
    (directory / "inventory.json").write_text(json.dumps(inventory))
    envelope = {"schema_version": 3, "state": "unsigned-handoff", "signing_status": "unsigned",
                "provenance_status": "not-attested", **CONTEXT, "selection": selected,
                "input_sha256": INPUTS, "build_inventory": handoff._metadata_identity(directory),
                "root_component_name": root, "package_version": "0.1.0", "tool_sha256": TOOLS,
                "observed_build": {"started_at": 100, "finished_at": 110}}
    write(directory, envelope)
    return selected, envelope, inventory


def write(directory, envelope):
    """Write only test-owned unsigned metadata; this function creates no authentication proof."""
    (directory / handoff.HANDOFF_NAME).write_text(json.dumps(envelope))


def check(directory, selection, **kwargs):
    """Require independently fixed source/inputs/root/version/tools with a synthetic consistency-test clock."""
    return handoff.verify_handoff_v3(directory, selection, CONTEXT, INPUTS, "app", "0.1.0", TOOLS,
                                     now=kwargs.pop("now", 120), **kwargs)


class UnsignedHandoffV3Tests(unittest.TestCase):
    """Reject substituted unsigned handoffs and preserve their declared run and asset identities."""
    def test_complete_unsigned_fixture_is_inert_read_only_and_structurally_valid(self):
        """Accept the exact unsigned five-leaf fixture without extraction, execution or source changes."""
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            selected, envelope, _ = create(directory)
            before = {path.name: path.read_bytes() for path in directory.iterdir()}
            self.assertEqual(check(directory, selected), envelope)
            schema = json.loads((Path(handoff.__file__).resolve().parent.parent / "schemas/unsigned-handoff-v3.json").read_bytes())
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(envelope)
            self.assertEqual({path.name: path.read_bytes() for path in directory.iterdir()}, before)
            self.assertFalse((directory / "executed").exists())

    def test_exact_mode_and_source_run_root_selection_tool_bindings(self):
        """Reject producer substitutions even when each changed envelope is structurally well formed."""
        mutations = [
            lambda value: value.update(schema_version=2), lambda value: value.update(schema_version=True),
            lambda value: value.update(state="signed"), lambda value: value.update(provenance_status="verified"),
            lambda value: value["source"].update(repository="attacker/graph"),
            lambda value: value["source"].update(commit="c"*40), lambda value: value.update(runtime_commit="c"*40),
            lambda value: value.update(run_id="18"), lambda value: value.update(run_attempt="3"),
            lambda value: value.update(run_id=None), lambda value: value.update(run_attempt=True),
            lambda value: value.update(run_id="1"*21), lambda value: value.update(root_component_name="other"),
            lambda value: value.update(package_version="0.2.0"),
            lambda value: value["selection"].update(default_features=True),
            lambda value: value["input_sha256"].update({"Cargo.lock":"5"*64}),
            lambda value: value["tool_sha256"].update(cyclonedx="5"*64),
            lambda value: value.update(custom_predicate={}),
        ]
        for mutate in mutations:
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary); selected, envelope, _ = create(directory)
                changed = copy.deepcopy(envelope); mutate(changed); write(directory, changed)
                with self.assertRaises(BuildError):
                    check(directory, selected)

    def test_observation_age_future_order_types_and_exact_fields(self):
        """Reject stale, future, reversed, boolean and caller-expanded build observations."""
        observations = [{"started_at":100,"finished_at":121}, {"started_at":110,"finished_at":100},
                        {"started_at":True,"finished_at":110}, {"started_at":0,"finished_at":110},
                        {"started_at":100,"finished_at":"110"}, {"started_at":100,"finished_at":110,"caller":True}]
        for observation in observations:
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary); selected, envelope, _ = create(directory)
                envelope["observed_build"] = observation;write(directory,envelope)
                with self.assertRaises(BuildError):
                    check(directory,selected)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); selected, _, _ = create(directory)
            for args in ({"max_age_seconds":19}, {"max_age_seconds":True}, {"max_age_seconds":86401}, {"now":False}):
                with self.assertRaises(BuildError):
                    check(directory,selected,**args)

    def test_inventory_serialization_bytes_are_bound_before_v2_semantics(self):
        """A whitespace-only inventory byte change fails the exact handoff manifest identity."""
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); selected, _, _ = create(directory)
            path = directory / "inventory.json";path.write_bytes(path.read_bytes()+b"\n")
            with self.assertRaises(BuildError):
                check(directory, selected)

    def test_graph_rewrite_with_updated_unsigned_digests_still_fails_independent_graph(self):
        """Rewritten untrusted metadata cannot conceal a retained graph edge substitution."""
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); selected, envelope, inventory = create(directory)
            path = directory / (selected["artifact_id"]+".cargo-graph.json")
            graph = json.loads(path.read_bytes());graph["nodes"][0]["dependencies"] = []
            path.write_text(json.dumps(graph))
            inventory["files"][2] = _file_record(path,"cargo-graph")
            (directory/"inventory.json").write_text(json.dumps(inventory))
            envelope["build_inventory"] = handoff._metadata_identity(directory);write(directory,envelope)
            with self.assertRaises(BuildError):
                check(directory,selected)

    def test_missing_extra_symlink_special_and_nested_leaves_fail_before_open(self):
        """Reject malformed transport sets without following links, opening FIFOs or executing payloads."""
        for case in range(6):
            with tempfile.TemporaryDirectory() as temporary:
                parent = Path(temporary);directory = parent/"download";directory.mkdir()
                selected, _, _ = create(directory)
                if case == 0:
                    (directory/handoff.HANDOFF_NAME).unlink()
                elif case == 1:
                    (directory/"extra.bin").write_bytes(b"extra")
                elif case == 2:
                    path = directory/(selected["artifact_id"]+".bin");path.rename(parent/"outside")
                    path.symlink_to(parent/"outside")
                elif case == 3:
                    (directory/"nested").mkdir()
                elif case == 4:
                    os.mkfifo(directory/"fifo")
                else:
                    (parent/"linked").symlink_to(directory,target_is_directory=True);directory = parent/"linked"
                with self.assertRaises(BuildError):
                    check(directory,selected)

    def test_sparse_oversized_subject_and_metadata_fail_without_large_allocation(self):
        """Bound regular files before copying so claimed sizes cannot trigger unbounded reads."""
        for name in ["artifact","handoff"]:
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary); selected, _, _ = create(directory)
                path = directory/(selected["artifact_id"]+".bin") if name=="artifact" else directory/handoff.HANDOFF_NAME
                with path.open("wb") as stream:
                    stream.truncate((handoff.MAX_ARTIFACT if name=="artifact" else handoff.MAX_HANDOFF)+1)
                with self.assertRaises(BuildError):
                    check(directory,selected)

    def test_ambiguous_json_and_v2_handoff_version_mix_never_fall_back(self):
        """Reject duplicate/trailing metadata and never infer a successor through a v2 reader."""
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary);selected,envelope,inventory = create(directory)
            with self.assertRaises(BuildError):
                verify_inventory_v2(directory,inventory,selected,CONTEXT,INPUTS,"app","0.1.0")
            for data in [b'{"schema_version":3,"schema_version":3}', b'{} {}']:
                (directory/handoff.HANDOFF_NAME).write_bytes(data)
                with self.assertRaises(BuildError):
                    check(directory,selected)
            write(directory,envelope)
            self.assertEqual(check(directory,selected),envelope)

    def test_actual_clock_expiry_is_rechecked_after_complete_file_validation(self):
        """A handoff that ages out during copying/validation cannot reach the finalizer as current."""
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); selected, _, _ = create(directory)
            with mock.patch.object(handoff.time, "time", side_effect=[120, 4000]):
                with self.assertRaises(BuildError):
                    handoff.verify_handoff_v3(directory, selected, CONTEXT, INPUTS, "app", "0.1.0", TOOLS)
