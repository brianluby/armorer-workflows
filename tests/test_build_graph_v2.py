"""Successor graph tests with independently fixed context; no authenticity claim."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from armorer_runtime.build import BuildError, _file_record, verify_inventory, verify_inventory_v2
from armorer_runtime.graph import validate_graph_v2, version
from test_build import case

CONTEXT = {"source": {"repository": "fixture/graph", "commit": "a" * 40}, "runtime_commit": "b" * 40,
           "run_id": "17", "run_attempt": "2"}
INPUTS = {"armorer.toml": "1" * 64, "armorer.lock": "2" * 64, "Cargo.lock": "3" * 64}
FIXTURES = Path(__file__).parent / "fixtures/cargo-graph-v2"


def expectation(name):
    """Fix profile/features/target and actual library target independently of producer records."""
    if name == "zero-library":
        return case(profile="library", binary=None), "custom_library"
    if name == "optional":
        return case(feature_set="optional", features=["extra"], artifact_id="app--x86_64-unknown-linux-gnu--optional"), "app"
    return case(), "app"


def fixture(name):
    """Read synthetic writer outputs without learning any consumer expectation from them."""
    return json.loads((FIXTURES / (name + ".graph.json")).read_bytes()), (FIXTURES / (name + ".cdx.json")).read_bytes()


def check(record, bom, name="optional"):
    """Check synthetic bytes against the separately fixed expected source/root/version context."""
    selected, root_name = expectation(name)
    validate_graph_v2(record, bom, selected, CONTEXT, INPUTS, root_name, "0.1.0")


class SelectedGraphV2Tests(unittest.TestCase):
    def test_shared_writer_fixtures_match_independent_context(self):
        """Accept minimal/optional/zero-library graphs, including host and prerelease dependencies."""
        for name in ("minimal", "optional", "zero-library"):
            record, bom = fixture(name)
            check(record, bom, name)

    def test_source_run_input_and_selection_substitution_rejected(self):
        """Reject internally consistent producer context that disagrees with separate expectations."""
        original, bom = fixture("optional")
        mutations = [
            lambda r: r.update(schema_version=1), lambda r: r.update(schema_version=True),
            lambda r: r["source"].update(repository="attacker/graph"), lambda r: r["source"].update(commit="c" * 40),
            lambda r: r.update(runtime_commit="c" * 40), lambda r: r.update(run_id=18), lambda r: r.update(run_attempt=3),
            lambda r: r.update(run_id=True), lambda r: r.update(run_id=None),
            lambda r: r["input_sha256"].update({"Cargo.lock": "5" * 64}), lambda r: r["input_sha256"].update({"armorer.toml": "5" * 64}),
            lambda r: r["selection"].update(default_features=True), lambda r: r["selection"].update(features=[]),
            lambda r: r["selection"].update(default_features=0),
            lambda r: r["selection"].update(profile="service"), lambda r: r["selection"].update(target="aarch64-unknown-linux-gnu"),
            lambda r: r["selection"].update(package_version="0.2.0"), lambda r: r.update(root_component_name="other"),
            lambda r: r.update(coverage_gaps=[]), lambda r: r.update(caller_command="build"),
        ]
        for mutate in mutations:
            record = copy.deepcopy(original); mutate(record)
            with self.assertRaises(BuildError):
                check(record, bom)

    def test_missing_duplicate_dangling_unreachable_or_dev_graph_rejected(self):
        """Reject partial graph inventories and contexts the pinned Cargo adapter does not emit."""
        original, bom = fixture("optional")
        for mutate in [
            lambda r: r.update(packages=[]), lambda r: r.update(nodes=[]), lambda r: r.update(root="missing"),
            lambda r: r["packages"][1].update(id="app"), lambda r: r["nodes"][1].update(id="app"),
            lambda r: r["nodes"][0].update(dependencies=[]), lambda r: r["nodes"][0].update(features=[]),
            lambda r: r["nodes"][0].update(features=["extra", "extra"]),
            lambda r: r["nodes"][0]["dependencies"][0].update(package="missing"),
            lambda r: r["nodes"][0]["dependencies"][0].update(contexts=[]),
            lambda r: r["nodes"][0]["dependencies"][0]["contexts"][0].update(kind="dev"),
            lambda r: r["packages"][1].update(version="0.2.0-01"),
        ]:
            record = copy.deepcopy(original); mutate(record)
            with self.assertRaises(BuildError):
                check(record, bom)

    def test_sbom_valid_reference_rerouting_and_identity_tamper_rejected(self):
        """Reject altered SBOM root/package identities, graph edges and nested or excluded nodes."""
        record, raw = fixture("optional"); original = json.loads(raw)
        for mutate in [
            lambda b: b["metadata"]["component"].update({"bom-ref": "dep"}),
            lambda b: b["metadata"]["component"].update(version="0.2.0"),
            lambda b: b["metadata"]["component"].update(type="library"),
            lambda b: b["components"][0].update(name="other"), lambda b: b["components"][0].update(version="0.2.0"),
            lambda b: b["components"][0].update({"bom-ref": "app"}), lambda b: b.update(components=[]),
            lambda b: b["dependencies"][0].update(dependsOn=["app", "dep"]),
            lambda b: b["dependencies"][0].update(dependsOn=["dep", "dep"]), lambda b: b.update(dependencies=[]),
            lambda b: b["dependencies"][0].update(provides=["hidden"]), lambda b: b.update(version=True),
            lambda b: b["components"][0].update(components=[{"bom-ref": "hidden"}]),
            lambda b: next(c for c in b["components"] if c["bom-ref"] == "dep").update(scope="excluded"),
            lambda b: b["components"][0].update(type="file"),
        ]:
            bom = copy.deepcopy(original); mutate(bom)
            with self.assertRaises(BuildError):
                check(record, json.dumps(bom).encode())

    def test_canonical_dependency_versions_and_stable_roots(self):
        """Preserve real prerelease/build metadata dependencies and reject invalid root versions."""
        for value in ("0.1.0", "0.2.0-alpha.1", "1.2.3+00.build"):
            self.assertTrue(version(value))
        for value in ("01.2.3", "0.2.0-01", "0.2.0-", "0.2.0+", "1.2.3 ", "18446744073709551616.0.0"):
            self.assertFalse(version(value))
        self.assertFalse(version("0.2.0-alpha.1", stable=True))

    def test_build_only_scope_and_mixed_paths_are_derived_from_graph(self):
        """Retain host descendants as excluded, with normal paths taking precedence when shared."""
        graph, raw = fixture("optional")
        bom = json.loads(raw)
        host_component = next(c for c in bom["components"] if c["bom-ref"] == "host")
        self.assertEqual(host_component["scope"], "excluded")
        for scope in ("required", "optional", None):
            changed = copy.deepcopy(bom)
            component = next(c for c in changed["components"] if c["bom-ref"] == "host")
            if scope is None:
                del component["scope"]
            else:
                component["scope"] = scope
            with self.assertRaises(BuildError):
                check(graph, json.dumps(changed).encode())
        root_node = next(n for n in graph["nodes"] if n["id"] == "app")
        normal_edge = root_node["dependencies"].pop(0)
        next(n for n in graph["nodes"] if n["id"] == "host")["dependencies"] = [normal_edge]
        next(n for n in bom["dependencies"] if n["ref"] == "app")["dependsOn"] = ["host"]
        next(n for n in bom["dependencies"] if n["ref"] == "host")["dependsOn"] = ["dep"]
        dependency = next(c for c in bom["components"] if c["bom-ref"] == "dep")
        dependency["scope"] = "excluded"
        check(graph, json.dumps(bom).encode())
        dependency["scope"] = "required"
        with self.assertRaises(BuildError):
            check(graph, json.dumps(bom).encode())
        root_node["dependencies"].append(normal_edge)
        next(n for n in bom["dependencies"] if n["ref"] == "app")["dependsOn"].append("dep")
        check(graph, json.dumps(bom).encode())

    def test_explicit_inventory_version_never_falls_back_to_legacy(self):
        """Exercise exact bytes and graph/SBOM pairing through both fixed public readers."""
        selected, root_name = expectation("optional"); graph, sbom = fixture("optional")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary); key = selected["artifact_id"]
            paths = [(output / (key + ".bin"), "artifact", b"inert fixture bytes"),
                     (output / (key + ".cdx.json"), "sbom", sbom),
                     (output / (key + ".cargo-graph.json"), "cargo-graph", json.dumps(graph).encode())]
            for path, _, data in paths:
                path.write_bytes(data)
            inventory = {"schema_version": 2, "cargo_graph_version": 2, "state": "build-produced", "signing_status": "unsigned", "provenance_status": "not-attested",
                         **CONTEXT, "selection": selected, "input_sha256": INPUTS, "source_input_sha256": {"Cargo.toml": "6" * 64},
                         "tool_sha256": {"cargo-cyclonedx": "7" * 64}, "tool_pin_authority": "immutable-trusted-workflow-catalog",
                         "graph_scope": "compiled-cargo-target-and-host-build-dependencies", "coverage_gaps": ["native scope incomplete", "host/target units aggregated"],
                         "artifact_kind": "executable", "files": [_file_record(path, role) for path, role, _ in paths]}
            (output / "inventory.json").write_text(json.dumps(inventory))
            verify_inventory_v2(output, inventory, selected, CONTEXT, INPUTS, root_name, "0.1.0")
            with self.assertRaises(BuildError):
                verify_inventory(output, inventory, selected, CONTEXT)
            # Change the graph and update its inventory digest: the semantic gate must still fail.
            graph["schema_version"] = 1; paths[2][0].write_text(json.dumps(graph)); inventory["files"][2] = _file_record(paths[2][0], "cargo-graph")
            (output / "inventory.json").write_text(json.dumps(inventory))
            with self.assertRaises(BuildError):
                verify_inventory_v2(output, inventory, selected, CONTEXT, INPUTS, root_name, "0.1.0")
            legacy = copy.deepcopy(inventory); legacy["schema_version"] = 1; del legacy["cargo_graph_version"]
            paths[2][0].write_text(json.dumps({"compiled_packages": {"app": []}, "native_linkage": [], "graph_scope": "compiled-cargo-target-and-host-build-dependencies"}))
            legacy["files"][2] = _file_record(paths[2][0], "cargo-graph"); (output / "inventory.json").write_text(json.dumps(legacy))
            verify_inventory(output, legacy, selected, CONTEXT)
            with self.assertRaises(BuildError):
                verify_inventory_v2(output, legacy, selected, CONTEXT, INPUTS, root_name, "0.1.0")
