"""Failure-oriented builder graph and exact inventory verification tests."""

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from armorer_runtime.build import (
    BuildError, _file_record, _run, build_arguments, compiler_evidence,
    metadata_adapter, parse_json, reconcile_metadata, validate_sbom,
    verify_inventory, require_clean_source,
)


def case(**updates):
    result = {"id": "app", "profile": "cli", "package": "app", "binary": "app",
              "targets": ["x86_64-unknown-linux-gnu"],
              "target": "x86_64-unknown-linux-gnu", "feature_set": "minimal",
              "default_features": False, "features": [], "runner": "ubuntu-24.04",
              "artifact_id": "app--x86_64-unknown-linux-gnu--minimal", "toolchain": "1.95.0"}
    return {**result, **updates}


def dependency(name, package, *, optional=False, kind=None, target=None):
    return ({"name": name, "rename": None, "kind": kind, "target": target, "optional": optional},
            {"name": name.replace("-", "_"), "pkg": package, "dep_kinds": [{"kind": kind, "target": target}]})


def graph():
    declaration, edge = dependency("optional-dep", "dep", optional=True)
    # Raw cargo metadata unifies a feature enabled by an unrelated workspace
    # member; actual build evidence has only the selected root's minimal graph.
    return {"packages": [
        {"id": "app", "name": "app", "version": "0.1.0", "features": {"extra": ["dep:optional-dep"]},
         "dependencies": [declaration], "targets": [{"name": "app", "kind": ["bin"]}]},
        {"id": "dep", "name": "optional-dep", "version": "0.1.0", "features": {}, "dependencies": []},
        {"id": "other", "name": "other", "version": "0.1.0", "features": {}, "dependencies": []}],
        "workspace_members": ["app", "dep", "other"], "workspace_default_members": ["other"],
        "resolve": {"root": None, "nodes": [
            {"id": "app", "features": ["extra"], "dependencies": ["dep"], "deps": [edge]},
            {"id": "dep", "features": [], "dependencies": [], "deps": []},
            {"id": "other", "features": [], "dependencies": [], "deps": []}]}}


def evidence(features=None):
    return {"root": {"package_id": "app"}, "features": features or {"app": []}}


def sbom():
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "application", "name": "app", "version": "0.1.0", "bom-ref": "app"}},
            "components": [], "dependencies": [{"ref": "app", "dependsOn": []}]}


class GraphTests(unittest.TestCase):
    def test_preexisting_untracked_source_is_rejected_before_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = {"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
            _run(["/usr/bin/git", "init", "-q"], root, environment)
            _run(["/usr/bin/git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                  "-c", "commit.gpgsign=false", "commit", "--allow-empty", "-qm", "fixture"], root, environment)
            require_clean_source(root, environment)
            (root / "untracked.rs").write_text("fn untracked_source() {}\n")
            with self.assertRaises(BuildError):
                require_clean_source(root, environment)
            self.assertFalse((root / "output").exists())

    def test_timeout_kills_descendant_processes_before_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sentinel = root / "child-wrote"
            child = f"import time; from pathlib import Path; time.sleep(1.4); Path({str(sentinel)!r}).write_text('late')"
            parent = f"import subprocess,time,sys; subprocess.Popen([sys.executable,'-c',{child!r}]); time.sleep(10)"
            with self.assertRaises(BuildError):
                _run([sys.executable, "-c", parent], root, {"PATH": "/usr/bin:/bin"}, timeout=1)
            time.sleep(0.7)
            self.assertFalse(sentinel.exists())

    def test_build_arguments_are_fixed_and_separate(self):
        arguments = build_arguments(case(features=["extra"]), Path("Cargo.toml"), Path("target"))
        self.assertEqual(arguments[:4], ["cargo", "build", "--locked", "--release"])
        self.assertIn("--no-default-features", arguments)
        self.assertEqual(arguments[-2:], ["--features", "extra"])
        self.assertEqual(arguments[arguments.index("--bin") + 1], "app")
        self.assertNotIn("--workspace", arguments)

    def test_workspace_feature_union_is_removed_for_minimal_build(self):
        original = graph()
        result = reconcile_metadata(original, evidence(), case())
        self.assertEqual(result["workspace_members"], ["app"])
        self.assertEqual([p["id"] for p in result["packages"]], ["app"])
        self.assertEqual(result["resolve"]["nodes"][0]["features"], [])
        self.assertEqual(result["resolve"]["nodes"][0]["deps"], [])
        self.assertEqual(original["resolve"]["nodes"][0]["features"], ["extra"])

    def test_optional_feature_graph_is_retained_for_selected_build(self):
        result = reconcile_metadata(graph(), evidence({"app": ["extra"], "dep": []}), case(features=["extra"]))
        self.assertEqual([p["id"] for p in result["packages"]], ["app", "dep"])
        self.assertEqual(result["resolve"]["nodes"][0]["dependencies"], ["dep"])

    def test_custom_dependency_library_name_uses_package_and_declaration_key(self):
        for rename in (None, "renamed-dep"):
            for optional in (False, True):
                with self.subTest(rename=rename, optional=optional):
                    document = graph()
                    declaration = document["packages"][0]["dependencies"][0]
                    declaration.update(rename=rename, optional=optional)
                    key = rename or declaration["name"]
                    document["packages"][0]["features"] = {"extra": ["dep:" + key]}
                    document["packages"][1]["targets"] = [{"name": "custom_library", "kind": ["lib"]}]
                    edge = document["resolve"]["nodes"][0]["deps"][0]
                    edge["name"] = rename.replace("-", "_") if rename else "custom_library"
                    result = reconcile_metadata(document, evidence({"app": ["extra"], "dep": []}),
                                                case(features=["extra"]))
                    self.assertEqual(result["resolve"]["nodes"][0]["dependencies"], ["dep"])
                    self.assertEqual(result["resolve"]["nodes"][0]["deps"][0]["name"], edge["name"])
                    if optional:
                        minimal = reconcile_metadata(document, evidence(), case())
                        self.assertEqual(minimal["resolve"]["nodes"][0]["dependencies"], [])

    def test_same_named_explicit_feature_does_not_activate_optional_dependency(self):
        document = graph()
        document["packages"][0]["features"]["optional-dep"] = []
        result = reconcile_metadata(document, evidence({"app": ["optional-dep"]}), case(features=["optional-dep"]))
        self.assertEqual(result["resolve"]["nodes"][0]["dependencies"], [])

    def test_optional_same_package_compiled_elsewhere_does_not_keep_false_edge(self):
        document = graph()
        declared, edge = dependency("bridge", "bridge")
        document["packages"][0]["dependencies"].append(declared)
        document["resolve"]["nodes"][0]["deps"].append(edge)
        declared_dep, dep_edge = dependency("optional-dep", "dep")
        document["packages"].append({"id": "bridge", "name": "bridge", "dependencies": [declared_dep], "features": {}})
        document["resolve"]["nodes"].append({"id": "bridge", "features": [], "deps": [dep_edge]})
        result = reconcile_metadata(document, evidence({"app": [], "bridge": [], "dep": []}), case())
        root = next(n for n in result["resolve"]["nodes"] if n["id"] == "app")
        self.assertEqual(root["dependencies"], ["bridge"])

    def test_missing_active_dependency_fails_closed(self):
        with self.assertRaises(BuildError):
            reconcile_metadata(graph(), evidence({"app": ["extra"]}), case(features=["extra"]))

    def test_unaccounted_host_dependency_fails_closed(self):
        with self.assertRaises(BuildError):
            reconcile_metadata(graph(), evidence({"app": [], "host-only": []}), case())

    def test_wrong_root_and_unreachable_compiler_package_fail(self):
        with self.assertRaises(BuildError):
            reconcile_metadata(graph(), evidence(), case(package="other"))
        with self.assertRaises(BuildError):
            reconcile_metadata(graph(), evidence({"app": [], "other": []}), case())

    def test_duplicate_metadata_ids_fail(self):
        document = graph()
        document["packages"].append(copy.deepcopy(document["packages"][0]))
        with self.assertRaises(BuildError):
            reconcile_metadata(document, evidence(), case())

    def test_zero_dependency_sbom_and_semantic_failures(self):
        document = sbom()
        validate_sbom(json.dumps(document).encode(), "app", "0.1.0", {"app"})
        for mutate in [
            lambda b: b["metadata"]["component"].update(name="other"),
            lambda b: b["metadata"]["component"].update(version="0.2.0"),
            lambda b: b["components"].append({"bom-ref": "app"}),
            lambda b: b["dependencies"][0]["dependsOn"].append("missing"),
            lambda b: b.update(dependencies=[]),
            lambda b: b.update(specVersion="1.6"),
        ]:
            bad = copy.deepcopy(document)
            mutate(bad)
            with self.assertRaises(BuildError):
                validate_sbom(json.dumps(bad).encode(), "app", "0.1.0", {"app"})
        with self.assertRaises(BuildError):
            parse_json(b'{"bomFormat":"CycloneDX","bomFormat":"other"}')
        with self.assertRaises(BuildError):
            parse_json(b'{"value":NaN}')

    def test_valid_existing_reference_rerouting_and_dependency_version_tamper_fail(self):
        document = sbom()
        document["components"] = [{"type": "library", "bom-ref": "dep", "name": "optional-dep", "version": "0.1.0"}]
        document["dependencies"] = [{"ref": "app", "dependsOn": ["dep"]}, {"ref": "dep", "dependsOn": []}]
        metadata = reconcile_metadata(graph(), evidence({"app": ["extra"], "dep": []}), case(features=["extra"]))
        validate_sbom(json.dumps(document).encode(), "app", "0.1.0", {"app", "dep"}, metadata)
        document["dependencies"][0]["dependsOn"] = ["app"]
        with self.assertRaises(BuildError):
            validate_sbom(json.dumps(document).encode(), "app", "0.1.0", {"app", "dep"}, metadata)
        document["dependencies"][0]["dependsOn"] = ["dep"]
        document["components"][0]["version"] = "0.2.0"
        with self.assertRaises(BuildError):
            validate_sbom(json.dumps(document).encode(), "app", "0.1.0", {"app", "dep"}, metadata)

    def test_schema_valid_root_reference_swap_cannot_hide_dependency_identity(self):
        document = sbom()
        document["metadata"]["component"]["bom-ref"] = "dep"
        document["components"] = [{"type": "library", "bom-ref": "app", "name": "app", "version": "0.1.0"}]
        document["dependencies"] = [{"ref": "app", "dependsOn": ["dep"]}, {"ref": "dep", "dependsOn": []}]
        metadata = reconcile_metadata(graph(), evidence({"app": ["extra"], "dep": []}), case(features=["extra"]))
        with self.assertRaisesRegex(BuildError, "root reference"):
            validate_sbom(json.dumps(document).encode(), "app", "0.1.0", {"app", "dep"}, metadata)

    def test_metadata_adapter_never_executes_cargo_or_accepts_other_args(self):
        with tempfile.TemporaryDirectory() as temporary:
            executable = metadata_adapter(Path(temporary), graph(), ["metadata", "--format-version", "1"])
            success = subprocess.run([str(executable), "metadata", "--format-version", "1"], capture_output=True, check=True)
            self.assertEqual(parse_json(success.stdout), graph())
            failed = subprocess.run([str(executable), "build", "; touch /tmp/armorer-injected"], capture_output=True)
            self.assertEqual(failed.returncode, 64)
            self.assertEqual(failed.stdout, b"")

    def test_compiler_artifact_requires_one_successful_selected_build(self):
        artifact = {"reason": "compiler-artifact", "package_id": "app", "features": [],
                    "target": {"name": "app", "kind": ["bin"]}, "executable": "/tmp/target/app"}
        finish = {"reason": "build-finished", "success": True}
        payload = b"uncontrolled compiler output\n" + json.dumps(artifact).encode() + b"\n" + json.dumps(finish).encode()
        self.assertEqual(compiler_evidence(payload, case())["features"], {"app": []})
        for bad in [json.dumps(artifact).encode(), payload + b"\n" + json.dumps(artifact).encode(),
                    json.dumps({**finish, "success": False}).encode()]:
            with self.assertRaises(BuildError):
                compiler_evidence(bad, case())


class InventoryTests(unittest.TestCase):
    def test_exact_byte_inventory_rejects_tampered_missing_extra_and_wrong_selection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact_id = case()["artifact_id"]
            artifact, bom = root / (artifact_id + ".bin"), root / (artifact_id + ".cdx.json")
            cargo_graph = root / (artifact_id + ".cargo-graph.json")
            artifact.write_bytes(b"binary")
            bom.write_bytes(json.dumps(sbom()).encode())
            cargo_graph.write_bytes(b'{"compiled_packages":{}}')
            inventory = {"schema_version": 1, "signing_status": "unsigned", "selection": case(),
                         "files": [_file_record(artifact, "artifact"), _file_record(bom, "sbom"), _file_record(cargo_graph, "cargo-graph")],
                         "state": "build-produced", "provenance_status": "not-attested", "source": {"repository": "fixture/build", "commit": "a" * 40},
                         "runtime_commit": "b" * 40, "run_id": "12", "run_attempt": "1",
                         "input_sha256": {k: "a" * 64 for k in ("armorer.toml", "armorer.lock", "Cargo.lock")},
                         "source_input_sha256": {"Cargo.toml": "c" * 64}, "tool_sha256": {"cargo-cyclonedx": "d" * 64},
                         "tool_pin_authority": "immutable-trusted-workflow-catalog", "graph_scope": "compiled-cargo-target-and-host-build-dependencies",
                         "coverage_gaps": ["native and system libraries are not fully inventoried"], "artifact_kind": "executable"}
            (root / "inventory.json").write_text(json.dumps(inventory))
            verify_inventory(root, inventory, case())
            manifest = root / "inventory.json"
            canonical_manifest = manifest.read_bytes()
            mutations = [b"NOT JSON", b'{"schema_version":1,"schema_version":1}',
                         json.dumps({**inventory, "source": {"repository": "other/repo", "commit": "a" * 40}}).encode(),
                         json.dumps({**inventory, "schema_version": True}).encode()]
            for changed_manifest in mutations:
                manifest.write_bytes(changed_manifest)
                with self.assertRaises(BuildError):
                    verify_inventory(root, inventory, case())
            manifest.unlink()
            manifest.symlink_to(artifact)
            with self.assertRaises(BuildError):
                verify_inventory(root, inventory, case())
            manifest.unlink()
            manifest.mkdir()
            with self.assertRaises(BuildError):
                verify_inventory(root, inventory, case())
            manifest.rmdir()
            manifest.write_bytes(canonical_manifest)
            for path in (artifact, bom):
                before = path.read_bytes()
                path.write_bytes(before + b"tampered")
                with self.assertRaises(BuildError):
                    verify_inventory(root, inventory, case())
                path.write_bytes(before)
            bom.unlink()
            with self.assertRaises(OSError):
                verify_inventory(root, inventory, case())
            bom.write_bytes(json.dumps(sbom()).encode())
            (root / "extra").write_bytes(b"unexpected")
            with self.assertRaises(BuildError):
                verify_inventory(root, inventory, case())
            (root / "extra").unlink()
            with self.assertRaises(BuildError):
                verify_inventory(root, inventory, case(package="other"))
            duplicate = {**inventory, "files": inventory["files"] + [inventory["files"][0]]}
            manifest.write_text(json.dumps(duplicate))
            with self.assertRaises(BuildError):
                verify_inventory(root, duplicate, case())
            manifest.write_bytes(canonical_manifest)
            expected_context = {k: inventory[k] for k in ("source", "runtime_commit", "run_id", "run_attempt")}
            verify_inventory(root, inventory, case(), expected_context)
            for key, value in [("source", {"repository": "other/repo", "commit": "a" * 40}),
                               ("source", {"repository": "fixture/build", "commit": "c" * 40}),
                               ("runtime_commit", "c" * 40), ("run_id", "13"), ("run_attempt", "2")]:
                bad = {**inventory, key: value}
                manifest.write_text(json.dumps(bad))
                with self.assertRaisesRegex(BuildError, "source, runtime or run identity"):
                    verify_inventory(root, bad, case(), expected_context)
                manifest.write_bytes(canonical_manifest)
            renamed = root / "other-valid-name.bin"
            artifact.rename(renamed)
            renamed_inventory = copy.deepcopy(inventory)
            renamed_inventory["files"][0]["name"] = renamed.name
            manifest.write_text(json.dumps(renamed_inventory))
            with self.assertRaisesRegex(BuildError, "filename"):
                verify_inventory(root, renamed_inventory, case(), expected_context)
            renamed.rename(artifact)
            manifest.write_bytes(canonical_manifest)
            for updates in [{"untrusted_claim": True}, {"schema_version": True}, {"selection": []}, {"provenance_status": "verified"}, {"run_attempt": None}, {"run_id": "0"}]:
                manifest.write_text(json.dumps({**inventory, **updates}))
                with self.assertRaises(BuildError):
                    verify_inventory(root, {**inventory, **updates}, case())
                manifest.write_bytes(canonical_manifest)
            # Both identifier limits are valid in the Rust/common contract;
            # their longest graph asset is longer than 240, but below 255 bytes.
            longest_id = "a" * 100 + "--x86_64-unknown-linux-gnu--" + "b" * 100
            longest_case = case(id="a" * 100, feature_set="b" * 100, artifact_id=longest_id)
            longest_inventory = copy.deepcopy(inventory)
            longest_inventory["selection"] = longest_case
            suffixes = {"artifact": ".bin", "sbom": ".cdx.json", "cargo-graph": ".cargo-graph.json"}
            for index, record in enumerate(longest_inventory["files"]):
                renamed_asset = root / (longest_id + suffixes[record["role"]])
                (root / record["name"]).rename(renamed_asset)
                longest_inventory["files"][index] = _file_record(renamed_asset, record["role"])
            manifest.write_text(json.dumps(longest_inventory))
            verify_inventory(root, longest_inventory, longest_case, expected_context)


if __name__ == "__main__":
    unittest.main()
