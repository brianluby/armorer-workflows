"""Independent draft-2020-12 validation of the documented unsigned inventory."""

import copy
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator, ValidationError

from test_build import case


class SchemaTests(unittest.TestCase):
    def setUp(self):
        """Prepare an independent v1 schema validator and unsigned inventory control."""
        self.schema = json.loads((Path(__file__).resolve().parent.parent / "schemas/build-inventory-v1.json").read_text())
        Draft202012Validator.check_schema(self.schema)
        self.validator = Draft202012Validator(self.schema)
        self.inventory = {"schema_version": 1, "state": "build-produced", "signing_status": "unsigned",
                          "provenance_status": "not-attested", "source": {"repository": "fixture/build", "commit": "a" * 40},
                          "runtime_commit": "b" * 40, "run_id": "12", "run_attempt": "1", "selection": case(),
                          "input_sha256": {k: "a" * 64 for k in ("armorer.toml", "armorer.lock", "Cargo.lock")},
                          "source_input_sha256": {"Cargo.toml": "c" * 64}, "tool_sha256": {"cargo-cyclonedx": "d" * 64},
                          "tool_pin_authority": "immutable-trusted-workflow-catalog",
                          "graph_scope": "compiled-cargo-target-and-host-build-dependencies",
                          "coverage_gaps": ["native and system libraries are not fully inventoried"], "artifact_kind": "executable",
                          "files": [{"name": "app" + suffix, "role": role, "size": 7, "sha256": "e" * 64}
                                    for suffix, role in ((".bin", "artifact"), (".cdx.json", "sbom"), (".cargo-graph.json", "cargo-graph"))]}

    def test_documented_inventory_validates_with_independent_validator(self):
        """Accept executable/library controls and supported longest asset names."""
        self.validator.validate(self.inventory)
        library = copy.deepcopy(self.inventory)
        library["selection"].update(profile="library", binary=None)
        library["artifact_kind"] = "source-package"
        self.validator.validate(library)
        longest = copy.deepcopy(self.inventory)
        artifact_id = "a" * 100 + "--x86_64-unknown-linux-gnu--" + "b" * 100
        longest["selection"].update(id="a" * 100, feature_set="b" * 100, artifact_id=artifact_id)
        for record in longest["files"]:
            suffix = {"artifact": ".bin", "sbom": ".cdx.json", "cargo-graph": ".cargo-graph.json"}[record["role"]]
            record["name"] = artifact_id + suffix
        self.validator.validate(longest)

    def test_schema_rejects_claims_and_malformed_identity_or_assets(self):
        """Reject unsupported claims, injection fields and malformed byte identities."""
        mutations = [
            lambda b: b.update(provenance_status="verified"),
            lambda b: b.update(signer="untrusted"),
            lambda b: b.update(runtime_commit="main"),
            lambda b: b.update(run_id="0"),
            lambda b: b["source"].update(commit="release-tag"),
            lambda b: b["selection"].update(shell="echo forged"),
            lambda b: b["files"][0].update(name="../escape"),
            lambda b: b["files"][0].update(size=-1),
            lambda b: b["files"][0].update(sha256="wrong"),
            lambda b: b["files"].pop(),
        ]
        for mutation in mutations:
            document = copy.deepcopy(self.inventory)
            mutation(document)
            with self.assertRaises(ValidationError):
                self.validator.validate(document)


class SchemaV2Tests(SchemaTests):
    def setUp(self):
        """Check successor schema independently while retaining all v1 inventory assertions."""
        super().setUp()
        self.schema = json.loads((Path(__file__).resolve().parent.parent / "schemas/build-inventory-v2.json").read_bytes())
        Draft202012Validator.check_schema(self.schema)
        self.validator = Draft202012Validator(self.schema)
        self.inventory.update(schema_version=2, cargo_graph_version=2)

    def test_versions_and_graph_markers_are_explicit(self):
        """Reject absent or older markers instead of inferring an upgrade from payload fields."""
        for mutate in (
            lambda r: r.update(schema_version=1),
            lambda r: r.update(cargo_graph_version=1),
            lambda r: r.pop("cargo_graph_version"),
            lambda r: r.update(cargo_graph_version=True),
        ):
            record = copy.deepcopy(self.inventory)
            mutate(record)
            with self.assertRaises(ValidationError):
                self.validator.validate(record)

    def test_shared_graphs_validate_against_generated_rust_schema(self):
        """Check byte-identical writer fixtures with the consumer-generated graph schema."""
        base = Path(__file__).resolve().parent
        schema = json.loads((base.parent / "schemas/cargo-graph-v2.json").read_bytes())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        for path in sorted((base / "fixtures/cargo-graph-v2").glob("*.graph.json")):
            record = json.loads(path.read_bytes())
            validator.validate(record)
            for mutate in (
                lambda r: r.update(schema_version=1),
                lambda r: r.update(caller_command="build"),
                lambda r: r.pop("packages"),
                lambda r: r["nodes"][0].update(extra="unrecognized"),
            ):
                changed = copy.deepcopy(record)
                mutate(changed)
                with self.assertRaises(ValidationError):
                    validator.validate(changed)


if __name__ == "__main__":
    unittest.main()
