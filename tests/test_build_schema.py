"""Independent draft-2020-12 validation of the documented unsigned inventory."""

import copy
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator, ValidationError

from test_build import case


class SchemaTests(unittest.TestCase):
    def setUp(self):
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


if __name__ == "__main__":
    unittest.main()
