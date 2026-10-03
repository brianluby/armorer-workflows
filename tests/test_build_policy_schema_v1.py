"""Explicit policy observation schema positives and structural rejection boundaries."""

import copy
import ast
import json
from pathlib import Path
import tempfile
import sys
import unittest
from unittest import mock

from jsonschema import Draft202012Validator, ValidationError
import tests_policy_v1 as fixtures


class PolicySchemaTests(unittest.TestCase):
    """Schema consistency is tested separately from authentication and meaningful native checks."""

    def test_actual_workflow_validator_rejects_empty_reports_and_checks_every_match(self):
        """Run the workflow's actual schema code against empty, misplaced, valid and malformed reports."""
        root = Path(__file__).resolve().parent.parent
        workflow = (root / ".github/workflows/development.yml").read_text()
        lines = [line.strip() for line in workflow.splitlines() if line.strip().startswith("code = 'import json, sys;")]
        self.assertEqual(len(lines), 1)
        code = ast.literal_eval(lines[0].removeprefix("code = "))
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            output = parent / "observations"
            output.mkdir()
            (output / "unrelated-retained-file").write_text("does not count as a report")
            with mock.patch.object(sys, "argv", ["policy-schema-fixture", str(output)]):
                with self.assertRaisesRegex(AssertionError, "no policy reports found"):
                    exec(compile(code, "policy-schema-workflow", "exec"), {})
                # A valid report at the wrong depth must not satisfy the declared layout.
                fixture = parent / "fixture"
                fixture.mkdir()
                example, _ = fixtures.ReportBoundaryTests().fixture(fixture)
                (output / "policy-v1.json").write_text(json.dumps(example))
                with self.assertRaisesRegex(AssertionError, "no policy reports found"):
                    exec(compile(code, "policy-schema-workflow", "exec"), {})
                correct = output / "valid-selection"
                correct.mkdir()
                (correct / "policy-v1.json").write_text(json.dumps(example))
                exec(compile(code, "policy-schema-workflow", "exec"), {})
                invalid = output / "invalid-selection"
                invalid.mkdir()
                (invalid / "policy-v1.json").write_text("{}")
                with self.assertRaises(ValidationError):
                    exec(compile(code, "policy-schema-workflow", "exec"), {})

    def test_explicit_structural_example_and_rejections(self):
        """A complete synthetic shape passes while authority claims, partial reports and moving pins fail."""
        root = Path(__file__).resolve().parent.parent
        schema = json.loads((root / "schemas/policy-observation-v1.json").read_bytes())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        with tempfile.TemporaryDirectory() as temporary:
            example, _ = fixtures.ReportBoundaryTests().fixture(Path(temporary))
        validator.validate(example)
        mutations = []
        for key, value in (("signing_authorized", True), ("producer_job_authenticated", True), ("runtime_commit", "main"),
                           ("event", "pull_request_target"), ("schema_version", 2)):
            mutations.append({**example, key: value})
        missing = copy.deepcopy(example); missing["reports"].pop("gitleaks.json"); mutations.append(missing)
        failed = copy.deepcopy(example); failed["checks"]["cargo-deny.jsonl"]["advisories"]["errors"] = 1; mutations.append(failed)
        extra = copy.deepcopy(example); extra["arbitrary_command"] = "unsupported"; mutations.append(extra)
        compiler = copy.deepcopy(example); compiler["selection"]["toolchain"] = "1.94.0"; mutations.append(compiler)
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(ValidationError):
                validator.validate(mutation)


if __name__ == "__main__":
    unittest.main()
