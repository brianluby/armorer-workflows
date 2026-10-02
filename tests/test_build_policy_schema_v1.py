"""Explicit policy observation schema positives and structural rejection boundaries."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from jsonschema import Draft202012Validator, ValidationError
import tests_policy_v1 as fixtures


class PolicySchemaTests(unittest.TestCase):
    """Schema consistency is tested separately from authentication and meaningful native checks."""

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
