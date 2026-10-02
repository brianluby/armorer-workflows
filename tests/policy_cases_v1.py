"""Real independent native report production on isolated synthetic library/CLI/service selections."""

import argparse
import json
from pathlib import Path
import tempfile

from armorer_runtime import common, policy_tools_v1 as pins, policy_v1 as policy, tools
from build_cases import create_fixture
from build_cases_v3 import extend_fixture


def main() -> None:
    """Produce and independently check four actual native report sets; all source identities are synthetic fixtures."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--armorer", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    runtime = Path(policy.__file__).resolve().parent.parent
    target = tools.platform_target()
    environment = common.base_environment()
    runtime_commit = policy.git(runtime, ["rev-parse", "HEAD"], environment).decode().strip()
    catalog, catalog_id = pins.load_catalog()
    expected_catalog = {"catalog": catalog, "identity": catalog_id}
    runtime_inputs = policy.runtime_inputs(runtime_commit, environment)
    require = common.require
    require(not args.output.exists(), "native receipt output already exists")
    args.output.mkdir(parents=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix="armorer-policy-cases-") as temporary:
        parent = Path(temporary); root = parent / "source"; root.mkdir()
        create_fixture(root, target); extend_fixture(root, target)
        (root / "app/build.rs").write_text('fn main() { panic!("consuming policy build scripts must never run"); }\n')
        workflow = root / ".github/workflows/ci.yml"; workflow.parent.mkdir(parents=True)
        workflow.write_text('''name: Independent fixture
on: push
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-24.04
    steps:
      - run: echo fixture
''')
        policy_input = root / ".armorer/ci-policy.toml"; policy_input.parent.mkdir()
        policy_input.write_text('''schema_version = 1
[licenses]
allow = ["MIT", "Apache-2.0"]
[advisories]
exceptions = []
[sources]
allow_git = []
[bans]
multiple_versions = "warn"
deny = []
''')
        cargo_home = parent / "fixture-cargo"; cargo_home.mkdir()
        cargo_environment = common.cargo_environment("1.95.0", cargo_home, parent / "fixture-target")
        for arguments in (["/usr/bin/git", "init", "-q"], ["cargo", "generate-lockfile", "--manifest-path", str(root / "Cargo.toml")],
                          ["/usr/bin/git", "add", "."], ["/usr/bin/git", "-c", "user.name=Armorer Fixture", "-c", "user.email=fixture@example.invalid",
                           "-c", "commit.gpgsign=false", "commit", "-qm", "independent fixture"]):
            common.run(arguments, cwd=root, env=cargo_environment)
        source_commit = policy.git(root, ["rev-parse", "HEAD"], environment).decode().strip()
        expected_context = {"source": {"repository": "fixture/build", "commit": source_commit}, "runtime_commit": runtime_commit,
                            "run_id": "17", "run_attempt": "2", "event": "workflow_dispatch", "ref": "refs/heads/fixture"}
        expected_inputs = policy.snapshot(root)
        project = common.load_project(root, args.armorer, "fixture/build")
        expected_policy = policy.ci.load_policy(root)
        cases = []
        for identifier, feature in (("minimal", "minimal"), ("extra", "extra"), ("zero", "minimal"), ("service", "service")):
            key = f"{identifier}--{target}--{feature}"
            output = args.output / identifier
            envelope = policy.produce(root, args.armorer, key, output, expected_context)
            selection = common.select(project, key)
            policy.verify(output, expected_context, selection, expected_inputs, runtime_inputs, expected_catalog, expected_policy)
            wrong_run = {**expected_context, "run_attempt": "3"}
            try:
                policy.verify(output, wrong_run, selection, expected_inputs, runtime_inputs, expected_catalog, expected_policy)
            except common.Failure:
                pass
            else:
                raise AssertionError("cross-run report accepted")
            cases.append({"selection": key, "profile": selection["profile"], "reports": envelope["reports"], "checks": envelope["checks"]})
        require(policy.snapshot(root) == expected_inputs and not (parent / "fixture-target").exists(), "policy checks executed builds or changed source")
        negatives = []
        key = f"minimal--{target}--minimal"
        wrong_source = {**expected_context, "source": {**expected_context["source"], "commit": "0" * 40}}
        try:
            policy.produce(root, args.armorer, key, parent / "wrong-source", wrong_source)
        except common.Failure:
            require(not (parent / "wrong-source").exists(), "rejected source retained reports")
            negatives.append("independently wrong source commit rejected before tool installation")
        else:
            raise AssertionError("wrong source report produced")
        # These mutations and Git commits affect only this isolated synthetic fixture.
        manifest = root / "app/Cargo.toml"
        original_manifest = manifest.read_bytes()
        manifest.write_bytes(original_manifest.replace(b'license = "MIT"', b'license = "GPL-3.0-only"'))
        for arguments in (["add", "."], ["-c", "user.name=Armorer Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "denied fixture license"]):
            policy.git(root, arguments, environment)
        denied_context = {**expected_context, "source": {**expected_context["source"], "commit": policy.git(root, ["rev-parse", "HEAD"], environment).decode().strip()}}
        try:
            policy.produce(root, args.armorer, key, parent / "denied-license", denied_context)
        except common.Failure:
            require(not (parent / "denied-license").exists(), "failed license retained passing reports")
            negatives.append("actual native denied license produced no passing report")
        else:
            raise AssertionError("denied license report produced")
        manifest.write_bytes(original_manifest)
        # Construct an explicitly synthetic test token; matched data never enters receipts or logs.
        sentinel = "".join(("ghp_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"))
        (root / "secret.txt").write_text("token=" + sentinel + " # gitleaks:allow\n")
        (root / ".gitleaks.toml").write_text('[allowlist]\npaths=[".*"]\n')
        for arguments in (["add", "."], ["-c", "user.name=Armorer Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "synthetic secret denial"]):
            policy.git(root, arguments, environment)
        denied_context = {**expected_context, "source": {**expected_context["source"], "commit": policy.git(root, ["rev-parse", "HEAD"], environment).decode().strip()}}
        try:
            policy.produce(root, args.armorer, key, parent / "denied-secret", denied_context)
        except common.Failure as error:
            require(not (parent / "denied-secret").exists() and sentinel not in str(error), "failed secret leaked or retained reports")
            negatives.append("actual native secret despite caller suppressions produced no passing report or raw diagnostic")
        else:
            raise AssertionError("secret report produced")
        require(not (parent / "fixture-target").exists(), "rejected policy cases executed consuming builds")
        receipt = {"native_target": target, "runtime_commit": runtime_commit, "source": expected_context["source"],
                   "source_inputs": expected_inputs, "runtime_inputs": runtime_inputs, "tool_catalog": catalog_id, "cases": cases,
                   "fixture_context": expected_context, "independent_consistency_verified": True, "negative_cases": negatives,
                   "consuming_build_scripts_executed": False, "producer_job_authenticated": False, "signed": False,
                   "run_identity": "synthetic fixture-only 17/2", "production_catalog_accepted": False}
        (args.output / "qualification.json").write_bytes(policy.canonical(receipt))
        print(json.dumps({"native_target": target, "cases": len(cases), "consuming_build_scripts_executed": False,
                          "producer_job_authenticated": False, "signed": False}))


if __name__ == "__main__":
    main()
