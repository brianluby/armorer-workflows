"""CI policy failures, scanner suppression and exact feature commands."""

from datetime import date
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import shutil
import time
import tomllib
import unittest
from unittest.mock import patch

from armorer_runtime import ci, common, tools

POLICY = '''schema_version = 1
[licenses]
allow = ["MIT", "Apache-2.0"]
[advisories]
exceptions = []
[sources]
allow_git = []
[bans]
multiple_versions = "warn"
deny = []
'''


def write_policy(root, text=POLICY):
    (root / ".armorer").mkdir(exist_ok=True)
    (root / ci.POLICY_PATH).write_text(text)


class PolicyTests(unittest.TestCase):
    def test_explicit_policy_and_translation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_policy(root)
            policy = ci.load_policy(root)
            generated = ci.deny_configuration(policy, root / "db")
            self.assertIn('maximum-db-staleness = "P1D"', generated)
            self.assertIn('unknown-git = "deny"', generated)
            self.assertIn('wildcards = "deny"', generated)
            self.assertIn('unsound = "all"', generated)
            self.assertIn("include-dev = true", generated)
            self.assertIn("include-build = true", generated)
            self.assertNotIn("DO-NOT-ECHO", generated)

    def test_unicode_policy_and_database_paths_roundtrip_as_toml(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entry = '{ id="RUSTSEC-2020-0001", owner="Maintainer 🛡️", reason="Reviewed impact 🛡️", expires="2026-10-01" }'
            write_policy(root, POLICY.replace("exceptions = []", "exceptions = [" + entry + "]"))
            policy = ci.load_policy(root, date(2026, 9, 30))
            database = root / "advisories-🛡️"
            document = tomllib.loads(ci.deny_configuration(policy, database))
            self.assertEqual(document["advisories"]["db-path"], str(database))
            self.assertIn("Maintainer 🛡️: Reviewed impact 🛡️", document["advisories"]["ignore"][0]["reason"])

    def test_missing_or_permissive_policy_is_not_invented(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(common.Failure):
                ci.load_policy(root)
            write_policy(root, POLICY.replace('allow = ["MIT", "Apache-2.0"]', "allow = []"))
            with self.assertRaises(common.Failure):
                ci.load_policy(root)
            write_policy(root, POLICY + '\n[custom]\ncommand="arbitrary"\n')
            with self.assertRaises(common.Failure):
                ci.load_policy(root)

    def test_expired_unbounded_or_unowned_advisory_exceptions_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for expiry, owner in [("2026-09-29", "team"), ("2027-12-31", "team"), ("2026-10-01", " ")]:
                entry = f'{{ id="RUSTSEC-2020-0001", owner="{owner}", reason="reviewed exception", expires="{expiry}" }}'
                write_policy(root, POLICY.replace("exceptions = []", "exceptions = [" + entry + "]"))
                with self.subTest(expiry=expiry, owner=owner), self.assertRaises(common.Failure):
                    ci.load_policy(root, date(2026, 9, 30))
            entry = '{ id="RUSTSEC-2020-0001", owner="team", reason="reviewed exception", expires="2026-10-01" }'
            write_policy(root, POLICY.replace("exceptions = []", "exceptions = [" + entry + "]"))
            self.assertEqual(len(ci.load_policy(root, date(2026, 9, 30))["advisories"]["exceptions"]), 1)

    def test_cargo_ci_cases_preserve_explicit_features(self):
        case = {"package": "sample", "target": "aarch64-apple-darwin", "default_features": False, "features": ["selected"]}
        commands = ci.cargo_commands(case, True)
        self.assertEqual(len(commands), 3)
        for command in commands:
            self.assertIn("--locked", command)
            self.assertIn("--no-default-features", command)
            self.assertIn("selected", command)
            self.assertNotIn("--all-features", command)
        self.assertIn("--doc", commands[1])

    def test_doctest_gate_supports_proc_macros_without_inventing_cargo_capabilities(self):
        for kind in ("lib", "rlib", "proc-macro"):
            self.assertTrue(ci.has_doctest_target({"targets": [{"kind": [kind]}]}))
        for kind in ("dylib", "cdylib", "staticlib", "bin"):
            self.assertFalse(ci.has_doctest_target({"targets": [{"kind": [kind]}]}))
        self.assertTrue(ci.has_doctest_target({"targets": [{"kind": ["cdylib", "rlib"]}]}))

    @unittest.skipUnless(os.environ.get("ARMORER_TEST_TOOLS"), "requires pinned native Rust toolchain")
    def test_real_proc_macro_doctest_failure_is_not_skipped(self):
        with tempfile.TemporaryDirectory(prefix="armorer-macro-test-") as directory:
            scratch = Path(directory)
            root = scratch / "source"
            (root / "src").mkdir(parents=True)
            (root / "Cargo.toml").write_text('''[package]
name = "fixture-macro"
version = "0.1.0"
edition = "2024"
license = "MIT"
[lib]
proc-macro = true
''')
            (root / "src/lib.rs").write_text('''extern crate proc_macro;
/// ```
/// compile_error!("the documentation gate must run");
/// ```
#[proc_macro]
pub fn armor(input: proc_macro::TokenStream) -> proc_macro::TokenStream { input }
''')
            cargo_home = scratch / "cargo"
            cargo_home.mkdir()
            env = common.cargo_environment("1.95.0", cargo_home, scratch / "target")
            common.run(["cargo", "generate-lockfile"], cwd=root, env=env)
            case = {"package": "fixture-macro", "target": tools.platform_target(), "default_features": False, "features": []}
            commands = ci.cargo_commands(case, ci.has_doctest_target({"targets": [{"kind": ["proc-macro"]}]}))
            common.run(commands[0], cwd=root, env=env)
            self.assertIn("--doc", commands[1])
            with self.assertRaises(common.Failure):
                common.run(commands[1], cwd=root, env=env)

    def test_fresh_advisory_outage_prevents_offline_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_policy(root)
            manifest = root / "Cargo.toml"
            data = b'[package]\nname="sample"\nversion="0.1.0"\n'
            manifest.write_bytes(data)
            project = common.Project(root, {}, {"workspace": {"packages": [{"name": "sample"}], "inputs": {
                "Cargo.toml": common.sha256(data)}}}, [])
            calls = []
            def outage(command, **kwargs):
                calls.append(command)
                if "fetch" in command and "all" in command:
                    raise common.Failure("fixed command failed")
            case = {"package": "sample", "target": "x86_64-unknown-linux-gnu", "default_features": False, "features": []}
            with self.assertRaises(common.Failure):
                ci.run_policy(project, case, ci.load_policy(root), Path("/trusted/cargo-deny"), root, {}, runner=outage)
            self.assertEqual(len(calls), 2)
            self.assertEqual(calls[0][0:3], ["cargo", "fetch", "--locked"])
            self.assertFalse(any("check" in command for command in calls))

    def test_scanner_flags_disable_caller_suppressions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".github/workflows").mkdir(parents=True)
            (root / ".github/workflows/ci.yml").write_text("name: example\n")
            calls = []
            def record(command, **kwargs):
                calls.append(command)
            binaries = {"actionlint": Path("/trusted/actionlint"), "zizmor": Path("/trusted/zizmor")}
            ci.scan_workflows(root, binaries, runner=record)
            self.assertIn("-config-file", calls[0])
            self.assertIn("--no-config", calls[1])
            self.assertIn("--no-ignores", calls[1])
            self.assertIn("--collect=all", calls[1])
            self.assertIn("--strict-collection", calls[1])
            ci.scan_secrets(root, Path("/trusted/gitleaks"), root, runner=record)
            self.assertIn("--ignore-gitleaks-allow", calls[2])
            self.assertIn("--redact=100", calls[2])
            self.assertIn("--gitleaks-ignore-path", calls[2])

    def test_implicit_cargo_deny_exceptions_cannot_override_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = b'[package]\nname="sample"\nversion="0.1.0"\n'
            (root / "Cargo.toml").write_bytes(data)
            project = common.Project(root, {}, {"workspace": {"packages": [{"name": "sample"}], "inputs": {
                "Cargo.toml": common.sha256(data)}}}, [{"package": "sample"}])
            (root / ".deny.exceptions.toml").write_text('exceptions=[{crate="sample",allow=["GPL-3.0"]}]')
            with self.assertRaises(common.Failure):
                ci.reject_implicit_exceptions(project)

    @unittest.skipUnless(os.environ.get("ARMORER_TEST_TOOLS"), "requires reviewed native tool binaries")
    def test_real_secret_is_detected_despite_all_caller_suppressions(self):
        binary = Path(os.environ["ARMORER_TEST_TOOLS"]) / "gitleaks"
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root, scratch = Path(directory), Path(outside)
            # Synthetic public test token, constructed to avoid checking test data into source.
            sentinel = "".join(("ghp_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"))
            (root / "secret.txt").write_text("token=" + sentinel + " # gitleaks:allow\n")
            (root / ".gitleaks.toml").write_text('[allowlist]\npaths=[".*"]\n')
            (root / ".gitleaksignore").write_text("secret.txt:github-pat:1\n")
            with self.assertRaises(common.Failure) as caught:
                ci.scan_secrets(root, binary, scratch)
            self.assertNotIn(sentinel, str(caught.exception))
            (root / "secret.txt").unlink()
            ci.scan_secrets(root, binary, scratch)

    @unittest.skipUnless(os.environ.get("ARMORER_TEST_TOOLS"), "requires reviewed native tool binaries")
    def test_real_workflow_audits_reject_unsafe_trigger_even_with_ignore(self):
        binaries = {name: Path(os.environ["ARMORER_TEST_TOOLS"]) / name for name in ("actionlint", "zizmor")}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".github/workflows").mkdir(parents=True)
            (root / ".github/workflows/ci.yml").write_text('''name: unsafe
on: pull_request_target
permissions: write-all
jobs:
  unsafe:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4 # zizmor: ignore[unpinned-uses]
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo unsafe
''')
            with self.assertRaises(common.Failure):
                ci.scan_workflows(root, binaries)

    @unittest.skipUnless(os.environ.get("ARMORER_TEST_TOOLS"), "requires reviewed native tool binaries")
    def test_real_actionlint_caller_configuration_cannot_suppress_context_errors(self):
        binaries = {name: Path(os.environ["ARMORER_TEST_TOOLS"]) / name for name in ("actionlint", "zizmor")}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            common.run(["git", "init", "-q", str(root)], cwd=root)
            (root / ".github/workflows").mkdir(parents=True)
            (root / ".github/actionlint.yaml").write_text('paths:\n  .github/workflows/ci.yml:\n    ignore:\n      - .*\n')
            workflow = root / ".github/workflows/ci.yml"
            workflow.write_text('''name: broken context
on: push
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-24.04
    env:
      EXAMPLE: ${{ github.nonexistent_property }}
    steps:
      - run: echo fixture
''')
            # Demonstrate the actual tool's implicit-config bypass as a positive control.
            common.run([str(binaries["actionlint"]), "-shellcheck=", "-pyflakes=", str(workflow)], cwd=root)
            with self.assertRaises(common.Failure):
                ci.scan_workflows(root, binaries)

    @unittest.skipUnless(os.environ.get("ARMORER_TEST_TOOLS") and os.environ.get("ARMORER_TEST_NETWORK") == "1",
                         "requires reviewed binaries and public advisory feed access")
    def test_real_registry_policy_license_denial_and_stale_advisories(self):
        binary = Path(os.environ["ARMORER_TEST_TOOLS"]) / "cargo-deny"
        fixture = Path(__file__).resolve().parent.parent / "fixtures/ci-workspace"
        with tempfile.TemporaryDirectory(prefix="armorer-policy-test-") as directory:
            scratch = Path(directory)
            root = scratch / "source"
            shutil.copytree(fixture, root)
            manifest = root / "service/Cargo.toml"
            original = manifest.read_bytes()
            plan = {"workspace": {"packages": [{"name": "fixture-service"}], "inputs": {
                "service/Cargo.toml": common.sha256(original)}}}
            project = common.Project(root, {}, plan, [])
            case = {"package": "fixture-service", "target": tools.platform_target(), "default_features": False, "features": ["json"]}
            cargo_home = scratch / "cargo"
            cargo_home.mkdir()
            env = common.cargo_environment("1.95.0", cargo_home, scratch / "target")
            ci.run_policy(project, case, ci.load_policy(root), binary, scratch, env)
            # Independent invocation against actual denied metadata, using already fetched bytes.
            manifest.write_bytes(original.replace(b'license = "MIT"', b'license = "GPL-3.0-only"'))
            prefix = [str(binary), "--locked", "--offline", "--manifest-path", str(manifest), "--config", str(scratch / "deny.toml"),
                      "--target", tools.platform_target(), "--no-default-features", "--features", "json"]
            with self.assertRaises(common.Failure):
                common.run([*prefix, "check", "licenses"], cwd=scratch, env=env)
            manifest.write_bytes(original)
            databases = list((scratch / "advisory-db").glob("*/.git"))
            self.assertEqual(len(databases), 1)
            fetched = databases[0] / "FETCH_HEAD"
            fetched.write_text("fixture freshness marker\n")
            old = time.time() - 2 * 86400
            os.utime(fetched, (old, old))
            with self.assertRaises(common.Failure):
                common.run([*prefix, "check", "advisories"], cwd=scratch, env=env)
            # All three profiles execute their declared fixed command sets on this native host.
            for package, features, library in [("fixture-library", [], True), ("fixture-cli", [], False), ("fixture-service", ["json"], False)]:
                selected = {"package": package, "target": tools.platform_target(), "default_features": False, "features": features}
                for command in ci.cargo_commands(selected, library):
                    common.run(command, cwd=root, env=env)


if __name__ == "__main__":
    unittest.main()
