"""Independent report boundaries and real native no-build policy qualification."""

import copy
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

from armorer_runtime import common, policy_tools_v1 as pins, policy_v1 as policy, tools


class ReportBoundaryTests(unittest.TestCase):
    """Reject ambiguous native reports, unsafe source snapshots and unbounded subprocess diagnostics."""

    def fixture(self, directory):
        """Create explicitly synthetic complete observations for independent consistency-reader tests."""
        expected_context = {"source": {"repository": "fixture/build", "commit": "a" * 40}, "runtime_commit": "b" * 40,
                            "run_id": "17", "run_attempt": "2", "event": "pull_request", "ref": "refs/pull/17/merge"}
        selection = {"id": "fixture-library", "profile": "library", "package": "fixture-library", "binary": None,
                     "targets": ["aarch64-apple-darwin"], "target": "aarch64-apple-darwin", "feature_set": "minimal",
                     "default_features": False, "features": [], "runner": "macos-15",
                     "artifact_id": "fixture-library--aarch64-apple-darwin--minimal", "toolchain": "1.95.0"}
        effective_policy = {"schema_version": 1, "licenses": {"allow": ["MIT", "Apache-2.0"]},
                            "advisories": {"exceptions": []}, "sources": {"allow_git": []},
                            "bans": {"multiple_versions": "warn", "deny": []}}
        source_inputs = {name: pins.identity(b"synthetic input") for name in ("armorer.toml", "armorer.lock", "Cargo.lock", ".armorer/ci-policy.toml")}
        runtime_inputs = {name: pins.identity(b"synthetic runtime") for name in policy.RUNTIME_INPUTS}
        catalog, catalog_id = pins.load_catalog()
        counts = {key: 0 for key in ("errors", "helps", "notes", "warnings")}
        reports = {"actionlint.json": b"[]\n", "zizmor.json": b"[]", "gitleaks.json": b"[]\n",
                   "cargo-deny.jsonl": policy.canonical({"type": "summary", "fields": {name: counts.copy() for name in ("advisories", "licenses", "sources", "bans")}}),
                   "source-inputs.json": policy.canonical(source_inputs),
                   "advisory-db.json": policy.canonical({"schema_version": 1, "repository": "https://github.com/RustSec/advisory-db",
                       "commit": "c" * 40, "tree": "d" * 40, "fetched_at": 1001, "upstream_signature_verified": False,
                       "files": {"README.md": {**pins.identity(b"synthetic"), "base64": "c3ludGhldGlj"}}})}
        envelope = {"schema_version": 1, "state": "passing-unsigned-policy-observation", **expected_context,
                    "selection": selection, "scope": "cargo-workspace-with-explicit-target-and-features",
                    "observed": {"started_at": 1000, "finished_at": 1002}, "effective_policy": effective_policy,
                    "runtime_inputs": runtime_inputs, "tool_catalog": catalog_id,
                    "tools": {name: {"version": tool["version"], "target": selection["target"], **tool["platforms"][selection["target"]]}
                              for name, tool in catalog["tools"].items()},
                    "reports": {name: pins.identity(data) for name, data in reports.items()},
                    "checks": {name: policy.passing_report(name, reports[name]) for name in policy.NATIVE_REPORTS},
                    "signing_authorized": False, "producer_job_authenticated": False, "cryptographic_release_authenticated": False}
        for name, data in {**reports, "policy-v1.json": policy.canonical(envelope)}.items():
            (directory / name).write_bytes(data)
        return envelope, (expected_context, selection, source_inputs, runtime_inputs, {"catalog": catalog, "identity": catalog_id}, effective_policy)

    def test_complete_reader_rejects_crossrun_tools_policy_and_claimed_authority(self):
        """Matching claims never replace independent run/tool/policy expectations or grant signing authority."""
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); envelope, expected = self.fixture(directory)
            self.assertEqual(policy.verify(directory, *expected, now=1003), envelope)
            for key, value in (("run_attempt", "3"), ("runtime_commit", "e" * 40), ("effective_policy", {}),
                               ("signing_authorized", True), ("producer_job_authenticated", True)):
                changed = {**envelope, key: value}; (directory / "policy-v1.json").write_bytes(policy.canonical(changed))
                with self.subTest(key=key), self.assertRaises(common.Failure):
                    policy.verify(directory, *expected, now=1003)
            changed = copy.deepcopy(envelope); changed["tools"]["gitleaks"]["executable"]["sha256"] = "0" * 64
            (directory / "policy-v1.json").write_bytes(policy.canonical(changed))
            with self.assertRaises(common.Failure):
                policy.verify(directory, *expected, now=1003)

    def test_reader_rejects_tampered_missing_extra_and_expired_report_sets(self):
        """Every offered report participates in the exact file set and byte/freshness checks."""
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); envelope, expected = self.fixture(directory)
            with self.assertRaises(common.Failure):
                policy.verify(directory, *expected, now=4601)
            for name in policy.REPORT_NAMES:
                original = (directory / name).read_bytes(); (directory / name).write_bytes(original + b"tamper")
                with self.subTest(name=name), self.assertRaises(common.Failure):
                    policy.verify(directory, *expected, now=1003)
                (directory / name).write_bytes(original)
            (directory / "extra").write_text("extra")
            with self.assertRaises(common.Failure):
                policy.verify(directory, *expected, now=1003)
            (directory / "extra").unlink(); (directory / "actionlint.json").unlink()
            with self.assertRaises(common.Failure):
                policy.verify(directory, *expected, now=1003)

    def test_self_consistent_mutated_advisory_bytes_still_fail_semantics(self):
        """Changing the envelope digest cannot legitimize an advisory file whose bytes disagree with its identity."""
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); envelope, expected = self.fixture(directory)
            database = json.loads((directory / "advisory-db.json").read_bytes())
            database["files"]["README.md"]["base64"] = "dGFtcGVy"
            data = policy.canonical(database); (directory / "advisory-db.json").write_bytes(data)
            envelope["reports"]["advisory-db.json"] = pins.identity(data)
            (directory / "policy-v1.json").write_bytes(policy.canonical(envelope))
            with self.assertRaises(common.Failure):
                policy.verify(directory, *expected, now=1003)

    def test_every_native_scanner_requires_empty_json_findings(self):
        """A successful process alone cannot turn missing or finding-bearing data into a passing report."""
        for name in policy.NATIVE_REPORTS - {"cargo-deny.jsonl"}:
            self.assertEqual(policy.passing_report(name, b"[]\n"), {"findings": 0})
            for data in (b"", b"null", b"{}", b'[{}]', b'[] []'):
                with self.subTest(name=name, data=data), self.assertRaises((common.Failure, ValueError)):
                    policy.passing_report(name, data)

    def test_four_explicit_deny_checks_require_zero_errors_and_complete_summary(self):
        """Partial, failed, duplicate or nonstandard JSON summaries cannot earn a passing observation."""
        counts = {key: 0 for key in ("errors", "helps", "notes", "warnings")}
        message = {"type": "summary", "fields": {name: counts.copy() for name in ("advisories", "licenses", "sources", "bans")}}
        self.assertEqual(set(policy.passing_report("cargo-deny.jsonl", policy.canonical(message))), set(message["fields"]))
        missing = copy.deepcopy(message); missing["fields"].pop("sources")
        failed = copy.deepcopy(message); failed["fields"]["licenses"]["errors"] = 1
        boolean = copy.deepcopy(message); boolean["fields"]["advisories"]["errors"] = False
        for data in (policy.canonical(missing), policy.canonical(failed), policy.canonical(boolean),
                     policy.canonical(message) * 2, b'{"type":"summary","type":"summary","fields":{}}',
                     policy.canonical(message) + b'{"type":"unsupported"}\n', b'NaN\n'):
            with self.subTest(data=data), self.assertRaises((common.Failure, ValueError)):
                policy.passing_report("cargo-deny.jsonl", data)

    def test_snapshot_copies_exact_inert_bytes_and_rejects_symlinks(self):
        """A source snapshot preserves consuming bytes without executing them or following external links."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory); root = parent / "source"; root.mkdir()
            (root / "build.rs").write_text('compile_error!("must not execute");\n')
            (root / ".git").mkdir(); (root / ".git/config").write_text("ignored metadata\n")
            before = (root / "build.rs").read_bytes()
            records = policy.snapshot(root, parent / "private")
            self.assertEqual(records, {"build.rs": pins.identity(before)})
            self.assertEqual((parent / "private/build.rs").read_bytes(), before)
            self.assertEqual((parent / "private/build.rs").stat().st_mode & 0o777, 0o400)
            (root / "external").symlink_to(parent / "private/build.rs")
            with self.assertRaises(common.Failure):
                policy.snapshot(root)

    def test_snapshot_enforces_file_entry_and_byte_limits(self):
        """A huge or deeply populated checkout fails before it can create an accepted observation."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / "one").write_bytes(b"1234"); (root / "two").write_bytes(b"1234")
            for constant, value in (("MAX_FILES", 1), ("MAX_SOURCE", 7), ("MAX_FILE", 3)):
                with self.subTest(constant=constant), mock.patch.object(policy, constant, value):
                    with self.assertRaises(common.Failure):
                        policy.snapshot(root)

    def test_capture_discards_failed_diagnostics_and_bounds_both_pipes(self):
        """Failed output remains private and either pipe overflowing stops the complete fixed command."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = "synthetic-sensitive-diagnostic"
            with self.assertRaises(common.Failure) as caught:
                policy.capture([sys.executable, "-I", "-c", "import sys;sys.stderr.write('" + marker + "');sys.exit(1)"], root, {})
            self.assertNotIn(marker, str(caught.exception))
            for stream in ("stdout", "stderr"):
                with self.subTest(stream=stream), mock.patch.object(policy, "MAX_REPORT", 128):
                    with self.assertRaises(common.Failure):
                        policy.capture([sys.executable, "-I", "-c", "import sys;sys." + stream + ".write('x'*1024)"], root, {})
            with self.assertRaises(common.Failure):
                policy.capture([sys.executable, "-I", "-c", "import time;time.sleep(30)"], root, {}, timeout=0)

    def test_context_rejects_unsafe_trigger_crossrun_and_moving_runtime(self):
        """A policy context requires explicit bounded immutable observations and an unprivileged event."""
        value = {"source": {"repository": "fixture/build", "commit": "a" * 40}, "runtime_commit": "b" * 40,
                 "run_id": "17", "run_attempt": "2", "event": "pull_request", "ref": "refs/pull/17/merge"}
        policy.context(value)
        for key, invalid in (("run_attempt", "0"), ("event", "pull_request_target"), ("runtime_commit", "main"), ("ref", "bad\nref")):
            changed = {**value, key: invalid}
            with self.subTest(key=key), self.assertRaises(common.Failure):
                policy.context(changed)

    def test_policy_catalog_covers_all_four_tools_and_three_native_targets(self):
        """The separate qualified catalog pins every archive and executable without replacing legacy pins."""
        catalog, byte_id = pins.load_catalog()
        self.assertEqual(set(catalog["tools"]), pins.NAMES)
        self.assertTrue(pins.byte_identity(byte_id, common.MAX_INPUT))
        for tool in catalog["tools"].values():
            self.assertEqual(set(tool["platforms"]), set(common.RUNNERS))
            for pin in tool["platforms"].values():
                self.assertNotEqual(pin["distribution"]["sha256"], pin["executable"]["sha256"])
                self.assertFalse(pin["authentication_record"]["upstream_signature_verified"])

    def test_tool_archive_requires_exact_member_and_architecture(self):
        """Whole-archive authentication precedes decoding and an alternate basename or link is rejected."""
        executable = bytearray(64); executable[:7] = b"\x7fELF\x02\x01\x01"
        executable[16:18] = (2).to_bytes(2, "little"); executable[18:20] = (62).to_bytes(2, "little")
        def archive(member, symlink=False):
            """Build inert adversarial archives for the exact leaf boundary."""
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode="w:gz") as stream:
                info = tarfile.TarInfo(member)
                if symlink:
                    info.type = tarfile.SYMTYPE; info.linkname = "/outside"
                    stream.addfile(info)
                else:
                    info.size = len(executable); stream.addfile(info, io.BytesIO(executable))
            return output.getvalue()
        data = archive("qualified/actionlint")
        pin = {"distribution": pins.identity(data), "member": "qualified/actionlint", "executable": pins.identity(executable)}
        self.assertEqual(pins.extract(data, pin, "x86_64-unknown-linux-gnu"), executable)
        with self.assertRaises(common.Failure):
            pins.extract(data + b"tamper", pin, "x86_64-unknown-linux-gnu")
        with self.assertRaises(common.Failure):
            pins.extract(data, pin, "aarch64-unknown-linux-gnu")
        for data in (archive("elsewhere/actionlint"), archive("qualified/actionlint", True), archive("../actionlint")):
            changed = {**pin, "distribution": pins.identity(data)}
            with self.assertRaises(common.Failure):
                pins.extract(data, changed, "x86_64-unknown-linux-gnu")


class NativePolicyTests(unittest.TestCase):
    """Exercise the real reviewed binaries and Cargo metadata policy without consuming code execution."""

    @unittest.skipUnless(os.environ.get("ARMORER_TEST_TOOLS") and os.environ.get("ARMORER_TEST_NETWORK") == "1",
                         "requires qualified native tools and the public advisory feed")
    def test_real_retained_reports_pass_without_running_a_build_script(self):
        """All four real scanners pass despite a build-script tripwire, with actual advisory bytes retained."""
        runtime = Path(policy.__file__).resolve().parent.parent
        catalog, _ = pins.load_catalog(); target = tools.platform_target()
        qualified = {name: pins.QualifiedTool(Path(os.environ["ARMORER_TEST_TOOLS"]) / name, target,
                    tool["version"], tool["platforms"][target]) for name, tool in catalog["tools"].items()}
        with tempfile.TemporaryDirectory(prefix="armorer-native-report-") as temporary:
            parent = Path(temporary); root = parent / "source"
            shutil.copytree(runtime / "fixtures/ci-workspace", root)
            (root / "service/build.rs").write_text('fn main() { panic!("policy must not execute consuming scripts"); }\n')
            data = {p.relative_to(root).as_posix(): common.sha256(p.read_bytes()) for p in root.rglob("Cargo.toml")}
            project = common.Project(root, {}, {"workspace": {"inputs": data, "packages": [{"name": "fixture-service"}]}},
                                     [{"package": "fixture-service"}])
            cargo_home = parent / "cargo"; cargo_home.mkdir()
            environment = common.cargo_environment("1.95.0", cargo_home, parent / "target")
            home = parent / "home"; home.mkdir(); environment["HOME"] = str(home)
            case = {"package": "fixture-service", "target": target, "toolchain": "1.95.0",
                    "default_features": False, "features": ["json"]}
            before = policy.snapshot(root)
            reports, effective_policy = policy.checks(project, case, qualified, parent, environment)
            self.assertEqual(policy.snapshot(root), before)
            self.assertEqual(set(reports), policy.NATIVE_REPORTS | {"advisory-db.json"})
            self.assertEqual(effective_policy["schema_version"], 1)
            database = json.loads(reports["advisory-db.json"])
            self.assertFalse(database["upstream_signature_verified"])
            self.assertGreater(len(database["files"]), 100)
            self.assertFalse((parent / "target").exists())
            for name in policy.NATIVE_REPORTS:
                policy.passing_report(name, reports[name])


if __name__ == "__main__":
    unittest.main()
