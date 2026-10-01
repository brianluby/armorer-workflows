"""Boundary failures use independent fixtures rather than mirroring branches."""

import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

from armorer_runtime import common, tools


def intent():
    return {"toolchain": "1.95.0", "feature_sets": {"minimal": {"default_features": False, "features": ["extra"]}},
            "deliverables": [{"id": "application", "package": "sample", "profile": "cli", "binary": "sample",
                              "feature_set": "minimal", "targets": ["x86_64-unknown-linux-gnu"]}]}


def archive(members):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as handle:
        for name, content, kind in members:
            entry = tarfile.TarInfo(name)
            entry.type = kind
            entry.size = len(content) if kind == tarfile.REGTYPE else 0
            entry.linkname = "/etc/passwd" if kind == tarfile.SYMTYPE else ""
            handle.addfile(entry, io.BytesIO(content) if content else None)
    return data.getvalue()


class CommonTests(unittest.TestCase):
    def test_feature_and_runner_selection_are_rederived(self):
        config = intent()
        cases = common.selections(config)
        self.assertEqual(cases[0]["runner"], "ubuntu-24.04")
        self.assertEqual(cases[0]["artifact_id"], "application--x86_64-unknown-linux-gnu--minimal")
        project = common.Project(Path("/tmp"), config, {}, [])
        self.assertEqual(common.select(project, cases[0]["artifact_id"]), cases[0])
        with self.assertRaises(common.Failure):
            common.select(project, "forged-subject")

    def test_shell_and_option_inputs_are_rejected(self):
        for feature in ["$(touch sentinel)", "--all-features", "x,y", "dependency/feature", "x\nflag"]:
            config = intent()
            config["feature_sets"]["minimal"]["features"] = [feature]
            with self.subTest(feature=feature), self.assertRaises(common.Failure):
                common.selections(config)
        config = intent()
        config["deliverables"][0]["package"] = "--workspace"
        with self.assertRaises(common.Failure):
            common.selections(config)

    def test_unsupported_trigger_cannot_start(self):
        for event in ["pull_request_target", "workflow_run", "schedule", "release", ""]:
            with self.subTest(event=event), self.assertRaises(common.Failure):
                common.check_trigger(event)

    def test_hosted_matrix_limit_fails_closed(self):
        config = intent()
        config["deliverables"] = [{**config["deliverables"][0], "id": f"case-{i}"} for i in range(129)]
        with self.assertRaises(common.Failure):
            common.selections(config)

    def test_duplicate_json_identity_is_rejected(self):
        with self.assertRaises(common.Failure):
            common.strict_json(b'{"repository":"right","repository":"wrong"}')

    def test_path_symlink_and_fifo_inputs_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "regular").write_text("valid")
            (root / "link").symlink_to(root / "regular")
            if hasattr(os, "mkfifo"):
                os.mkfifo(root / "pipe")
            for relative in ["../escape", "/etc/passwd", "link", "pipe"]:
                with self.subTest(relative=relative), self.assertRaises(common.Failure):
                    common.read_input(root, relative)

    def test_manifest_binding_rejects_changed_or_ambiguous_name(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = b'[package]\nname="sample"\nversion="0.1.0"\n'
            (root / "Cargo.toml").write_bytes(data)
            plan = {"workspace": {"packages": [{"name": "sample"}], "inputs": {"Cargo.toml": common.sha256(data)}}}
            project = common.Project(root, intent(), plan, [])
            self.assertEqual(common.member_manifest(project, "sample"), root / "Cargo.toml")
            (root / "Cargo.toml").write_bytes(data + b"# changed\n")
            with self.assertRaises(common.Failure):
                common.member_manifest(project, "sample")
            (root / "Cargo.toml").write_bytes(data)
            (root / "nested").mkdir()
            (root / "nested/Cargo.toml").write_bytes(data)
            plan["workspace"]["inputs"]["nested/Cargo.toml"] = common.sha256(data)
            with self.assertRaises(common.Failure):
                common.member_manifest(project, "sample")

    def test_cargo_ancestor_configuration_is_rejected_without_reading_values(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            (parent / ".cargo").mkdir()
            (parent / ".cargo/config.toml").write_text("DO-NOT-ECHO")
            nested = parent / "source"
            nested.mkdir()
            with self.assertRaisesRegex(common.Failure, "Cargo ancestor") as caught:
                common.reject_cargo_configuration(nested)
            self.assertNotIn("DO-NOT-ECHO", str(caught.exception))

    def test_caller_path_and_credential_environment_are_not_forwarded(self):
        with patch.dict(os.environ, {"PATH": "/tmp/tenant/fake-bin", "GH_TOKEN": "DO-NOT-ECHO",
                                     "RUSTFLAGS": "tenant flags", "RUSTC_WRAPPER": "/tmp/tenant/wrapper"}):
            environment = common.base_environment()
        self.assertNotIn("/tmp/tenant", environment["PATH"])
        self.assertNotIn("GH_TOKEN", environment)
        self.assertNotIn("RUSTFLAGS", environment)
        self.assertEqual(environment["RUSTC_WRAPPER"], "")

    def test_fixed_command_failure_never_echoes_process_output(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(common.Failure) as caught:
                common.run(["/bin/sh", "-c", "echo DO-NOT-ECHO >&2; exit 1"], cwd=Path(directory))
            self.assertNotIn("DO-NOT-ECHO", str(caught.exception))

    def test_timeout_kills_build_script_descendants(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(common.Failure, "timed out"):
                common.run(["/bin/sh", "-c", "(sleep 0.6; touch escaped-child) & wait"], cwd=root, timeout=0.15)
            time.sleep(0.7)
            self.assertFalse((root / "escaped-child").exists())

    def test_tool_archive_rejects_links_escapes_and_duplicate_binaries(self):
        cases = [[("../tool", b"code", tarfile.REGTYPE)], [("tool", b"", tarfile.SYMTYPE)],
                 [("one/tool", b"code", tarfile.REGTYPE), ("two/tool", b"code", tarfile.REGTYPE)]]
        for members in cases:
            with self.subTest(members=members), self.assertRaises(common.Failure):
                tools.extract_binary(archive(members), "tool", "tar.gz")
        self.assertEqual(tools.extract_binary(archive([("bin/tool", b"code", tarfile.REGTYPE)]), "tool", "tar.gz"), b"code")

    def test_tampered_distribution_never_extracts_or_executes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalog = root / "catalog.json"
            catalog.write_text(json.dumps({"schema_version": 1, "tools": {"tool": {"binary": "tool", "platforms": {
                "x86_64-unknown-linux-gnu": {"url": "https://github.com/example/tool", "sha256": "0" * 64, "format": "binary"}}}}}))
            with patch.object(tools, "CATALOG", catalog), patch.object(tools, "platform_target", return_value="x86_64-unknown-linux-gnu"), \
                    patch("urllib.request.urlopen", return_value=io.BytesIO(b"tampered bytes")):
                with self.assertRaisesRegex(common.Failure, "digest mismatch"):
                    tools.install_tools(root / "installed", ["tool"])
                self.assertEqual(list((root / "installed").iterdir()), [])


if __name__ == "__main__":
    unittest.main()
