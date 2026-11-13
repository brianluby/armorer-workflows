"""Adversarial release-signing handoff tests; inert synthetic bytes, no live signing/OIDC/network.

These exercise the credential-free pure functions and the early approval guards. finalize_signing
invokes real codesign/notarytool and is intentionally out of scope here; the canonical repackaging,
extraction, matrix derivation and verify-stage byte binding are fully testable without credentials.
"""
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest

from armorer_runtime import release_signing_v1 as signing
from armorer_runtime.build_v3 import MAX_ARTIFACT
from armorer_runtime.common import Failure
from armorer_runtime.final_payload_v1 import MAX_METADATA


def identity(data):
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def gz_tar(members):
    """Build one synthetic gzip USTAR archive from (name, bytes-or-None-for-dir) members."""
    buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buffer, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, data in members:
                if data is None:
                    info = tarfile.TarInfo(name)
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o755
                    archive.addfile(info)
                else:
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    info.mode = 0o755
                    archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def approval(keys=("app--aarch64-apple-darwin--minimal",), *, binary="app",
             commit="a" * 40, run_id=17, run_attempt=2):
    """Construct a minimal SigningApproval directly; the pure functions never call run.validate()."""
    items = tuple(SimpleNamespace(selection={"artifact_id": key, "binary": binary}) for key in keys)
    run = SimpleNamespace(run_id=run_id, run_attempt=run_attempt)
    return signing.SigningApproval(
        run=run, items=items, apple_items=items, inputs={}, catalog={},
        build_inputs=(), team_id="DVH6X33J83",
        signing_identity="Developer ID Application: Test (DVH6X33J83)",
        signing_workflow_commit=commit, max_age_seconds=3600)


class RepackagingTests(unittest.TestCase):
    def test_repackage_then_extract_round_trips_exact_bytes(self):
        data = b"signed executable bytes\x00\x01\x02"
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "release.tar.gz"
            recorded = signing.repackage_signed(data, "app", destination)
            self.assertEqual(recorded, identity(destination.read_bytes()))
            # The finalized release archive is a single leaf named <binary>, matching the
            # armorer consumer's unpack contract, not the pkg/ apple-signing input layout.
            self.assertEqual(signing.extract_release_binary(destination, "app"), data)

    def test_release_reader_rejects_package_layout_and_foreign_leaf(self):
        with tempfile.TemporaryDirectory() as temporary:
            packaged = Path(temporary) / "packaged.tar.gz"
            packaged.write_bytes(gz_tar([("pkg", None), ("pkg/app", b"x")]))
            with self.assertRaises(Failure):
                signing.extract_release_binary(packaged, "app")
            foreign = Path(temporary) / "foreign.tar.gz"
            foreign.write_bytes(gz_tar([("other", b"x")]))
            with self.assertRaises(Failure):
                signing.extract_release_binary(foreign, "app")

    def test_package_reader_rejects_single_leaf_release_layout(self):
        data = b"signed executable bytes"
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "release.tar.gz"
            signing.repackage_signed(data, "app", destination)
            with self.assertRaises(Failure):
                signing.extract_signed_binary(destination, "app")

    def test_extract_rejects_foreign_member(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "foreign.tar.gz"
            path.write_bytes(gz_tar([("pkg", None), ("pkg/other", b"x")]))
            with self.assertRaises(Failure):
                signing.extract_signed_binary(path, "app")

    def test_extract_rejects_duplicate_binary(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "dup.tar.gz"
            path.write_bytes(gz_tar([("pkg/app", b"x"), ("pkg/app", b"y")]))
            with self.assertRaises(Failure):
                signing.extract_signed_binary(path, "app")

    def test_extract_rejects_missing_binary(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "empty.tar.gz"
            path.write_bytes(gz_tar([("pkg", None)]))
            with self.assertRaises(Failure):
                signing.extract_signed_binary(path, "app")

    def test_repackage_rejects_unsafe_binary_name(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "unsafe.tar.gz"
            with self.assertRaises(Failure):
                signing.repackage_signed(b"x", "../escape", destination)

    def test_repackage_rejects_oversized_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "big.tar.gz"
            with self.assertRaises(Failure):
                signing.repackage_signed(b"x" * (MAX_ARTIFACT + 1), "app", destination)

    def test_package_signing_input_wraps_pkg_layout(self):
        data = b"unsigned macho bytes"
        with tempfile.TemporaryDirectory() as temporary:
            payload = Path(temporary) / "payload"
            payload.write_bytes(data)
            destination = Path(temporary) / "input.tar.gz"
            recorded = signing.package_signing_input(payload, "app", destination)
            self.assertEqual(recorded, identity(data))
            with tarfile.open(destination, "r:gz") as archive:
                names = archive.getnames()
                self.assertIn("pkg", names)
                self.assertIn("pkg/app", names)
                self.assertEqual(archive.extractfile("pkg/app").read(), data)


class ApprovalGuardTests(unittest.TestCase):
    def call(self, data, digest, **overrides):
        kwargs = dict(run_id=17, run_attempt=2, repository="brianluby/armorer-test",
                      event_name="push", workflow_commit="a" * 40)
        kwargs.update(overrides)
        return signing.load_approval(data, digest, **kwargs)

    def test_digest_mismatch_is_rejected(self):
        data = b'{"schema_version": 1}'
        wrong = "0" * 64
        with self.assertRaises(Failure):
            self.call(data, wrong)

    def test_oversized_approval_is_rejected(self):
        with self.assertRaises(Failure):
            self.call(b"x" * (MAX_METADATA + 1), "0" * 64)

    def test_non_bytes_approval_is_rejected(self):
        with self.assertRaises(Failure):
            self.call("not bytes", "0" * 64)

    def test_empty_approval_is_rejected(self):
        with self.assertRaises(Failure):
            self.call(b"", "0" * 64)

    def test_malformed_digest_is_rejected(self):
        with self.assertRaises(Failure):
            self.call(b'{"schema_version": 1}', "not-a-digest")


class MatrixTests(unittest.TestCase):
    def test_matrix_names_come_from_approval_not_offered_bytes(self):
        permit = approval(keys=("app--aarch64-apple-darwin--minimal",))
        rows = signing.signing_matrix(permit)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["key"], "app--aarch64-apple-darwin--minimal")
        self.assertEqual(row["binary"], "app")
        self.assertEqual(row["archive_name"], "app--aarch64-apple-darwin--minimal.tar.gz")
        self.assertEqual(row["binary_path"], "pkg/app")
        self.assertEqual(row["team_id"], "DVH6X33J83")
        self.assertEqual(row["signing_identity"], permit.signing_identity)


class VerifyGuardTests(unittest.TestCase):
    """verify_signed_release must admit only the exact finalized bytes; substitutions fail closed."""

    def setup_release(self, temporary, *, tamper_archive=False, tamper_sbom=False):
        permit = approval()
        key = "app--aarch64-apple-darwin--minimal"
        signed_bytes = b"final signed executable"
        sbom_bytes = b'{"bomFormat": "CycloneDX"}'
        release = Path(temporary) / "release"
        release.mkdir()
        archive = release / (key + signing.SIGNED_RELEASE_SUFFIX + ".tar.gz")
        archive.write_bytes(gz_tar([("app", signed_bytes)]))
        (release / (key + ".cdx.json")).write_bytes(sbom_bytes)
        row = dict(signing.signing_matrix(permit)[0])
        row["final"] = identity(archive.read_bytes())
        row["signed_binary"] = identity(signed_bytes)
        row["sbom"] = identity(sbom_bytes)
        plan = {"schema_version": 1, "state": signing.SIGNING_PLAN_NAME,
                "signing_workflow_commit": permit.signing_workflow_commit,
                "run": {"id": permit.run.run_id, "attempt": permit.run.run_attempt},
                "rows": [row]}
        if tamper_archive:
            archive.write_bytes(gz_tar([("app", b"substituted unsigned bytes")]))
        if tamper_sbom:
            (release / (key + ".cdx.json")).write_bytes(b'{"bomFormat": "tampered"}')
        return permit, plan, release

    def test_exact_finalized_release_is_admitted(self):
        with tempfile.TemporaryDirectory() as temporary:
            permit, plan, release = self.setup_release(temporary)
            result = signing.verify_signed_release(approval=permit, plan=plan, release_directory=release)
            self.assertEqual(result["state"], "release-signing-verified")
            self.assertIn("app--aarch64-apple-darwin--minimal", result["subjects"])

    def test_substituted_archive_bytes_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            permit, plan, release = self.setup_release(temporary, tamper_archive=True)
            with self.assertRaises(Failure):
                signing.verify_signed_release(approval=permit, plan=plan, release_directory=release)

    def test_substituted_sbom_bytes_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            permit, plan, release = self.setup_release(temporary, tamper_sbom=True)
            with self.assertRaises(Failure):
                signing.verify_signed_release(approval=permit, plan=plan, release_directory=release)

    def test_foreign_run_plan_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            permit, plan, release = self.setup_release(temporary)
            plan["run"] = {"id": 999, "attempt": 2}
            with self.assertRaises(Failure):
                signing.verify_signed_release(approval=permit, plan=plan, release_directory=release)


if __name__ == "__main__":
    unittest.main()