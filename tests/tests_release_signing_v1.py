"""Adversarial release-signing handoff tests; inert synthetic bytes, no live signing/OIDC/network.

These exercise the credential-free pure functions and the early approval guards. The full
finalize -> verify chain is covered with only the platform-measurement boundary mocked, so no
codesign/notarytool, credential, OIDC or network access occurs.
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
from unittest import mock

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


class FinalizeChainTests(unittest.TestCase):
    """Exercise finalize -> verify end to end; only Apple platform measurement is mocked.

    Regression scope: the pre-staged evidence directory, the consumer-canonical single-leaf
    release archive, and the <key>.apple.json transformation-evidence name.
    """

    KEY = "app--aarch64-apple-darwin--minimal"

    def permit(self):
        selection = {"id": "app", "profile": "cli", "package": "app", "binary": "app",
                     "target": "aarch64-apple-darwin", "targets": ["aarch64-apple-darwin"],
                     "feature_set": "minimal", "default_features": False, "features": [],
                     "runner": "macos-15", "artifact_id": self.KEY, "toolchain": "1.95.0"}
        item = signing.PayloadExpectation(selection=selection, context={}, input_sha256={},
                                          root_component_name="app", package_version="0.1.0",
                                          tool_sha256={})
        run = SimpleNamespace(run_id=17, run_attempt=2, runtime_commit="b" * 40)
        inputs = {"source": {"repository": "brianluby/armorer-test", "commit": "a" * 40,
                             "git_ref": "refs/tags/v0.1.0"},
                  "config_sha256": "1" * 64, "lock_sha256": "2" * 64, "cargo_lock_sha256": "3" * 64,
                  "runtime": {"sha256": "4" * 64, "size": 100}, "runtime_version": "0.1.0",
                  "run": {"id": 17, "attempt": 2}}
        catalog = {"catalog": {"sha256": "5" * 64, "size": 10},
                   "identity": {"sha256": "6" * 64, "size": 20}}
        return signing.SigningApproval(
            run=run, items=(item,), apple_items=(item,), inputs=inputs, catalog=catalog,
            build_inputs=(), team_id="DVH6X33J83",
            signing_identity="Developer ID Application: Test (DVH6X33J83)",
            signing_workflow_commit="a" * 40, max_age_seconds=3600)

    def stage(self, root, permit, signed_bytes):
        """Reproduce exactly what the gated credential step leaves behind before finalize."""
        work = root / "work"
        work.mkdir()
        signed = root / "signed"
        signed.mkdir()
        unsigned_bytes = b"unsigned macho bytes"
        sbom_bytes = b'{"bomFormat": "CycloneDX"}'
        staged = work / (self.KEY + ".tar.gz")
        staged.write_bytes(gz_tar([("pkg", None), ("pkg/app", unsigned_bytes)]))
        (signed / (self.KEY + ".tar.gz")).write_bytes(gz_tar([("pkg", None), ("pkg/app", signed_bytes)]))
        # The gated step pre-creates work/<key>/ to hold Apple's acceptance records.
        staging = work / self.KEY
        staging.mkdir(mode=0o700)
        acceptance = {"id": "submission-1", "status": "Accepted", "createdDate": "2020-01-01T00:00:00.000Z"}
        (staging / "submission.json").write_bytes(json.dumps(acceptance).encode())
        (staging / "notarization.json").write_bytes(json.dumps(
            {"jobId": "submission-1", "status": "Accepted", "uploadDate": "2020-01-01T00:01:00.000Z"}).encode())
        row = dict(signing.signing_matrix(permit)[0])
        row.update(unsigned=identity(unsigned_bytes), archive=identity(staged.read_bytes()),
                   sbom=identity(sbom_bytes),
                   observed_build={"started_at": 1577836800, "finished_at": 1577836800})
        plan = {"schema_version": 1, "state": signing.SIGNING_PLAN_NAME,
                "signing_workflow_commit": permit.signing_workflow_commit,
                "run": {"id": 17, "attempt": 2}, "rows": [row]}
        return work, signed, plan, sbom_bytes

    def finalize(self, work, signed, plan, permit):
        certificate = {"sha256": "7" * 64, "size": 32}
        tool = {"name": "codesign", "kind": "tool", "version": "hosted-image",
                "bytes": certificate, "authentication_record": certificate,
                "observed_at": 1577836800, "max_age_seconds": None}
        with mock.patch.object(signing, "signing_platform_evidence",
                               return_value={"certificate_sha256": "7" * 64, "certificate": certificate}), \
             mock.patch.object(signing, "_tool_observation", return_value=tool):
            return signing.finalize_signing(approval=permit, plan=plan, work=work,
                                            signed_directory=signed, runner_image="macos-15-test")

    def test_finalize_emits_apple_evidence_and_the_release_verifies(self):
        permit = self.permit()
        signed_bytes = b"final signed macho bytes"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work, signed, plan, sbom_bytes = self.stage(root, permit, signed_bytes)
            result = self.finalize(work, signed, plan, permit)
            # Apple transformation evidence uses the consumer's .apple.json role, never .build.json.
            self.assertTrue((work / (self.KEY + ".apple.json")).is_file())
            self.assertFalse((work / (self.KEY + ".build.json")).exists())
            evidence = json.loads((work / (self.KEY + ".apple.json")).read_bytes())
            self.assertIsNotNone(evidence["apple_assertions"])
            # Assemble the release set exactly as the workflow does, then verify it.
            release = root / "release"
            release.mkdir()
            archive = result["results"][self.KEY]["release_archive"]
            (release / archive).write_bytes((work / archive).read_bytes())
            (release / (self.KEY + ".cdx.json")).write_bytes(sbom_bytes)
            plan["rows"][0].update(final=result["results"][self.KEY]["final"],
                                   signed_binary=result["results"][self.KEY]["signed_binary"])
            verified = signing.verify_signed_release(approval=permit, plan=plan, release_directory=release)
            self.assertEqual(verified["state"], "release-signing-verified")
            self.assertEqual(verified["subjects"][self.KEY]["final"], result["results"][self.KEY]["final"])

    def test_finalize_rejects_unchanged_bytes_after_signing(self):
        permit = self.permit()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            # Identical unsigned and "signed" bytes must fail: signing has to change the executable.
            work, signed, plan, _ = self.stage(root, permit, b"unsigned macho bytes")
            with self.assertRaises(Failure):
                self.finalize(work, signed, plan, permit)


if __name__ == "__main__":
    unittest.main()