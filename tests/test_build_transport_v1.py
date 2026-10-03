"""Transport adversaries use inert payloads; mocked API records are never live qualification."""
import copy
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import io
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest
from unittest import mock
import zipfile

from armorer_runtime import transport_v1 as transport
from armorer_runtime.common import Failure
from test_build_graph_v2 import expectation


def timestamp(value):
    """Render exact test-owned UTC provider observations."""
    return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def zipped(selection, mutate=None):
    """Create a bounded five-leaf provider ZIP whose nested executable payload remains inert."""
    output = io.BytesIO()
    records = [(name, b"#!/bin/sh\ntouch executed\n" if name.endswith(".bin") else b"{}")
               for name in transport._names(selection)]
    if mutate:
        records = mutate(records)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in records:
            info = zipfile.ZipInfo(name)
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            archive.writestr(info, data)
    return output.getvalue()


def fixture():
    """Keep controller expectations separate from mock provider metadata and arbitrary payload claims."""
    selected, _ = expectation("optional")
    expected = transport.ExpectedRun("example/source", 7, "a" * 40, "b" * 40, "feature", "pull_request",
                                     ".github/workflows/release.yml", 9, 17, 2, "c" * 40)
    repository = {"id": 7, "full_name": "example/source", "fork": False}
    run = {"id": 17, "run_attempt": 2, "workflow_id": 9, "head_sha": expected.head_commit,
           "head_branch": "feature", "event": "pull_request", "path": expected.caller_path,
           "repository": repository, "head_repository": copy.deepcopy(repository),
           "status": "completed", "conclusion": "success", "run_started_at": timestamp(100),
           "referenced_workflows": [{"path": "brianluby/armorer-workflows/" + expected.builder_path + "@" + expected.runtime_commit,
                                     "sha": expected.runtime_commit}]}
    archive = zipped(selected)
    artifact = {"id": 27, "name": selected["artifact_id"] + "-handoff-v3-run-17-attempt-2", "expired": False,
                "size_in_bytes": len(archive), "digest": "sha256:" + hashlib.sha256(archive).hexdigest(),
                "workflow_run": {"id": 17, "repository_id": 7, "head_repository_id": 7,
                                 "head_sha": expected.head_commit, "head_branch": "feature"},
                "created_at": timestamp(110), "updated_at": timestamp(110), "expires_at": timestamp(1000)}
    return expected, selected, run, {"total_count": 1, "artifacts": [artifact]}, archive


class ProviderTransportTests(unittest.TestCase):
    """Reject ambiguous provider transport responses and cross-run artifact substitutions."""
    def test_exact_provider_snapshot_is_private_inert_and_has_no_signing_authority(self):
        """Accept exact transport metadata while retaining explicit absence of release/producer/signing proofs."""
        expected, selected, run, listing, archive = fixture()
        api = transport.QualifiedGhApi.operator_qualification(Path("/test-owned/pinned-gh"))
        responses = [run, run, listing, run, run, listing]
        with mock.patch.object(api, "json", side_effect=responses), \
             mock.patch.object(api, "archive", side_effect=lambda repo, ident, path: path.write_bytes(archive)), \
             mock.patch.object(transport.time, "time", return_value=120):
            with transport.collect_handoffs(api, expected, [selected]) as (directories, receipt):
                root = directories[selected["artifact_id"]]
                self.assertEqual({path.name for path in root.iterdir()}, set(transport._names(selected)))
                self.assertFalse((root / "executed").exists())
                self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o400 for path in root.iterdir()))
                for key in ("signing_authorized", "producer_job_authenticated", "cryptographic_release_authenticated"):
                    self.assertIs(receipt[key], False)
                self.assertEqual(receipt["source_commit"], expected.source_commit)
                with self.assertRaises(TypeError):
                    directories["other"] = root
            self.assertFalse(root.exists())

    def test_wrong_run_source_repository_attempt_trigger_workflow_and_freshness_prevent_download(self):
        """Reject control-plane substitutions before any archive fetch, consumer execution or credential use."""
        changes = [lambda r: r.update(id=18), lambda r: r.update(id=True), lambda r: r.update(run_attempt=1),
                   lambda r: r.update(workflow_id=10), lambda r: r.update(head_sha="d" * 40),
                   lambda r: r.update(head_branch="main"), lambda r: r.update(event="pull_request_target"),
                   lambda r: r.update(path=".github/workflows/other.yml"),
                   lambda r: r["repository"].update(id=8), lambda r: r["head_repository"].update(fork=True),
                   lambda r: r["head_repository"].update(full_name="attacker/source"),
                   lambda r: r.update(status="queued", conclusion=None), lambda r: r.update(conclusion="failure"),
                   lambda r: r.update(run_started_at=timestamp(121)), lambda r: r.update(run_started_at=False),
                   lambda r: r["referenced_workflows"][0].update(sha="d" * 40),
                   lambda r: r.update(referenced_workflows=[]),
                   lambda r: r["referenced_workflows"].append(copy.deepcopy(r["referenced_workflows"][0]))]
        for change in changes:
            expected, selected, run, listing, _ = fixture()
            change(run)
            api = transport.QualifiedGhApi.operator_qualification(Path("/test-owned/pinned-gh"))
            with mock.patch.object(api, "json", return_value=run), mock.patch.object(api, "archive") as download, \
                 mock.patch.object(transport.time, "time", return_value=120):
                with self.assertRaises(Failure):
                    with transport.collect_handoffs(api, expected, [selected]):
                        self.fail("rejected run yielded a snapshot")
                download.assert_not_called()

    def test_missing_extra_duplicate_foreign_old_attempt_and_expired_artifact_prevent_download(self):
        """Require exact complete provider object IDs, names, byte identities, source and attempt timestamps."""
        changes = [lambda l: l.update(total_count=2), lambda l: l.update(total_count=True),
                   lambda l: l.update(artifacts=[]), lambda l: l["artifacts"].append(copy.deepcopy(l["artifacts"][0])),
                   lambda l: l["artifacts"][0].update(name="foreign"), lambda l: l["artifacts"][0].update(expired=True),
                   lambda l: l["artifacts"][0].update(id=True), lambda l: l["artifacts"][0].update(size_in_bytes=True),
                   lambda l: l["artifacts"][0].update(size_in_bytes=transport.MAX_ZIP + 1),
                   lambda l: l["artifacts"][0].update(digest=None),
                   lambda l: l["artifacts"][0]["workflow_run"].update(id=18),
                   lambda l: l["artifacts"][0]["workflow_run"].update(head_repository_id=8),
                   lambda l: l["artifacts"][0]["workflow_run"].update(head_sha="d" * 40),
                   lambda l: l["artifacts"][0].update(created_at=timestamp(99)),
                   lambda l: l["artifacts"][0].update(updated_at=timestamp(121)),
                   lambda l: l["artifacts"][0].update(expires_at=timestamp(120))]
        for change in changes:
            expected, selected, run, listing, _ = fixture()
            change(listing)
            api = transport.QualifiedGhApi.operator_qualification(Path("/test-owned/pinned-gh"))
            with mock.patch.object(api, "json", side_effect=[run, run, listing]), \
                 mock.patch.object(api, "archive") as download, mock.patch.object(transport.time, "time", return_value=120):
                with self.assertRaises(Failure):
                    with transport.collect_handoffs(api, expected, [selected]):
                        self.fail("rejected artifact yielded a snapshot")
                download.assert_not_called()

    def test_archive_tampering_and_unsafe_zip_never_yield_a_snapshot(self):
        """Reject digest mismatches before decoding and reject extra/nested/duplicate/injected ZIP members."""
        mutations = [lambda records: records + [("extra.bin", b"extra")],
                     lambda records: records[:-1], lambda records: records[:-1] + [records[0]],
                     lambda records: [("../" + records[0][0], records[0][1])] + records[1:]]
        for mutate in mutations:
            expected, selected, run, listing, _ = fixture()
            archive = zipped(selected, mutate)
            listing["artifacts"][0].update(size_in_bytes=len(archive), digest="sha256:" + hashlib.sha256(archive).hexdigest())
            self._reject(expected, selected, run, listing, archive)
        expected, selected, run, listing, archive = fixture()
        self._reject(expected, selected, run, listing, archive + b"tampered")
        listing["artifacts"][0].update(size_in_bytes=len(archive) + 1)
        self._reject(expected, selected, run, listing, archive)

    def _reject(self, expected, selected, run, listing, archive, *, final_run=None, final_listing=None):
        """Run and assert a full collector rejection under mock provider reads, without claiming live evidence."""
        api = transport.QualifiedGhApi.operator_qualification(Path("/test-owned/pinned-gh"))
        with mock.patch.object(api, "json", side_effect=[run, run, listing, final_run or run, run, final_listing or listing]), \
             mock.patch.object(api, "archive", side_effect=lambda repo, ident, path: path.write_bytes(archive)), \
             mock.patch.object(transport.time, "time", return_value=120):
            with self.assertRaises(Failure):
                with transport.collect_handoffs(api, expected, [selected]):
                    self.fail("rejected transport yielded a snapshot")

    def test_rerun_replacement_extra_assets_and_expiry_during_download_reject(self):
        """Recheck current attempt and complete storage identity after downloads to reject races."""
        expected, selected, run, listing, archive = fixture()
        changed_run = copy.deepcopy(run); changed_run["run_attempt"] = 3
        self._reject(expected, selected, run, listing, archive, final_run=changed_run)
        for mutate in (lambda l: l["artifacts"][0].update(id=28),
                       lambda l: l["artifacts"][0].update(digest="sha256:" + "0" * 64),
                       lambda l: l.update(total_count=2)):
            changed = copy.deepcopy(listing); mutate(changed)
            self._reject(expected, selected, run, listing, archive, final_listing=changed)
        api = transport.QualifiedGhApi.operator_qualification(Path("/test-owned/pinned-gh"))
        with mock.patch.object(api, "json", side_effect=[run, run, listing, run, run, listing]), \
             mock.patch.object(api, "archive", side_effect=lambda repo, ident, path: path.write_bytes(archive)), \
             mock.patch.object(transport.time, "time", side_effect=[120, 4000]):
            with self.assertRaises(Failure):
                with transport.collect_handoffs(api, expected, [selected]):
                    self.fail("expired snapshot yielded")

    def test_special_zip_modes_compression_crc_and_trailing_directory_reject(self):
        """Reject unsafe member metadata and corrupt/trailing transport even with matching provider digests."""
        for variant in ("symlink", "directory-attribute", "bzip2", "encrypted", "crc", "trailing"):
            expected, selected, run, listing, original = fixture()
            buffer = io.BytesIO()
            with zipfile.ZipFile(io.BytesIO(original)) as source, zipfile.ZipFile(buffer, "w") as archive:
                for index, info in enumerate(source.infolist()):
                    data = source.read(info)
                    if index == 0:
                        if variant == "symlink":
                            info.external_attr = (stat.S_IFLNK | 0o777) << 16
                        elif variant == "directory-attribute":
                            info.external_attr |= 0x10
                        elif variant == "bzip2":
                            info.compress_type = zipfile.ZIP_BZIP2
                    archive.writestr(info, data)
            data = bytearray(buffer.getvalue())
            if variant in ("encrypted", "crc"):
                central = data.index(b"PK\x01\x02")
                if variant == "encrypted":
                    data[central + 8] |= 1
                else:
                    data[central + 16] ^= 0x80
            if variant == "trailing":
                data.extend(b"unapproved trailing bytes")
            archive = bytes(data)
            listing["artifacts"][0].update(size_in_bytes=len(archive), digest="sha256:" + hashlib.sha256(archive).hexdigest())
            self._reject(expected, selected, run, listing, archive)

    def test_unqualified_adapters_invalid_intent_duplicate_selections_and_release_source_mix_reject(self):
        """No arbitrary JSON client, moving pin or malformed independent intent reaches provider reads."""
        expected, selected, _, _, _ = fixture()
        with self.assertRaises(Failure):
            with transport.collect_handoffs(mock.Mock(), expected, [selected]):
                self.fail("unqualified adapter yielded")
        api = transport.QualifiedGhApi.operator_qualification(Path("/test-owned/pinned-gh"))
        invalid = [replace(expected, repository="../source"), replace(expected, run_id=True),
                   replace(expected, runtime_commit="main"), replace(expected, event="workflow_run"),
                   replace(expected, event="push"), replace(expected, max_age_seconds=True),
                   replace(expected, builder_path=".github/workflows/attacker.yml")]
        with mock.patch.object(api, "json") as read:
            for context in invalid:
                with self.assertRaises(Failure):
                    with transport.collect_handoffs(api, context, [selected]):
                        self.fail("invalid intent yielded")
            with self.assertRaises(Failure):
                with transport.collect_handoffs(api, expected, [selected, selected]):
                    self.fail("duplicate selections yielded")
            read.assert_not_called()

    def test_native_digest_and_unsafe_endpoints_fail_before_process_start(self):
        """A native tool byte mismatch or option/path injection cannot start an executable."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake = root / "fake-gh"; fake.write_text("#!/bin/sh\ntouch executed\n"); fake.chmod(0o700)
            api = transport.QualifiedGhApi(fake, "test-only-token")
            for endpoint in ("https://attacker.invalid", "repos/a/b/actions/runs/1;injected", "repos/a/b/releases",
                             "repos/a/b/actions/runs/1", "repos/a/b/actions/runs/1?per_page=100&injected=true"):
                with mock.patch.object(transport.subprocess, "Popen") as launch:
                    with self.assertRaises(Failure):
                        api._read(endpoint, root / "output", 100)
                    launch.assert_not_called()
            self.assertFalse((root / "executed").exists())

    def test_real_fixed_process_output_bounds_and_sterile_token_environment(self):
        """Use an owned native test process to enforce real stream limits and exclude ambient credentials/debug."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            program = root / "test-gh"
            program.write_text("#!/bin/sh\n[ -z \"$GH_DEBUG$GITHUB_TOKEN$HTTP_PROXY\" ] || exit 1\n"
                               "[ \"$GH_TOKEN\" = test-only-token ] || exit 1\nprintf '123456789'\n")
            program.chmod(0o700)
            api = transport.QualifiedGhApi(program, "test-only-token")
            with mock.patch.object(api, "_check_native"), \
                 mock.patch.dict(os.environ, {"GH_DEBUG": "api", "GITHUB_TOKEN": "ambient-test", "HTTP_PROXY": "bad"}):
                with self.assertRaises(Failure):
                    api._read("repos/a/b/actions/runs/1", root / "too-large", 5)
                api._read("repos/a/b/actions/runs/1", root / "good", 9)
            self.assertEqual((root / "good").read_bytes(), b"123456789")
            self.assertEqual((root / "too-large").read_bytes(), b"")

    def test_real_native_read_deadline_terminates_an_owned_stalled_process(self):
        """Enforce the actual monotonic read deadline without mocked subprocesses or consumed payloads."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            program = root / "test-stalled-gh"; program.write_text("#!/bin/sh\nsleep 5\n"); program.chmod(0o700)
            api = transport.QualifiedGhApi(program, "test-only-token")
            api._deadline = time.monotonic() + 0.1
            start = time.monotonic()
            with mock.patch.object(api, "_check_native"):
                with self.assertRaises(Failure):
                    api._read("repos/a/b/actions/runs/1", root / "output", 100)
            self.assertLess(time.monotonic() - start, 2)


if __name__ == "__main__":
    unittest.main()
