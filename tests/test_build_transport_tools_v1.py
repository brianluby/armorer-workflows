"""Synthetic archives exercise installer boundaries; only hosted native reads qualify tokens."""
import copy
import hashlib
import io
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

from armorer_runtime import transport_tools_v1 as tools
from armorer_runtime import transport_v1
from armorer_runtime.common import Failure
from transport_cases_v1 import ExpectedRead, _run, qualify
from test_build_transport_v1 import timestamp


def archive(kind="tar.gz", mutation=None):
    """Construct tiny inert test-owned distributions without executable qualification claims."""
    binary = b"inert-test-native-leaf"
    leaf = "test-distribution/bin/gh"
    records = [(leaf, binary, "regular"), ("test-distribution/share/readme", b"test-owned", "regular")]
    if mutation:
        records = mutation(records)
    buffer = io.BytesIO()
    if kind == "tar.gz":
        with tarfile.open(fileobj=buffer, mode="w:gz") as package:
            for name, data, member_type in records:
                info = tarfile.TarInfo(name)
                info.type = tarfile.SYMTYPE if member_type == "link" else tarfile.REGTYPE
                info.size = len(data) if member_type != "link" else 0
                info.linkname = "/foreign"
                package.addfile(info, io.BytesIO(data))
    else:
        with zipfile.ZipFile(buffer, "w") as package:
            for name, data, member_type in records:
                info = zipfile.ZipInfo(name)
                info.external_attr = ((stat.S_IFLNK if member_type == "link" else stat.S_IFREG) | 0o600) << 16
                package.writestr(info, data)
    data = buffer.getvalue()
    distribution = {"format": kind, "name": "test-owned-distribution", "leaf": leaf,
                    "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    return data, distribution, binary


def provider():
    """Keep independent test intent distinct from synthetic offered run/artifact metadata."""
    expected = ExpectedRead("brianluby/armorer-workflows", 1398918288, "a" * 40, "feature", "pull_request", 17, 1)
    repository = {"id": expected.repository_id, "full_name": expected.repository, "fork": False}
    run = {"id": 17, "run_attempt": 1, "workflow_id": 371830961, "path": ".github/workflows/development.yml",
           "head_sha": expected.head_commit, "head_branch": expected.head_branch, "event": expected.event,
           "status": "in_progress", "conclusion": None, "repository": repository, "head_repository": repository,
           "run_started_at": timestamp(100)}
    data = b"inert-archive-test-bytes"
    artifacts = [{"id": index + 1, "name": f"policy-native-v1-{runner}-17-1", "expired": False,
                  "size_in_bytes": len(data), "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
                  "created_at": timestamp(110), "updated_at": timestamp(110), "expires_at": timestamp(1000),
                  "workflow_run": {"id": 17, "repository_id": expected.repository_id,
                                   "head_repository_id": expected.repository_id, "head_sha": expected.head_commit,
                                   "head_branch": expected.head_branch}}
                 for index, runner in enumerate(("ubuntu-24.04", "ubuntu-24.04-arm", "macos-15"))]
    artifacts.sort(key=lambda row: row["name"])
    return expected, run, {"total_count": 3, "artifacts": artifacts}, data


class NativeTransportToolTests(unittest.TestCase):
    def test_both_archive_formats_return_one_exact_inert_leaf(self):
        """Accept exact bounded tar/ZIP leaf bytes without executing any test or foreign binary."""
        for kind in ("tar.gz", "zip"):
            data, distribution, binary = archive(kind)
            self.assertEqual(tools._binary(data, distribution, len(binary)), binary)

    def test_whole_archive_size_and_hash_precede_both_decoders(self):
        """Wrong distribution bytes must not enter a tar or ZIP parser."""
        for kind in ("tar.gz", "zip"):
            data, distribution, binary = archive(kind)
            for field, value in (("size", len(data) + 1), ("sha256", "0" * 64)):
                changed = dict(distribution, **{field: value})
                with mock.patch.object(tools.tarfile, "open") as tar, mock.patch.object(tools.zipfile, "ZipFile") as zipped:
                    with self.assertRaises(Failure):
                        tools._binary(data, changed, len(binary))
                    tar.assert_not_called()
                    zipped.assert_not_called()

    def test_path_alias_link_duplicate_missing_and_wrong_size_reject(self):
        """Unsafe archive members cannot bypass exact selected executable identity."""
        changes = [lambda rows: [("../bin/gh", rows[0][1], "regular"), *rows[1:]],
                   lambda rows: [("test-distribution/bin/./gh", rows[0][1], "regular"), *rows[1:]],
                   lambda rows: [("test-distribution//bin/gh", rows[0][1], "regular"), *rows[1:]],
                   lambda rows: [("/test-distribution/bin/gh", rows[0][1], "regular"), *rows[1:]],
                   lambda rows: [(rows[0][0], rows[0][1], "link"), *rows[1:]],
                   lambda rows: [*rows, rows[0]], lambda rows: rows[1:],
                   lambda rows: [(rows[0][0], rows[0][1] + b"replacement", "regular"), *rows[1:]]]
        for kind in ("tar.gz", "zip"):
            for change in changes:
                data, distribution, binary = archive(kind, change)
                with self.assertRaises(Failure):
                    tools._binary(data, distribution, len(binary))
            data, distribution, binary = archive(kind)
            for limit in ("MAX_MEMBERS", "MAX_EXPANDED", "MAX_ARCHIVE"):
                with mock.patch.object(tools, limit, 1), self.assertRaises(Failure):
                    tools._binary(data, distribution, len(binary))

    def test_installer_hashes_before_executable_mode_and_preserves_existing_paths(self):
        """Only a new private destination receives exact native bytes; unrelated files remain untouched."""
        data, distribution, binary = archive()
        target = "aarch64-apple-darwin"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            existing = root / "existing"; existing.mkdir(); (existing / "custom").write_bytes(b"preserved")
            alias = root / "alias"; alias.symlink_to(existing, target_is_directory=True)
            with mock.patch.object(tools, "platform_target", return_value=target), \
                 mock.patch.object(tools, "DISTRIBUTIONS", {target: distribution}), \
                 mock.patch.object(tools, "GH_PINS", {target: (len(binary), hashlib.sha256(binary).hexdigest())}), \
                 mock.patch.object(tools, "_download", return_value=data) as download:
                for destination in (existing, alias):
                    with self.assertRaises(Failure):
                        tools.install_gh(destination)
                download.assert_not_called()
                output, receipt = tools.install_gh(root / "native")
                self.assertEqual(output.read_bytes(), binary)
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o500)
                self.assertEqual(stat.S_IMODE(output.parent.stat().st_mode), 0o700)
                self.assertFalse(receipt["production_catalog_accepted"])
                self.assertFalse(receipt["upstream_signature_authenticated"])
                with mock.patch.object(tools, "GH_PINS", {target: (len(binary), "0" * 64)}), self.assertRaises(Failure):
                    tools.install_gh(root / "rejected")
                self.assertFalse((root / "rejected/gh").exists())
            self.assertEqual((existing / "custom").read_bytes(), b"preserved")

    def test_unsupported_platform_and_invalid_tokens_cannot_start_native_reads(self):
        """Unsupported hosts and invalid token shapes fail before download or process creation."""
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(tools, "platform_target", return_value="unqualified-host"), \
             mock.patch.object(tools, "_download") as download:
            with self.assertRaises(Failure):
                tools.install_gh(Path(temporary) / "native")
            download.assert_not_called()
        for value in (None, "", "has space", "has\nline", "a" * 4097):
            with mock.patch.object(transport_v1.subprocess, "Popen") as launch, self.assertRaises(Failure):
                transport_v1.QualifiedGhApi(Path("/unqualified-gh"), value)
            launch.assert_not_called()

    def test_qualification_snapshot_rechecks_exact_bytes_and_has_no_release_authority(self):
        """Synthetic positive tests yield only an unsigned native adapter checkpoint, never authentication of payloads."""
        expected, run, listing, data = provider()
        api = transport_v1.QualifiedGhApi(Path("/test-owned-gh"), "test-only-token")
        responses = [run, run, listing, *listing["artifacts"], run, run, listing]
        paths = []
        def download(repo, ident, path):
            """Write inert test archive bytes and record cleanup for the synthetic adapter boundary."""
            paths.append(path)
            path.write_bytes(data)
        with mock.patch.object(api, "json", side_effect=responses), mock.patch.object(api, "archive", side_effect=download), \
             mock.patch("transport_cases_v1.time.time", return_value=120):
            receipt = qualify(api, expected, {"test_only": True})
        self.assertEqual(len(receipt["artifacts"]), 3)
        self.assertEqual(receipt["authentication_mode"], "isolated-workflow-token")
        self.assertTrue(all(not path.exists() for path in paths))
        for field in ("signing_authorized", "producer_job_authenticated", "cryptographic_release_authenticated",
                      "payload_decoded", "artifact_executed", "policy_snapshot_authenticated", "production_catalog_accepted"):
            self.assertIs(receipt[field], False)

    def test_qualification_wrong_source_run_caller_fork_and_expiry_prevent_download(self):
        """Provider substitutions fail before payload reads under independently supplied job context."""
        changes = [lambda row: row.update(id=18), lambda row: row.update(run_attempt=True),
                   lambda row: row.update(workflow_id=1), lambda row: row.update(head_sha="b" * 40),
                   lambda row: row.update(event="pull_request_target"), lambda row: row.update(path=".github/workflows/foreign.yml"),
                   lambda row: row["head_repository"].update(fork=True), lambda row: row.update(conclusion="failure"),
                   lambda row: row.update(run_started_at=timestamp(121))]
        for change in changes:
            expected, run, _, _ = provider()
            change(run)
            api = transport_v1.QualifiedGhApi(Path("/test-owned-gh"), "test-only-token")
            with mock.patch.object(api, "json", return_value=run), mock.patch.object(api, "archive") as download, \
                 mock.patch("transport_cases_v1.time.time", return_value=120), self.assertRaises(Failure):
                qualify(api, expected, {})
            download.assert_not_called()

    def test_qualification_hash_detail_and_final_rerun_races_reject(self):
        """Authentic storage metadata alone cannot excuse changed archives, records or provider attempts."""
        for case in ("archive", "detail", "rerun", "listing", "expired"):
            expected, run, listing, data = provider()
            details = copy.deepcopy(listing["artifacts"])
            final_run, final_listing = copy.deepcopy(run), copy.deepcopy(listing)
            if case == "detail": details[0]["digest"] = "sha256:" + "0" * 64
            if case == "rerun": final_run["run_attempt"] = 2
            if case == "listing": final_listing["artifacts"][0]["id"] = 999
            if case == "expired": final_listing["artifacts"][0]["expires_at"] = timestamp(120)
            incoming = data + b"replacement" if case == "archive" else data
            api = transport_v1.QualifiedGhApi(Path("/test-owned-gh"), "test-only-token")
            with mock.patch.object(api, "json", side_effect=[run, run, listing, *details, final_run, run, final_listing]), \
                 mock.patch.object(api, "archive", side_effect=lambda repo, ident, path: path.write_bytes(incoming)), \
                 mock.patch("transport_cases_v1.time.time", return_value=120), self.assertRaisesRegex(Failure, {
                     "archive": "archive bytes mismatch", "detail": "artifact detail changed",
                     "rerun": "provider run mismatch", "listing": "provider state changed",
                     "expired": "outside the exact attempt upload window"}[case]):
                qualify(api, expected, {})
