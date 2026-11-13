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
from transport_cases_v1 import ExpectedRead, _run, _state, qualify
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


def routed(expected, run, listing, *, attempt=None, producer_run=None, extra=()):
    """Answer by exact provider route so tests bind behaviour to endpoints, not call order."""
    route = f"repos/{expected.repository}/actions/runs/{expected.run_id}"
    current = attempt if attempt is not None else expected.run_attempt
    table = {route: run, route + f"/attempts/{current}": run,
             route + "/artifacts?per_page=100": listing}
    if producer_run is not None:
        table[route + f"/attempts/{producer_run['run_attempt']}"] = producer_run
    for row in list(listing["artifacts"]) + list(extra):
        table[f"repos/{expected.repository}/actions/artifacts/{row['id']}"] = row
    return lambda endpoint: copy.deepcopy(table[endpoint])


def rerun_provider(*, full=False):
    """Reproduce a real rerun: attempt 2 is current, attempt 1 produced the retained artifacts.

    Provider facts mirrored from run 43318660476: attempt 1 started at 100 and uploaded at 110,
    attempt 2 started later at 200. A partial rerun keeps only attempt 1's set; a full rerun
    keeps both complete sets.
    """
    expected, run, listing, data = provider()
    first = copy.deepcopy(run)
    first.update(run_attempt=1, run_started_at=timestamp(100))
    second = copy.deepcopy(run)
    second.update(run_attempt=2, run_started_at=timestamp(200))
    older = copy.deepcopy(listing["artifacts"])
    rows = list(older)
    if full:
        newer = copy.deepcopy(older)
        for index, row in enumerate(newer):
            row["id"] += 100
            row["name"] = row["name"].rsplit("-", 1)[0] + "-2"
            row["created_at"] = row["updated_at"] = timestamp(210)
        rows += newer
    combined = {"total_count": len(rows), "artifacts": rows}
    current = ExpectedRead(expected.repository, expected.repository_id, expected.head_commit,
                           expected.head_branch, expected.event, expected.run_id, 2)
    return current, second, combined, data, first


class NativeTransportToolTests(unittest.TestCase):
    """Authenticate fixed native transport distributions and reject path or byte substitutions."""
    def test_unrecognized_provider_values_are_excluded_from_state_diagnostics(self):
        """State diagnostics must not print arbitrary provider bodies or purported credential values."""
        self.assertEqual(_state({"status": "test-only-sensitive-value", "conclusion": {"secret": "test-only-value"}}),
                         ("unsupported", "unsupported"))
        self.assertEqual(_state({"status": "in_progress", "conclusion": None}), ("in_progress", "none"))

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
        answer = routed(expected, run, listing)
        paths = []
        def download(repo, ident, path):
            """Write inert test archive bytes and record cleanup for the synthetic adapter boundary."""
            paths.append(path)
            path.write_bytes(data)
        with mock.patch.object(api, "json", side_effect=answer), mock.patch.object(api, "archive", side_effect=download), \
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

    def test_matching_pending_metadata_waits_for_active_state_before_archive_reads(self):
        """Queued provider propagation may wait, but exact active metadata precedes all archive downloads."""
        expected, run, listing, data = provider()
        pending = copy.deepcopy(run); pending.update(status="queued", run_started_at=None)
        api = transport_v1.QualifiedGhApi(Path("/test-owned-gh"), "test-only-token")
        answer = routed(expected, run, listing)
        calls = {"n": 0}

        def staged(endpoint):
            calls["n"] += 1
            return copy.deepcopy(pending) if calls["n"] == 1 else answer(endpoint)

        with mock.patch.object(api, "json", side_effect=staged), \
             mock.patch.object(api, "archive", side_effect=lambda repo, ident, path: path.write_bytes(data)) as download, \
             mock.patch("transport_cases_v1.time.time", return_value=120), mock.patch("transport_cases_v1.time.sleep") as sleep:
            receipt = qualify(api, expected, {})
        self.assertEqual(download.call_count, 3)
        self.assertEqual(sleep.call_count, 1)
        self.assertEqual(receipt["artifact_run_attempt"], 1)
        self.assertFalse(receipt["signing_authorized"])

    def test_partial_rerun_qualifies_the_producing_attempt_set(self):
        """A partial rerun keeps attempt 1's artifacts; they must still qualify against attempt 1's window."""
        current, run, listing, data, first = rerun_provider()
        api = transport_v1.QualifiedGhApi(Path("/test-owned-gh"), "test-only-token")
        with mock.patch.object(api, "json", side_effect=routed(current, run, listing, producer_run=first)), \
             mock.patch.object(api, "archive", side_effect=lambda repo, ident, path: path.write_bytes(data)) as download, \
             mock.patch("transport_cases_v1.time.time", return_value=220), mock.patch("transport_cases_v1.time.sleep"):
            receipt = qualify(api, current, {})
        self.assertEqual(download.call_count, 3)
        self.assertEqual(receipt["run_attempt"], 2)
        self.assertEqual(receipt["artifact_run_attempt"], 1)
        self.assertTrue(all(name.endswith("-17-1") for name in receipt["artifacts"]))

    def test_full_rerun_selects_the_newest_complete_attempt_set(self):
        """Two complete sets are retained after a full rerun; only the newest attempt is qualified."""
        current, run, listing, data, first = rerun_provider(full=True)
        api = transport_v1.QualifiedGhApi(Path("/test-owned-gh"), "test-only-token")
        with mock.patch.object(api, "json", side_effect=routed(current, run, listing, producer_run=first)), \
             mock.patch.object(api, "archive", side_effect=lambda repo, ident, path: path.write_bytes(data)) as download, \
             mock.patch("transport_cases_v1.time.time", return_value=220), mock.patch("transport_cases_v1.time.sleep"):
            receipt = qualify(api, current, {})
        self.assertEqual(download.call_count, 3)
        self.assertEqual(receipt["artifact_run_attempt"], 2)
        self.assertTrue(all(name.endswith("-17-2") for name in receipt["artifacts"]))

    def test_incomplete_or_future_attempt_sets_are_rejected(self):
        """A partial set, or an attempt beyond the current one, cannot become a qualification subject."""
        for case in ("incomplete", "future"):
            current, run, listing, data, first = rerun_provider()
            if case == "incomplete":
                listing["artifacts"] = listing["artifacts"][:2]
                listing["total_count"] = 2
            else:
                for row in listing["artifacts"]:
                    row["name"] = row["name"].rsplit("-", 1)[0] + "-3"
            api = transport_v1.QualifiedGhApi(Path("/test-owned-gh"), "test-only-token")
            with mock.patch.object(api, "json", side_effect=routed(current, run, listing, producer_run=first)), \
                 mock.patch.object(api, "archive") as download, \
                 mock.patch("transport_cases_v1.time.time", return_value=220), mock.patch("transport_cases_v1.time.sleep"):
                with self.assertRaises(Failure):
                    qualify(api, current, {})
            download.assert_not_called()

    def test_duplicate_runner_artifact_in_one_attempt_is_rejected(self):
        """Two artifacts for one runner in one attempt are ambiguous and must fail closed."""
        current, run, listing, data, first = rerun_provider()
        duplicate = copy.deepcopy(listing["artifacts"][0]); duplicate["id"] += 500
        listing["artifacts"].append(duplicate)
        listing["total_count"] = len(listing["artifacts"])
        api = transport_v1.QualifiedGhApi(Path("/test-owned-gh"), "test-only-token")
        with mock.patch.object(api, "json", side_effect=routed(current, run, listing, producer_run=first)), \
             mock.patch.object(api, "archive") as download, \
             mock.patch("transport_cases_v1.time.time", return_value=220), mock.patch("transport_cases_v1.time.sleep"):
            with self.assertRaises(Failure):
                qualify(api, current, {})
        download.assert_not_called()

    def test_pending_deadline_and_foreign_pending_identity_prevent_download(self):
        """Persistent queued metadata or a foreign identity cannot become an accepted checkpoint."""
        for case in ("expired", "foreign"):
            expected, run, listing, _ = provider()
            run.update(status="queued", run_started_at=None)
            if case == "foreign":
                run["head_repository"] = copy.deepcopy(run["head_repository"])
                run["head_repository"]["id"] += 1
            api = transport_v1.QualifiedGhApi(Path("/test-owned-gh"), "test-only-token")
            # The stage deadline is fixed at construction; drive it directly rather than the clock.
            api._deadline = 0 if case == "expired" else 10_000
            with mock.patch.object(api, "json", side_effect=routed(expected, run, listing)), \
                 mock.patch.object(api, "archive") as download, \
                 mock.patch("transport_cases_v1.time.monotonic", return_value=1), \
                 mock.patch("transport_cases_v1.time.time", return_value=120), \
                 mock.patch("transport_cases_v1.time.sleep") as sleep, \
                 self.assertRaisesRegex(Failure, "readiness deadline expired" if case == "expired"
                                        else "provider repository mismatch"):
                qualify(api, expected, {})
            download.assert_not_called()
            if case == "foreign":
                sleep.assert_not_called()

    def test_qualification_hash_detail_and_final_rerun_races_reject(self):
        """Authentic storage metadata alone cannot excuse changed archives, records or provider attempts."""
        for case in ("archive", "detail", "rerun", "listing", "expired"):
            expected, run, listing, data = provider()
            final_run = copy.deepcopy(run)
            final_listing = copy.deepcopy(listing)
            details = copy.deepcopy(listing["artifacts"])
            if case == "detail":
                details[0]["id"] = 999
            if case == "rerun":
                final_run["run_attempt"] = 2
            if case == "listing":
                final_listing["artifacts"][0]["id"] = 999
                final_listing["artifacts"][0]["digest"] = "sha256:" + "0" * 64
            if case == "expired":
                final_listing["artifacts"][0]["expires_at"] = timestamp(120)
            incoming = data + b"replacement" if case == "archive" else data
            route = f"repos/{expected.repository}/actions/runs/{expected.run_id}"
            answer = routed(expected, run, listing)
            state = {"detail": 0, "final": False}

            def staged(endpoint):
                if endpoint.startswith(f"repos/{expected.repository}/actions/artifacts/"):
                    state["detail"] += 1
                    row = details[min(state["detail"], len(details)) - 1]
                    return copy.deepcopy(row)
                if endpoint == route + "/artifacts?per_page=100" and state["final"]:
                    return copy.deepcopy(final_listing)
                if endpoint == route + f"/attempts/{expected.run_attempt}" and state["final"]:
                    return copy.deepcopy(final_run)
                if endpoint == route + "/artifacts?per_page=100":
                    state["final"] = True
                return answer(endpoint)

            api = transport_v1.QualifiedGhApi(Path("/test-owned-gh"), "test-only-token")
            with mock.patch.object(api, "json", side_effect=staged), \
                 mock.patch.object(api, "archive", side_effect=lambda repo, ident, path: path.write_bytes(incoming)), \
                 mock.patch("transport_cases_v1.time.time", return_value=120), \
                 mock.patch("transport_cases_v1.time.sleep"), \
                 self.assertRaisesRegex(Failure, {
                     "archive": "archive bytes mismatch", "detail": "artifact detail changed",
                     "rerun": "provider run mismatch",
                     # A changed final set is caught by the stability re-check, not the first listing.
                     "listing": "provider artifacts changed",
                     "expired": "outside the exact attempt upload window"}[case]):
                qualify(api, expected, {})
