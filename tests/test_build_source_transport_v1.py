"""Source/actor/ref substitutions reject before a source observation; fixtures grant no authority."""
import base64
import copy
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from armorer_runtime import source_transport_v1 as source
from armorer_runtime.common import Failure
from test_build_transport_v1 import timestamp


def fixture(event="pull_request"):
    """Construct independent test intent and inert provider replies without signature/producer claims."""
    data = b"reviewed-test-only-caller\n"
    blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
    intent = source.SourceIntent("owner/repo", 7, 8, "main", 17, 1, 19, ".github/workflows/release.yml",
        "a" * 40, hashlib.sha256(data).hexdigest(), "b" * 40 if event == "pull_request" else "a" * 40,
        "a" * 40, "feature" if event == "pull_request" else "main", event,
        "refs/pull/3/merge" if event == "pull_request" else "refs/heads/main", 8, "owner", 9, "rerunner",
        pull_request=3 if event == "pull_request" else None, base_commit="c" * 40 if event == "pull_request" else None,
        base_branch="main" if event == "pull_request" else None)
    repository = {"id": 7, "full_name": "owner/repo", "fork": False, "owner": {"id": 8, "login": "owner"},
                  "default_branch": "main", "archived": False, "disabled": False}
    actor = {"id": 8, "login": "owner", "type": "User"}
    rerunner = {"id": 9, "login": "rerunner", "type": "User"}
    run = {"id": 17, "run_attempt": 1, "workflow_id": 19, "path": intent.caller_path, "head_sha": intent.head_commit,
           "head_branch": intent.head_branch, "event": event, "repository": repository, "head_repository": repository,
           "actor": actor, "triggering_actor": rerunner, "status": "in_progress", "conclusion": None,
           "run_started_at": timestamp(100), "referenced_workflows": []}
    root = "repos/owner/repo"
    responses = {root: repository, root + "/actions/runs/17": run, root + "/actions/runs/17/attempts/1": run,
        root + "/collaborators/owner/permission": {"user": actor, "permission": "admin"},
        root + "/collaborators/rerunner/permission": {"user": rerunner, "permission": "write"},
        root + "/git/commits/" + "a" * 40: {"sha": "a" * 40, "tree": {"sha": "d" * 40},
            "parents": [{"sha": "c" * 40}, {"sha": "b" * 40}] if event == "pull_request" else [{"sha": "c" * 40}]},
        root + "/git/blobs/" + blob: {"sha": blob, "encoding": "base64", "content": base64.b64encode(data).decode(), "size": len(data)},
        root + "/pulls/3": {"number": 3, "state": "open", "merge_commit_sha": "a" * 40,
            "head": {"sha": "b" * 40, "ref": "feature", "repo": repository},
            "base": {"sha": "c" * 40, "ref": "main", "repo": repository}},
        root + "/git/ref/heads/main": {"ref": "refs/heads/main", "object": {"type": "commit", "sha": "a" * 40}},
        root + "/compare/" + "a" * 40 + "..." + "a" * 40 + "?per_page=1": {
            "status": "identical", "base_commit": {"sha": "a" * 40}, "merge_base_commit": {"sha": "a" * 40}}}
    for sha, name, kind, mode, child in (("d" * 40, ".github", "tree", "040000", "e" * 40),
            ("e" * 40, "workflows", "tree", "040000", "f" * 40), ("f" * 40, "release.yml", "blob", "100644", blob)):
        responses[root + "/git/trees/" + sha] = {"sha": sha, "truncated": False,
            "tree": [{"path": name, "type": kind, "mode": mode, "sha": child}]}
    return intent, responses


def observe(intent, responses):
    """Patch native reads only in tests; the production entry point still requires its exact native type."""
    api = source.SourceGhApi(Path("/inert-test-native"), "test-only-token")
    with mock.patch.object(api, "json", side_effect=lambda route: copy.deepcopy(responses[route])), \
         mock.patch.object(source.time, "time", return_value=120):
        return source.observe_source(api, intent)


class SourceControlTests(unittest.TestCase):
    def test_pr_and_default_dispatch_observe_inert_bytes_without_credential_authority(self):
        """Both supported observation paths bind caller bytes and exact distinct original/rerun actors."""
        for event in ("pull_request", "workflow_dispatch"):
            intent, responses = fixture(event)
            receipt = observe(intent, responses)
            self.assertEqual(receipt["source_control"]["caller"]["sha256"], intent.caller_sha256)
            self.assertEqual(receipt["source_control"]["actors"], {"owner": "admin", "rerunner": "write"})
            for name in ("signing_authorized", "publication_authorized", "producer_job_authenticated",
                         "protected_ref_authenticated", "protected_environment_authenticated", "production_catalog_accepted",
                         "cryptographic_release_authenticated"):
                self.assertIs(receipt[name], False)

    def test_unsafe_events_refs_actor_shapes_and_boolean_ids_prevent_native_reads(self):
        """Unsupported invocation, ambiguous intent and non-default dispatch fail before launching gh."""
        intent, _ = fixture("workflow_dispatch")
        changes = ({"event": "pull_request_target"}, {"event": "workflow_run"}, {"event": "push"},
            {"ref": "refs/heads/feature"}, {"ref": "refs/tags/v01.2.3", "event": "push"}, {"run_attempt": True},
            {"actor_login": "owner?injection"}, {"default_branch": None}, {"caller_path": ".github/workflows/../release.yml"},
            {"referenced_workflows": ([],)}, {"head_commit": "main"})
        api = source.SourceGhApi(Path("/inert"), "test-only-token")
        for change in changes:
            with self.subTest(change=change), mock.patch.object(api, "json") as read, self.assertRaises(Failure):
                source.observe_source(api, replace(intent, **change))
            read.assert_not_called()

    def test_readonly_route_allowlist_rejects_origin_options_artifacts_aliases_and_extra_queries(self):
        """The explicit successor permits source reads only and cannot widen the frozen v1 routes."""
        bad = ("https://api.github.com/repos/owner/repo", "--hostname", "repos/owner/repo/actions/artifacts/1/zip",
               "repos/owner/repo/git/ref/heads/../other", "repos/owner/repo/git/ref/heads/%2e%2e/other",
               "repos/owner/repo?secret=value", "repos/owner/repo/releases", "repos/owner/repo/git/ref/heads/main.lock")
        with mock.patch.object(source.subprocess, "Popen") as launch, tempfile.TemporaryDirectory() as temporary:
            api = source.SourceGhApi(Path("/inert"), "test-only-token")
            for route in bad:
                with self.assertRaises(Failure): api._read(route, Path(temporary) / "absent", 1024)
            launch.assert_not_called()

    def test_real_process_boundary_omits_ambient_tokens_debug_proxies_and_caller_working_directory(self):
        """A test-owned real child observes only the explicit synthetic token and fixed GET environment."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "fake-native"
            executable.write_text("#!" + sys.executable + "\nimport os,sys,json\n"
                "print(json.dumps({'explicit':os.environ.get('GH_TOKEN')=='test-only-token',"
                "'ambient':any(k in os.environ for k in ('GITHUB_TOKEN','GH_DEBUG','HTTP_PROXY','PYTHONPATH')),"
                "'private':os.path.samefile(os.getcwd(),os.environ['HOME']),'method':sys.argv[sys.argv.index('--method')+1]}))\n")
            executable.chmod(0o500)
            api = source.SourceGhApi(executable, "test-only-token")
            with mock.patch.object(api, "_check_native"), mock.patch.dict(os.environ,
                    GITHUB_TOKEN="test-only-unrelated", GH_DEBUG="api", HTTP_PROXY="http://test-only.invalid:9", PYTHONPATH="/foreign"):
                self.assertEqual(api.json("repos/owner/repo"), {"explicit": True, "ambient": False,
                                                               "private": True, "method": "GET"})
            with mock.patch.object(api, "_check_native"), self.assertRaisesRegex(Failure, "output exceeded limit"):
                api._read("repos/owner/repo", root / "bounded.json", 10)

    def test_source_owner_actor_permissions_reusable_identity_and_run_substitutions_reject(self):
        """Wrong immutable accounts, missing write access and cross-run/pin/fork substitutions yield no observation."""
        changes = [lambda r: r["repos/owner/repo"].update(id=True),
            lambda r: r["repos/owner/repo"]["owner"].update(id=99), lambda r: r["repos/owner/repo"].update(fork=True),
            lambda r: r["repos/owner/repo/collaborators/rerunner/permission"].update(permission="read"),
            lambda r: r["repos/owner/repo/actions/runs/17"]["actor"].update(id=99),
            lambda r: r["repos/owner/repo/actions/runs/17"]["triggering_actor"].update(type="Bot"),
            lambda r: r["repos/owner/repo/actions/runs/17"].update(run_attempt=2),
            lambda r: r["repos/owner/repo/actions/runs/17"].update(event="workflow_run"),
            lambda r: r["repos/owner/repo/actions/runs/17"].update(referenced_workflows=[{"path": "foreign", "sha": "a" * 40}]),
            lambda r: r["repos/owner/repo/actions/runs/17"].update(status="completed", conclusion="failure")]
        for change in changes:
            intent, responses = fixture(); change(responses)
            with self.assertRaises(Failure): observe(intent, responses)

    def test_exact_caller_identity_truncated_trees_symlinks_and_base64_aliases_reject(self):
        """A caller cannot authenticate itself through a blob name, parser ambiguity or symlink target."""
        for case in ("digest", "truncated", "link", "executable", "duplicate", "blob", "encoding"):
            intent, responses = fixture()
            tree = responses["repos/owner/repo/git/trees/" + "f" * 40]
            blob = next(value for key, value in responses.items() if "/git/blobs/" in key)
            if case == "digest": intent = replace(intent, caller_sha256="0" * 64)
            if case == "truncated": tree["truncated"] = True
            if case == "link": tree["tree"][0]["mode"] = "120000"
            if case == "executable": tree["tree"][0]["mode"] = "100755"
            if case == "duplicate": tree["tree"].append(copy.deepcopy(tree["tree"][0]))
            if case == "blob": blob["sha"] = "0" * 40
            if case == "encoding": blob["content"] += " "
            with self.subTest(case=case), self.assertRaises(Failure): observe(intent, responses)

    def test_current_merge_head_base_parents_and_ancestry_are_required(self):
        """Exact PR ancestry and default-branch ancestry cannot be replaced by head names alone."""
        for case in ("head", "base", "merge", "closed", "parents", "ancestor", "dispatch_moved"):
            intent, responses = fixture("workflow_dispatch" if case in ("ancestor", "dispatch_moved") else "pull_request")
            pull = responses["repos/owner/repo/pulls/3"]
            if case in ("head", "base"): pull[case]["sha"] = "9" * 40
            if case == "merge": pull["merge_commit_sha"] = "9" * 40
            if case == "closed": pull["state"] = "closed"
            if case == "parents": responses["repos/owner/repo/git/commits/" + "a" * 40]["parents"].reverse()
            if case == "ancestor": responses["repos/owner/repo/compare/" + "a" * 40 + "..." + "a" * 40 + "?per_page=1"]["merge_base_commit"]["sha"] = "9" * 40
            if case == "dispatch_moved": responses["repos/owner/repo/git/ref/heads/main"]["object"]["sha"] = "9" * 40
            with self.subTest(case=case), self.assertRaises(Failure): observe(intent, responses)

    def test_annotated_stable_tags_peel_to_exact_default_ancestor_without_moving_tags(self):
        """Stable lightweight/annotated tags work; cycles, tree leaves and excessive depth reject."""
        intent, responses = fixture("workflow_dispatch")
        intent = replace(intent, event="push", ref="refs/tags/v1.2.3", head_branch="v1.2.3")
        for key in ("repos/owner/repo/actions/runs/17", "repos/owner/repo/actions/runs/17/attempts/1"):
            responses[key].update(event="push", head_branch="v1.2.3")
        tag = "1" * 40
        responses["repos/owner/repo/git/ref/tags/v1.2.3"] = {"ref": intent.ref, "object": {"type": "tag", "sha": tag}}
        responses["repos/owner/repo/git/tags/" + tag] = {"sha": tag, "object": {"type": "commit", "sha": intent.source_commit}}
        self.assertEqual(observe(intent, responses)["source_control"]["reference"]["tag_objects"], [tag])
        for obj in ({"type": "tag", "sha": tag}, {"type": "tree", "sha": intent.source_commit}):
            responses["repos/owner/repo/git/tags/" + tag]["object"] = obj
            with self.assertRaises(Failure): observe(intent, responses)
        for index in range(1, 10):
            current, child = str(index) * 40, str(index + 1) * 40
            responses["repos/owner/repo/git/tags/" + current] = {"sha": current, "object": {"type": "tag", "sha": child}}
        with self.assertRaisesRegex(Failure, "unsupported ref object"): observe(intent, responses)

    def test_final_reread_and_clock_expiry_reject_changed_mutable_prerequisites(self):
        """Reruns, actor revocation, ref/default movement and expiry during collection invalidate the checkpoint."""
        intent, _ = fixture()
        for case in ("permission", "rerun", "freshness"):
            api = source.SourceGhApi(Path("/inert"), "test-only-token")
            first = {"run_started_at": 100, "test_only": "before"}
            second = dict(first)
            if case == "permission": second["test_only"] = "revoked"
            _, responses = fixture()
            if case == "rerun": responses["repos/owner/repo/actions/runs/17"]["run_attempt"] = 2
            with mock.patch.object(source, "_snapshot", side_effect=[first, second]), \
                 mock.patch.object(api, "json", side_effect=lambda route: responses[route]), \
                 mock.patch.object(source.time, "time", return_value=4000 if case == "freshness" else 120), self.assertRaises(Failure):
                source.observe_source(api, intent)
