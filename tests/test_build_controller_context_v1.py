"""Adversarial controller mappings and protection observations never mint release authority."""
import copy
from dataclasses import replace
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from armorer_runtime import controller_context_v1 as controller
from armorer_runtime.common import Failure
from armorer_runtime.source_transport_v1 import SourceGhApi
from test_build_source_transport_v1 import fixture as source_fixture
from test_build_transport_v1 import timestamp


def fixture(event="pull_request", environment=False):
    """Create separate independent intent and inert API data with deliberately different job/check IDs."""
    source, source_data = source_fixture(event)
    expected = controller.JobIntent(source, "Release", "trusted-finalizer", "macos-15",
                                    qualification_only=event == "pull_request")
    origin = "https://api.github.com/repos/owner/repo"
    job = {"id": 31, "run_id": 17, "run_attempt": 1, "name": expected.job_name,
           "head_sha": source.head_commit, "head_branch": source.head_branch,
           "workflow_name": expected.workflow_name, "url": origin + "/actions/jobs/31",
           "run_url": origin + "/actions/runs/17", "check_run_url": origin + "/check-runs/47",
           "status": "in_progress", "conclusion": None, "started_at": timestamp(110), "completed_at": None,
           "labels": ["macos-15"], "runner_id": 51, "runner_name": "GitHub Actions 51",
           "runner_group_id": 0, "runner_group_name": "GitHub Actions"}
    data = {key: copy.deepcopy(value) for key, value in source_data.items() if "/actions/runs/" in key}
    data["repos/owner/repo/actions/runs/17/attempts/1/jobs?per_page=100&page=1"] = {
        "total_count": 1, "jobs": [job]}
    data["repos/owner/repo/actions/jobs/31"] = copy.deepcopy(job)
    policy = None
    if environment:
        policy = controller.EnvironmentIntent("release-signing", 61, "EN_test61", (9, 10), "main")
        root = "repos/owner/repo/environments/release-signing"
        data[root] = {"id": 61, "node_id": "EN_test61", "name": "release-signing",
            "url": "https://api.github.com/" + root, "protection_rules": [
                {"id": 71, "type": "required_reviewers", "prevent_self_review": True,
                 "reviewers": [{"type": "User", "reviewer": {"type": "User", "id": ident}} for ident in (9, 10)]},
                {"id": 72, "type": "branch_policy"}],
            "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}}
        data[root + "/deployment-branch-policies?per_page=100&page=1"] = {"total_count": 2,
            "branch_policies": [{"id": 81, "type": "branch", "name": "main"},
                                {"id": 82, "type": "tag", "name": "v*"}]}
    return expected, source_data, data, policy


def observe(expected, source_data, data, policy=None, source_read=None, controller_read=None):
    """Replace native GETs only inside fixtures while keeping exact production adapter/intent types."""
    source_api = SourceGhApi(Path("/test-only-never-executed"), "test-only-token")
    api = controller.ControllerGhApi(Path("/test-only-never-executed"), "test-only-token")
    with mock.patch.object(source_api, "json", side_effect=source_read or
                           (lambda route: copy.deepcopy(source_data[route]))), \
         mock.patch.object(api, "json", side_effect=controller_read or
                           (lambda route: copy.deepcopy(data[route]))), \
         mock.patch("time.time", return_value=120):
        return controller.observe_controller(source_api, api, expected, policy)


class ControllerTests(unittest.TestCase):
    """Source, attempt, name, native metadata, controls and mutable races are independent gates."""

    def test_current_job_is_mapped_without_assuming_check_id_equals_job(self):
        """A unique attempt job maps to its separate check-run identity without producer authority."""
        expected, source, data, _ = fixture()
        record = observe(expected, source, data)
        self.assertEqual((record["controller"]["job"]["job_id"], record["controller"]["job"]["check_run_id"]), (31, 47))
        self.assertTrue(record["current_job_mapping_observed"])
        self.assertTrue(record["candidate_qualification_only"])
        for flag in ("producer_job_authenticated", "protected_environment_authenticated",
                     "protected_ref_authenticated", "signing_authorized", "publication_authorized"):
            self.assertIs(record[flag], False)

    def test_release_mapping_still_requires_oidc_and_protection(self):
        """Default-branch metadata does not authenticate hosted producer code or grant signing."""
        expected, source, data, _ = fixture("workflow_dispatch")
        record = observe(expected, source, data)
        self.assertFalse(record["candidate_qualification_only"])
        self.assertFalse(record["producer_job_authenticated"])

    def test_completed_run_cannot_supply_a_stale_active_job(self):
        """Successful run metadata is valid historical source data but cannot establish a current job."""
        expected, source, initial, _ = fixture()
        for route in ("repos/owner/repo/actions/runs/17", "repos/owner/repo/actions/runs/17/attempts/1"):
            data = copy.deepcopy(initial)
            data[route].update(status="completed", conclusion="success")
            with self.subTest(route=route), self.assertRaisesRegex(Failure, "intended run is not active"):
                observe(expected, source, data)

    def test_unsafe_or_malformed_intent_fails_before_provider_access(self):
        """PRs cannot enter producer mode, and independent identities are validated before GETs."""
        expected, source, data, _ = fixture()
        for invalid in (replace(expected, qualification_only=False), replace(expected, job_name="job\n"),
                        replace(expected, runner_label="self-hosted"), replace(expected, source=None),
                        replace(expected, qualification_only=1), replace(expected, workflow_name="")):
            with self.subTest(invalid=invalid), self.assertRaises(Failure):
                observe(invalid, source, data, source_read=mock.Mock(side_effect=AssertionError("GET occurred")),
                        controller_read=mock.Mock(side_effect=AssertionError("GET occurred")))

    def test_cross_run_attempt_head_branch_and_name_substitution(self):
        """Alter each API binding independently, including booleans in numeric identity slots."""
        expected, source, initial, _ = fixture()
        for key, value in (("run_id", 18), ("run_attempt", 2), ("run_attempt", True),
                           ("head_sha", "f" * 40), ("head_branch", "other"), ("workflow_name", "Other"),
                           ("name", "different-job"), ("id", True)):
            data = copy.deepcopy(initial)
            data["repos/owner/repo/actions/runs/17/attempts/1/jobs?per_page=100&page=1"]["jobs"][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(Failure):
                observe(expected, source, data)

    def test_ambiguous_name_and_duplicate_job_id_reject(self):
        """Complete attempt pagination must yield one reviewed name and unique numeric job IDs."""
        expected, source, initial, _ = fixture()
        for duplicate_id in (False, True):
            data = copy.deepcopy(initial)
            page = data["repos/owner/repo/actions/runs/17/attempts/1/jobs?per_page=100&page=1"]
            second = copy.deepcopy(page["jobs"][0])
            second["id"] = 31 if duplicate_id else 32
            page.update(total_count=2, jobs=[page["jobs"][0], second])
            with self.subTest(duplicate_id=duplicate_id), self.assertRaises(Failure):
                observe(expected, source, data)

    def test_complete_pagination_and_truncation_bounds(self):
        """The selected job cannot hide a duplicate on later pages or excuse a truncated listing."""
        expected, source, initial, _ = fixture()
        root = "repos/owner/repo/actions/runs/17/attempts/1/jobs?per_page=100&page="
        data = copy.deepcopy(initial)
        template = data[root + "1"]["jobs"][0]
        first = [copy.deepcopy(template)]
        for number in range(99):
            other = copy.deepcopy(template)
            other.update(id=100 + number, name="other-job-" + str(number))
            first.append(other)
        last = copy.deepcopy(template)
        last.update(id=500, name="last-job")
        data[root + "1"] = {"total_count": 101, "jobs": first}
        data[root + "2"] = {"total_count": 101, "jobs": [last]}
        self.assertEqual(len(observe(expected, source, data)["controller"]["attempt_jobs"]), 101)
        for alteration in ("later-duplicate", "count-change", "missing-page", "too-many"):
            changed = copy.deepcopy(data)
            if alteration == "later-duplicate":
                changed[root + "2"]["jobs"][0]["name"] = expected.job_name
            elif alteration == "count-change":
                changed[root + "2"]["total_count"] = 102
            elif alteration == "missing-page":
                changed[root + "2"]["jobs"] = []
            else:
                changed[root + "1"]["total_count"] = 1001
            with self.subTest(alteration=alteration), self.assertRaises(Failure):
                observe(expected, source, changed)

    def test_check_run_url_must_be_exact_fixed_origin_and_bounded_id(self):
        """No query, alias, foreign repository, leading zero or job-ID fallback can establish check identity."""
        expected, source, initial, _ = fixture()
        for url in (None, "https://evil.invalid/check-runs/47", "http://api.github.com/repos/owner/repo/check-runs/47",
                    "https://api.github.com/repos/other/repo/check-runs/47",
                    "https://api.github.com/repos/owner/repo/check-runs/047",
                    "https://api.github.com/repos/owner/repo/check-runs/47?x=1",
                    "https://api.github.com/repos/owner/repo/check-runs/47\n",
                    "https://api.github.com/repos/owner/repo/check-runs/9223372036854775808"):
            data = copy.deepcopy(initial)
            data["repos/owner/repo/actions/runs/17/attempts/1/jobs?per_page=100&page=1"]["jobs"][0]["check_run_url"] = url
            with self.subTest(url=url), self.assertRaises(Failure):
                observe(expected, source, data)

    def test_inactive_future_and_unqualified_runner_jobs_reject(self):
        """Metadata for completed, queued, future, self-hosted or mixed-label jobs is insufficient."""
        expected, source, initial, _ = fixture()
        for key, value in (("status", "completed"), ("status", "queued"), ("conclusion", "success"),
                           ("completed_at", timestamp(115)), ("started_at", timestamp(99)),
                           ("started_at", timestamp(121)), ("labels", ["self-hosted"]),
                           ("labels", ["macos-15", "self-hosted"]), ("runner_group_id", True),
                           ("runner_group_id", 3), ("runner_group_name", "custom"), ("runner_id", 0)):
            data = copy.deepcopy(initial)
            data["repos/owner/repo/actions/runs/17/attempts/1/jobs?per_page=100&page=1"]["jobs"][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(Failure):
                observe(expected, source, data)

    def test_job_listing_and_direct_read_must_agree(self):
        """The direct selected job cannot switch its check-run identity after independent mapping."""
        expected, source, data, _ = fixture()
        data["repos/owner/repo/actions/jobs/31"]["check_run_url"] = "https://api.github.com/repos/owner/repo/check-runs/48"
        with self.assertRaises(Failure):
            observe(expected, source, data)

    def test_final_job_and_run_races_reject(self):
        """A late completion, replacement check or rerun is checked after full source re-observation."""
        expected, source, data, _ = fixture()
        for target in ("job", "run"):
            calls = {}
            def changed(route):
                """Inject an actual read-order race without changing the independent expected intent."""
                calls[route] = calls.get(route, 0) + 1
                value = copy.deepcopy(data[route])
                if target == "job" and route.endswith("/actions/jobs/31") and calls[route] == 3:
                    value["status"] = "completed"
                if target == "run" and route.endswith("/actions/runs/17") and calls[route] == 3:
                    value["run_attempt"] = 2
                return value
            with self.subTest(target=target), self.assertRaises(Failure):
                observe(expected, source, data, controller_read=changed)

    def test_final_source_permissions_revocation_rejects(self):
        """Original/rerun actors must still have write permission after controller metadata reads."""
        expected, source, data, _ = fixture()
        calls = {}
        def revoked(route):
            """Revoke a mutable permission only on the second complete source observation."""
            calls[route] = calls.get(route, 0) + 1
            value = copy.deepcopy(source[route])
            if route.endswith("/collaborators/owner/permission") and calls[route] >= 3:
                value["permission"] = "read"
            return value
        with self.assertRaises(Failure):
            observe(expected, source, data, source_read=revoked)

    def test_environment_configuration_never_proves_attempt_approval(self):
        """Absent admin metadata stays unknown; even explicit false cannot prove per-attempt enforcement."""
        expected, source, data, policy = fixture("workflow_dispatch", environment=True)
        root = "repos/owner/repo/environments/release-signing"
        for bypass, state in ((None, "unknown"), (False, "configured"), (True, "disabled")):
            if bypass is not None:
                data[root]["can_admins_bypass"] = bypass
            record = observe(expected, source, data, policy)
            env = record["controller"]["environment"]
            self.assertEqual(env["state"], state)
            self.assertEqual(env["current_attempt_approval"], "unsupported")
            self.assertEqual(env["effective_enforcement"], "unsupported")
            self.assertFalse(record["protected_environment_authenticated"])
            self.assertFalse(record["signing_authorized"])

    def test_environment_identity_reviewers_and_restrictions_reject(self):
        """Swapped environments, self-review, teams and broad deployment restrictions cannot match policy."""
        expected, source, initial, policy = fixture("workflow_dispatch", environment=True)
        root = "repos/owner/repo/environments/release-signing"
        for change in ("id", "node", "name", "self-review", "reviewer", "team", "extra-rule", "branches", "bypass-type"):
            data = copy.deepcopy(initial)
            row = data[root]
            if change == "id": row["id"] = 62
            elif change == "node": row["node_id"] = "EN_other"
            elif change == "name": row["name"] = "release-publish"
            elif change == "self-review": row["protection_rules"][0]["prevent_self_review"] = False
            elif change == "reviewer": row["protection_rules"][0]["reviewers"][0]["reviewer"]["id"] = 11
            elif change == "team": row["protection_rules"][0]["reviewers"][0]["type"] = "Team"
            elif change == "extra-rule": row["protection_rules"].append({"id": 73, "type": "custom"})
            elif change == "branches": row["deployment_branch_policy"]["protected_branches"] = True
            elif change == "bypass-type": row["can_admins_bypass"] = "false"
            with self.subTest(change=change), self.assertRaises(Failure):
                observe(expected, source, data, policy)

    def test_exact_branch_and_tag_policy_set_rejects_broadening(self):
        """Typed deployment policies must exactly allow the reviewed default branch and v* tag scope."""
        expected, source, initial, policy = fixture("workflow_dispatch", environment=True)
        route = "repos/owner/repo/environments/release-signing/deployment-branch-policies?per_page=100&page=1"
        for change in ("extra", "broad-tag", "wrong-type", "default", "duplicate-id", "count"):
            data = copy.deepcopy(initial)
            row = data[route]
            if change == "extra": row["branch_policies"].append({"id": 83, "type": "branch", "name": "*"})
            elif change == "broad-tag": row["branch_policies"][1]["name"] = "*"
            elif change == "wrong-type": row["branch_policies"][1]["type"] = "branch"
            elif change == "default": row["branch_policies"][0]["name"] = "other"
            elif change == "duplicate-id": row["branch_policies"][1]["id"] = 81
            elif change == "count": row["total_count"] = True
            with self.subTest(change=change), self.assertRaises(Failure):
                observe(expected, source, data, policy)

    def test_environment_mutation_after_source_preflight_rejects(self):
        """A configuration change after both snapshots is detected by the final environment reread."""
        expected, source, data, policy = fixture("workflow_dispatch", environment=True)
        root = "repos/owner/repo/environments/release-signing"
        calls = {}
        def changed(route):
            """Change an otherwise valid environment identity on the third control read."""
            calls[route] = calls.get(route, 0) + 1
            value = copy.deepcopy(data[route])
            if route == root and calls[route] == 3:
                value["protection_rules"][1]["id"] = 90
            return value
        with self.assertRaises(Failure):
            observe(expected, source, data, policy, controller_read=changed)

    def test_protected_controls_cannot_use_pr_qualification_or_unknown_policy(self):
        """A PR-only native qualification never enters environment policy collection."""
        expected, source, data, _ = fixture()
        policy = controller.EnvironmentIntent("release-signing", 61, "EN_test61", (9,), "main")
        for value in (policy, {"name": "release-signing"}):
            with self.subTest(value=value), self.assertRaises(Failure):
                observe(expected, source, data, value, source_read=mock.Mock(side_effect=AssertionError("GET occurred")))

    def test_routes_reject_mutations_archives_and_arbitrary_provider_paths(self):
        """Rejected routes never launch native gh, so callers cannot smuggle writes or extra data scopes."""
        api = controller.ControllerGhApi(Path("/test-only-never-executed"), "test-only-token")
        allowed = ("repos/owner/repo/actions/jobs/31", "repos/owner/repo/actions/runs/17",
                   "repos/owner/repo/actions/runs/17/attempts/1/jobs?per_page=100&page=10",
                   "repos/owner/repo/environments/release-publish/deployment-branch-policies?per_page=100&page=1")
        for route in allowed:
            self.assertTrue(controller._route(route), route)
        for route in ("https://api.github.com/repos/owner/repo/actions/jobs/31", "repos/owner/repo/actions/jobs/31/logs",
                      "repos/owner/repo/actions/runs/17/jobs?filter=all", "repos/owner/repo/actions/artifacts/31/zip",
                      "repos/owner/repo/actions/runs/17/attempts/1/jobs?per_page=100&page=11",
                      "repos/owner/repo/actions/runs/17/attempts/1/jobs?per_page=100&page=1&x=1",
                      "repos/owner/repo/environments/other", "repos/owner/repo/rulesets", "repos/owner/repo/releases",
                      "repos/owner/repo/actions/jobs/31\n", "repos/owner/repo/actions/jobs/0"):
            with self.subTest(route=route), tempfile.TemporaryDirectory() as temporary, \
                 mock.patch.object(api, "_check_native", side_effect=AssertionError("native checked")), \
                 self.assertRaises(Failure):
                api._read(route, Path(temporary) / "response", 4096)

    def test_real_process_uses_only_explicit_token_and_discards_provider_diagnostics(self):
        """An actual fixture child proves sterile GET execution, byte bounds and secret-free errors."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "fake-native"
            executable.write_text("#!" + sys.executable + "\nimport os,sys,json\n"
                "print(json.dumps({'explicit':os.environ.get('GH_TOKEN')=='test-only-token',"
                "'ambient':any(k in os.environ for k in ('GITHUB_TOKEN','GH_DEBUG','HTTP_PROXY','PYTHONPATH')),"
                "'private':os.path.samefile(os.getcwd(),os.environ['HOME']),'method':sys.argv[sys.argv.index('--method')+1]}))\n"
                "print('test-only-sensitive-provider-diagnostic',file=sys.stderr)\n")
            executable.chmod(0o500)
            api = controller.ControllerGhApi(executable, "test-only-token")
            route = "repos/owner/repo/actions/jobs/31"
            with mock.patch.object(api, "_check_native"), mock.patch.dict(os.environ,
                    GITHUB_TOKEN="test-only-unrelated", GH_DEBUG="api", HTTP_PROXY="http://test-only.invalid:9", PYTHONPATH="/foreign"):
                self.assertEqual(api.json(route), {"explicit": True, "ambient": False, "private": True, "method": "GET"})
            with mock.patch.object(api, "_check_native"), self.assertRaisesRegex(Failure, "output exceeded limit") as caught:
                api._read(route, root / "bounded.json", 10)
            self.assertNotIn("sensitive", str(caught.exception))
            executable.chmod(0o700)
            executable.write_text("#!" + sys.executable + "\nimport sys\nprint('test-only-sensitive-provider-diagnostic',file=sys.stderr)\nsys.exit(1)\n")
            executable.chmod(0o500)
            with mock.patch.object(api, "_check_native"), self.assertRaisesRegex(Failure, "native transport read failed") as caught:
                api.json(route)
            self.assertNotIn("sensitive", str(caught.exception))

    def test_wait_timer_is_exact_and_unknown_policy_fails_before_gets(self):
        """A reviewed timer has no default coercion, and invalid environment intent has no provider effects."""
        expected, source, data, policy = fixture("workflow_dispatch", environment=True)
        root = "repos/owner/repo/environments/release-signing"
        timed = replace(policy, wait_minutes=30)
        data[root]["protection_rules"].append({"id": 73, "type": "wait_timer", "wait_timer": 30})
        self.assertEqual(observe(expected, source, data, timed)["controller"]["environment"]["controls"]["wait_minutes"], 30)
        data[root]["protection_rules"][-1]["wait_timer"] = True
        with self.assertRaises(Failure):
            observe(expected, source, data, timed)
        for invalid in (replace(policy, environment_id=True), replace(policy, reviewer_ids=()),
                        replace(policy, reviewer_ids=(9, 9)), replace(policy, node_id="node\n"),
                        replace(policy, wait_minutes=True), replace(policy, default_branch="other")):
            with self.subTest(invalid=invalid), self.assertRaises(Failure):
                observe(expected, source, data, invalid, source_read=mock.Mock(side_effect=AssertionError("GET occurred")))

    def test_mixed_operator_and_workflow_authentication_cannot_form_a_context(self):
        """Operator metadata qualification cannot be joined with a differently scoped workflow observation."""
        expected, _, _, _ = fixture()
        source_api = SourceGhApi(Path("/test-only-never-executed"), "test-only-token")
        api = controller.ControllerGhApi.operator_qualification(Path("/test-only-never-executed"))
        with mock.patch.object(source_api, "json", side_effect=AssertionError("GET occurred")), self.assertRaises(Failure):
            controller.observe_controller(source_api, api, expected)


if __name__ == "__main__":
    unittest.main()
