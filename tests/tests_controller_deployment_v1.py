"""Synthetic controller deployment-binding contract; no live provider writes or credentials."""
import unittest

from armorer_runtime import controller_deployment_v1 as deployment
from armorer_runtime.common import Failure

RUN_ID = 17
RUN_ATTEMPT = 2
COMMIT = "a" * 40
REPO = "brianluby/armorer-test"


class PayloadContractTests(unittest.TestCase):
    """The payload keys and types must mirror the native Rust adapter's attempt binding exactly."""

    def test_payload_binds_exact_attempt_with_required_keys_and_types(self):
        payload = deployment.deployment_payload(RUN_ID, RUN_ATTEMPT, COMMIT)
        self.assertEqual(set(payload), set(deployment.PAYLOAD_KEYS))
        self.assertIs(type(payload["armorer_run_id"]), int)
        self.assertIs(type(payload["armorer_run_attempt"]), int)
        self.assertIs(type(payload["armorer_source_commit"]), str)
        self.assertTrue(deployment.binds_attempt(payload, RUN_ID, RUN_ATTEMPT, COMMIT))

    def test_foreign_run_attempt_and_commit_are_rejected(self):
        payload = deployment.deployment_payload(RUN_ID, RUN_ATTEMPT, COMMIT)
        for run_id, attempt, commit in [
            (RUN_ID + 1, RUN_ATTEMPT, COMMIT),
            (RUN_ID, RUN_ATTEMPT + 1, COMMIT),
            (RUN_ID, RUN_ATTEMPT, "b" * 40),
        ]:
            with self.subTest(run_id=run_id, attempt=attempt):
                self.assertFalse(deployment.binds_attempt(payload, run_id, attempt, commit))

    def test_binding_rejects_coerced_and_extra_payload_fields(self):
        good = deployment.deployment_payload(RUN_ID, RUN_ATTEMPT, COMMIT)
        for mutation in [
            lambda p: p.update(armorer_run_id=str(RUN_ID)),
            lambda p: p.update(armorer_run_attempt=True),
            lambda p: p.update(armorer_run_id=0),
            lambda p: p.update(extra="field"),
            lambda p: p.pop("armorer_source_commit"),
        ]:
            payload = dict(good)
            mutation(payload)
            self.assertFalse(deployment.binds_attempt(payload, RUN_ID, RUN_ATTEMPT, COMMIT))
        self.assertFalse(deployment.binds_attempt("not-a-dict", RUN_ID, RUN_ATTEMPT, COMMIT))

    def test_invalid_identity_inputs_fail_closed(self):
        for run_id, attempt, commit in [
            (0, RUN_ATTEMPT, COMMIT),
            (RUN_ID, 0, COMMIT),
            (True, RUN_ATTEMPT, COMMIT),
            (RUN_ID, RUN_ATTEMPT, "A" * 40),
            (RUN_ID, RUN_ATTEMPT, "a" * 39),
            (RUN_ID, RUN_ATTEMPT, None),
        ]:
            with self.subTest(run_id=run_id, attempt=attempt):
                with self.assertRaises(Failure):
                    deployment.deployment_payload(run_id, attempt, commit)


class BodyContractTests(unittest.TestCase):
    """The create-deployment body must not merge the frozen commit or gate on commit statuses."""

    def test_create_body_is_attempt_bound_and_non_mutating_to_the_sha(self):
        body = deployment.create_deployment_body(RUN_ID, RUN_ATTEMPT, COMMIT)
        self.assertEqual(body["ref"], COMMIT)
        self.assertEqual(body["environment"], deployment.ENVIRONMENT)
        self.assertIs(body["auto_merge"], False)
        self.assertEqual(body["required_contexts"], [])
        self.assertIs(body["transient_environment"], False)
        self.assertIs(body["production_environment"], False)
        self.assertTrue(deployment.binds_attempt(body["payload"], RUN_ID, RUN_ATTEMPT, COMMIT))

    def test_only_the_release_publish_environment_is_admitted(self):
        with self.assertRaises(Failure):
            deployment.create_deployment_body(RUN_ID, RUN_ATTEMPT, COMMIT, environment="release-signing")

    def test_active_status_is_non_terminal(self):
        self.assertEqual(deployment.active_status_body()["state"], "in_progress")


class RouteAllowlistTests(unittest.TestCase):
    """Only the two fixed deployment write routes are admitted; no arbitrary origin or path."""

    def test_fixed_routes_are_admitted(self):
        self.assertEqual(deployment.deployment_route(REPO), f"repos/{REPO}/deployments")
        self.assertEqual(deployment.status_route(REPO, 5), f"repos/{REPO}/deployments/5/statuses")

    def test_foreign_and_malformed_routes_are_rejected(self):
        for endpoint in [
            f"repos/{REPO}/deployments/5",
            f"repos/{REPO}/deployments/0/statuses",
            f"repos/{REPO}/releases",
            f"repos/{REPO}/deployments/5/statuses/9",
            "https://evil.invalid/repos/owner/repo/deployments",
            f"repos/{REPO}/deployments?environment=release-publish",
            None,
            123,
        ]:
            with self.subTest(endpoint=endpoint):
                self.assertFalse(deployment._route(endpoint))

    def test_route_builders_reject_invalid_repository_and_id(self):
        with self.assertRaises(Failure):
            deployment.deployment_route("not a repo")
        with self.assertRaises(Failure):
            deployment.status_route(REPO, 0)
        with self.assertRaises(Failure):
            deployment.status_route(REPO, True)


if __name__ == "__main__":
    unittest.main()