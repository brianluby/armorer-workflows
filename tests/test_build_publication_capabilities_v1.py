"""Capability denial, parser, process isolation and mutable prerequisite regressions."""
import copy
from dataclasses import replace
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

from armorer_runtime import publication_capabilities_v1 as capability
from armorer_runtime.common import Failure
from test_build_controller_context_v1 import fixture as controller_fixture


def fixture():
    """Create independently expected repository identity with inert native-response fixtures."""
    expected = capability.RepositoryIntent("owner/repo", 20, "main")
    root = "repos/owner/repo"
    data = {root: capability.NativeResponse(200, {"id": 20, "full_name": "owner/repo",
        "url": "https://api.github.com/" + root, "default_branch": "main", "fork": False,
        "archived": False, "disabled": False, "private": False}),
        root + "/immutable-releases": capability.NativeResponse(200, {"enabled": True, "enforced_by_owner": False})}
    for name in capability.ENVIRONMENTS:
        data[root + "/environments/" + name] = capability.NativeResponse(404, {"message": "not visible"})
    return expected, data


def observe(expected, data, policies=(), read=None):
    """Patch native reads only for fixtures; retain exact production adapter and independent intent types."""
    api = capability.CapabilityGhApi(Path("/test-only-never-executed"), "test-only-read-token")
    with mock.patch.object(api, "response", side_effect=read or (lambda route: copy.deepcopy(data[route]))):
        return capability.observe_capabilities(api, expected, policies)


def wire(status=200, body=b"{}", headers=b"Content-Type: application/json", protocol=b"HTTP/2.0"):
    """Encode inert bounded native include-output bytes for framing and process tests."""
    return protocol + b" " + str(status).encode() + b" Status\r\n" + headers + b"\r\n\r\n" + body


class CapabilityTests(unittest.TestCase):
    """Provider configuration and every failure class remain distinct from operational authority."""

    def test_observation_never_grants_operational_authority(self):
        """A configured immutable setting and exact repository identity do not authorize signing or publication."""
        expected, data = fixture()
        result = observe(expected, data)
        self.assertEqual(result["prerequisites"]["immutable_releases"]["state"], "configured")
        self.assertEqual(result["prerequisites"]["environments"]["release-signing"]["state"], "unknown")
        self.assertTrue(result["native_read_observed"])
        for flag in ("run_bound", "protected_environment_authenticated", "signing_authorized",
                     "publication_authorized", "immutable_release_verified", "release_attestation_verified"):
            self.assertIs(result[flag], False)

    def test_native_error_statuses_never_become_disabled_or_success(self):
        """Hidden reads, denied permissions, throttling and server errors have explicit blocking states."""
        expected, initial = fixture()
        for status, state in ((401, "denied"), (403, "unknown"), (404, "unknown"),
                              (422, "error"), (429, "error"), (500, "error"), (503, "error")):
            data = copy.deepcopy(initial)
            data["repos/owner/repo/immutable-releases"] = capability.NativeResponse(status, {"message": "secret-sentinel"})
            with self.subTest(status=status):
                result = observe(expected, data)
                self.assertEqual(result["prerequisites"]["immutable_releases"]["state"], state)
                self.assertNotIn("secret-sentinel", json.dumps(result))
                self.assertFalse(result["publication_authorized"])

    def test_permission_and_rate_limit_403_remain_indistinguishable(self):
        """Both provider meanings of HTTP 403 remain unknown without trusting or reflecting diagnostic text."""
        expected, initial = fixture()
        for message in ("API rate limit exceeded", "Resource not accessible by integration"):
            data = copy.deepcopy(initial)
            data["repos/owner/repo/immutable-releases"] = capability.NativeResponse(403, {"message": message})
            with self.subTest(message=message):
                result = observe(expected, data)
                self.assertEqual(result["prerequisites"]["immutable_releases"],
                    {"state": "unknown", "reason": "access-denied-or-throttled", "http_status": 403})
                self.assertNotIn(message, json.dumps(result))
                self.assertFalse(result["publication_authorized"])

    def test_explicit_disabled_setting_is_distinct(self):
        """An explicit boolean false is retained as disabled while an invisible 404 remains unknown."""
        expected, data = fixture()
        data["repos/owner/repo/immutable-releases"] = capability.NativeResponse(200, {"enabled": False, "enforced_by_owner": False})
        self.assertEqual(observe(expected, data)["prerequisites"]["immutable_releases"]["state"], "disabled")

    def test_immutable_malformed_claims_reject(self):
        """Numeric truthiness, missing fields and unsupported additions never configure the capability."""
        expected, initial = fixture()
        for row in ({"enabled": 1, "enforced_by_owner": False}, {"enabled": True},
                    {"enabled": True, "enforced_by_owner": "false"},
                    {"enabled": True, "enforced_by_owner": False, "extra": True}):
            data = copy.deepcopy(initial)
            data["repos/owner/repo/immutable-releases"] = capability.NativeResponse(200, row)
            with self.subTest(row=row), self.assertRaisesRegex(Failure, "response unsupported"):
                observe(expected, data)

    def test_invalid_independent_intent_rejects_before_reads(self):
        """No malformed repository, branch or policy can start a credentialed provider process."""
        expected, data = fixture()
        for invalid in (replace(expected, repository="../repo"), replace(expected, repository="owner/repo?x=1"),
                        replace(expected, repository="owner/repo.git"), replace(expected, repository=None),
                        replace(expected, repository_id=True), replace(expected, default_branch="main\n"),
                        replace(expected, default_branch="main//other")):
            with self.subTest(invalid=invalid), self.assertRaises(Failure):
                observe(invalid, data, read=mock.Mock(side_effect=AssertionError("read occurred")))
        with self.assertRaises(Failure):
            observe(expected, data, policies=[])

    def test_repository_identity_state_substitution_rejects(self):
        """Wrong numeric identity, origin, branch and unsafe repository flags fail before capability reads."""
        expected, initial = fixture()
        for key, value in (("id", 21), ("id", True), ("full_name", "other/repo"),
                           ("url", "https://evil.invalid/repos/owner/repo"), ("default_branch", "other"),
                           ("fork", True), ("archived", True), ("disabled", True), ("private", 0)):
            data = copy.deepcopy(initial)
            data["repos/owner/repo"].body[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(Failure):
                observe(expected, data)

    def test_settings_race_rejects(self):
        """Stable identities cannot hide a setting changed between the two complete snapshots."""
        expected, data = fixture()
        calls = 0

        def changing_read(route):
            """Flip the immutable prerequisite on its second native read."""
            nonlocal calls
            result = copy.deepcopy(data[route])
            if route.endswith("/immutable-releases"):
                calls += 1
                result.body["enabled"] = calls == 1
            return result

        with self.assertRaisesRegex(Failure, "changed between reads"):
            observe(expected, data, read=changing_read)

    def test_configured_environment_still_has_no_attempt_approval(self):
        """Exact reviewed controls and a false admin-bypass flag retain unsupported effective enforcement."""
        expected, data = fixture()
        _, _, rows, policy = controller_fixture("workflow_dispatch", environment=True)
        for route, row in rows.items():
            if "/environments/" in route:
                data[route] = capability.NativeResponse(200, copy.deepcopy(row))
        data["repos/owner/repo/environments/release-signing"].body["can_admins_bypass"] = False
        result = observe(expected, data, (policy,))
        environment = result["prerequisites"]["environments"]["release-signing"]
        self.assertEqual(environment["state"], "configured")
        self.assertEqual(environment["current_attempt_approval"], "unsupported")
        self.assertEqual(environment["effective_enforcement"], "unsupported")
        self.assertFalse(result["signing_authorized"])

    def test_missing_or_enabled_admin_bypass_is_blocking(self):
        """Omitted bypass metadata remains unknown, while enabled bypass explicitly disables the prerequisite."""
        expected, initial = fixture()
        _, _, rows, policy = controller_fixture("workflow_dispatch", environment=True)
        for bypass, state in ((None, "unknown"), (True, "disabled")):
            data = copy.deepcopy(initial)
            for route, row in rows.items():
                if "/environments/" in route:
                    data[route] = capability.NativeResponse(200, copy.deepcopy(row))
            if bypass is not None:
                data["repos/owner/repo/environments/release-signing"].body["can_admins_bypass"] = bypass
            with self.subTest(bypass=bypass):
                result = observe(expected, data, (policy,))
                self.assertEqual(result["prerequisites"]["environments"]["release-signing"]["state"], state)

    def test_unreviewed_environment_identity_is_discovery_only(self):
        """Provider-discovered environment IDs cannot supply independent expected policy or approval."""
        expected, data = fixture()
        _, _, rows, _ = controller_fixture("workflow_dispatch", environment=True)
        root = "repos/owner/repo/environments/release-signing"
        data[root] = capability.NativeResponse(200, rows[root])
        result = observe(expected, data)["prerequisites"]["environments"]["release-signing"]
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(result["reason"], "independent-environment-policy-unavailable")

    def test_environment_policy_cannot_be_substituted_or_duplicated(self):
        """Wrong identity, reviewer controls and duplicate policies cannot become accepted configuration."""
        expected, initial = fixture()
        _, _, rows, policy = controller_fixture("workflow_dispatch", environment=True)
        data = copy.deepcopy(initial)
        for route, row in rows.items():
            if "/environments/" in route:
                data[route] = capability.NativeResponse(200, copy.deepcopy(row))
        for policies in ((replace(policy, environment_id=62),), (replace(policy, reviewer_ids=(11,)),),
                         (policy, policy)):
            with self.subTest(policies=policies), self.assertRaises(Failure):
                observe(expected, data, policies)

    def test_clock_rollback_or_expiry_rejects(self):
        """A stable provider snapshot cannot survive a local freshness-window violation."""
        expected, data = fixture()
        for times in ((120, 119), (120, 241)):
            with self.subTest(times=times), mock.patch.object(capability.time, "time", side_effect=times), \
                    self.assertRaisesRegex(Failure, "expired or clock rolled back"):
                observe(expected, data)


class NativeResponseTests(unittest.TestCase):
    """Strict framing and native process isolation prevent diagnostic or route-based bypasses."""

    def test_supported_success_and_error_framing(self):
        """Native success and HTTP failures retain the authenticated status without diagnostic inference."""
        for protocol in (b"HTTP/1.1", b"HTTP/2.0", b"HTTP/2"):
            for status, code in ((200, 0), (403, 1), (404, 1), (503, 1)):
                with self.subTest(protocol=protocol, status=status):
                    self.assertEqual(capability._parse_response(wire(status, protocol=protocol), code).status, status)

    def test_redirect_forged_exit_and_multiple_headers_reject(self):
        """Redirects, contradictory native outcomes and appended header blocks cannot become provider success."""
        cases = ((wire(302), 0), (wire(200), 1), (wire(403), 0), (wire(200), -9),
                 (wire(headers=b"bad-header"), 0), (wire(body=wire()), 0), (b"{}", 0),
                 (wire(body=b'{"enabled":true,"enabled":false}'), 0),
                 (wire(body=b'{"value":NaN}'), 0), (wire(body=b"[]"), 0),
                 (wire(body=b"x" * (capability.MAX_JSON + 1)), 0))
        for data, code in cases:
            with self.subTest(code=code, length=len(data)), self.assertRaises(Failure):
                capability._parse_response(data, code)

    def test_unapproved_routes_and_inherited_downloads_reject(self):
        """The capability adapter cannot invoke other APIs, URLs, secret endpoints or artifact downloads."""
        api = capability.CapabilityGhApi(Path("/never"), "test-only-token")
        with mock.patch.object(capability.subprocess, "Popen", side_effect=AssertionError("process occurred")):
            for route in ("https://api.github.com/repos/owner/repo", "repos/owner/repo/actions/runs/1",
                          "repos/owner/repo/environments/copilot", "repos/owner/repo/environments/release-signing/secrets",
                          "repos/owner/repo/immutable-releases?x=1", "repos/owner/repo/../other"):
                with self.subTest(route=route), self.assertRaises(Failure):
                    api.response(route)
            with self.assertRaises(Failure):
                api.archive("owner/repo", 1, Path("/never-written"))

    def test_native_process_is_sterile_get_only_and_discards_stderr(self):
        """A real inert child proves fixed argv, closed stdin and absence of inherited credentials or proxy/debug state."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capture, executable = root / "capture.json", root / "fake-native"
            executable.write_text("#!" + sys.executable + "\nimport json,os,sys\n"
                "from pathlib import Path\nPath(" + repr(str(capture)) + ").write_text(json.dumps({"
                "'argv':sys.argv[1:],'keys':sorted(os.environ),'stdin':sys.stdin.read(),"
                "'home_is_cwd':Path(os.environ['HOME']).resolve()==Path.cwd(),'token_present':'GH_TOKEN' in os.environ}))\n"
                "sys.stderr.write('secret-stderr-sentinel')\n"
                "sys.stdout.buffer.write(" + repr(wire(403)) + ")\nraise SystemExit(1)\n")
            executable.chmod(0o700)
            api = capability.CapabilityGhApi(executable, "test-only-token")
            with mock.patch.dict(os.environ, {"HTTP_PROXY": "secret-proxy", "GH_DEBUG": "api",
                                             "GITHUB_TOKEN": "unrelated-secret", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "secret-oidc"}), \
                    mock.patch.object(api, "_check_native") as native_check:
                result = api.response("repos/owner/repo/immutable-releases")
            native_check.assert_called_once()
            captured = json.loads(capture.read_bytes())
            self.assertEqual(result.status, 403)
            self.assertEqual(captured["argv"], ["api", "--hostname", "github.com", "--method", "GET", "--include",
                "--header", "Accept: application/vnd.github+json", "--header", "X-GitHub-Api-Version: 2022-11-28",
                "repos/owner/repo/immutable-releases"])
            self.assertEqual(captured["stdin"], "")
            self.assertTrue(captured["home_is_cwd"])
            self.assertTrue(captured["token_present"])
            for key in ("HTTP_PROXY", "GH_DEBUG", "GITHUB_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"):
                self.assertNotIn(key, captured["keys"])
            self.assertNotIn("secret-stderr-sentinel", repr(result))

    def test_real_child_output_limit_and_timeout_are_blocking(self):
        """An inert oversized or stalled native child is rejected, killed and reaped within the bound."""
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "fake-native"
            for code, reason in (("import sys; sys.stdout.buffer.write(b'x' * 5000000)", "output exceeded limit"),
                                 ("import time; time.sleep(60)", "read timed out")):
                executable.write_text("#!" + sys.executable + "\n" + code + "\n")
                executable.chmod(0o700)
                api = capability.CapabilityGhApi(executable, "test-only-token")
                api._deadline = capability.time.monotonic() + 0.5
                with self.subTest(reason=reason), mock.patch.object(api, "_check_native"), \
                        self.assertRaisesRegex(Failure, reason):
                    api.response("repos/owner/repo/immutable-releases")

    def test_exited_leader_cannot_leave_a_pipe_holding_descendant(self):
        """A descendant of an exited native leader is killed before it can perform a delayed write."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable, marker = root / "fake-native", root / "descendant-wrote"
            child = "import time; from pathlib import Path; time.sleep(1); Path(" + repr(str(marker)) + ").write_text('bad')"
            executable.write_text("#!" + sys.executable + "\nimport subprocess,sys\nsubprocess.Popen([sys.executable,'-c'," +
                                  repr(child) + "])\n")
            executable.chmod(0o700)
            api = capability.CapabilityGhApi(executable, "test-only-token")
            api._deadline = capability.time.monotonic() + 0.4
            with mock.patch.object(api, "_check_native"), self.assertRaisesRegex(Failure, "read timed out"):
                api.response("repos/owner/repo/immutable-releases")
            time.sleep(1.1)
            self.assertFalse(marker.exists())
