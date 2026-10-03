"""Native Node startup adversaries use only synthetic credentials and an ephemeral RSA issuer."""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from armorer_runtime import producer_launcher_v1 as launcher
from armorer_runtime.common import Failure


class ProducerStartupTests(unittest.TestCase):
    """A preload must never execute in the credentialed child or manufacture a supported parent API proof."""

    @classmethod
    def setUpClass(cls):
        """Prepare a public fixed native Node only when a qualified fixture was not independently provided."""
        offered = os.environ.get('ARMORER_TEST_NODE')
        cls.owned = None
        if offered:
            cls.node = Path(offered)
        elif os.environ.get('ARMORER_TEST_NETWORK') == '1':
            cls.owned = tempfile.TemporaryDirectory(prefix='armorer-startup-node-fixture-')
            cls.node = launcher.prepare_node(Path(cls.owned.name) / 'node')
        else:
            raise unittest.SkipTest('explicit native Node fixture or network qualification required')

    @classmethod
    def tearDownClass(cls):
        """Delete only the test-owned public tool directory after every native child has exited."""
        if cls.owned:
            cls.owned.cleanup()

    def request(self):
        """Freeze exact independent source/signer/job expectations before constructing any synthetic token."""
        return {'schema_version': 1, 'operation': 'oidc', 'intent': {
            'repository': 'fixture-owner/fixture-repo', 'repository_id': '7', 'repository_owner_id': '8',
            'repository_visibility': 'public', 'source_sha': 'a' * 40, 'ref': 'refs/heads/main',
            'event': 'workflow_dispatch', 'default_branch': 'main', 'actor': 'fixture-actor', 'actor_id': '11',
            'caller_path': '.github/workflows/release.yml', 'caller_sha': 'a' * 40,
            'signer_repository': 'brianluby/armorer-workflows', 'signer_path': '.github/workflows/release-cli.yml',
            'signer_sha': 'b' * 40, 'run_id': '17', 'run_attempt': '1', 'check_run_id': '19',
            'environment': None, 'environment_node_id': None, 'subject_mode': 'immutable', 'protected_ref': True}}

    def credentials(self):
        """Supply only fake platform credentials and the fixed hosted token-service fixture route."""
        return {
            'ACTIONS_ID_TOKEN_REQUEST_URL': 'https://pipelines.actions.githubusercontent.com/fixture/_apis/distributedtask/hubs/build/plans/fixture/jobs/fixture/idtoken?api-version=2.0',
            'ACTIONS_ID_TOKEN_REQUEST_TOKEN': 'synthetic-service-credential-no-authority',
            'ARMORER_WORKFLOW_READ_TOKEN': 'synthetic-read-token-no-authority',
        }

    def fixture(self, directory):
        """Interpose a fixed in-memory issuer then import the actual production stdin/operation entry."""
        source = launcher.ROOT
        directory.mkdir()
        driver = directory / 'producer_context_entry_v1.mjs'
        driver.write_text('''import { generateKeyPairSync, sign } from 'node:crypto';
const clock=2000000000; Date.now=()=>clock*1000;
const {publicKey,privateKey}=generateKeyPairSync('rsa',{modulusLength:2048});
const p={iss:'https://token.actions.githubusercontent.com',aud:'armorer:producer-context:v1',
sub:'repo:fixture-owner@8/fixture-repo@7:ref:refs/heads/main',repository:'fixture-owner/fixture-repo',
repository_id:'7',repository_owner:'fixture-owner',repository_owner_id:'8',repository_visibility:'public',
sha:'a'.repeat(40),ref:'refs/heads/main',ref_type:'branch',ref_protected:'true',event_name:'workflow_dispatch',
actor:'fixture-actor',actor_id:'11',workflow_ref:'fixture-owner/fixture-repo/.github/workflows/release.yml@refs/heads/main',
workflow_sha:'a'.repeat(40),job_workflow_ref:'brianluby/armorer-workflows/.github/workflows/release-cli.yml@'+'b'.repeat(40),
job_workflow_sha:'b'.repeat(40),run_id:'17',run_attempt:'1',check_run_id:'19',runner_environment:'github-hosted',
iat:clock-5,nbf:clock-5,exp:clock+295};
const input=[{alg:'RS256',typ:'JWT',kid:'fixture-key'},p].map(x=>Buffer.from(JSON.stringify(x)).toString('base64url')).join('.');
const token=input+'.'+sign('RSA-SHA256',Buffer.from(input),privateKey).toString('base64url');
globalThis.fetch=async(url,options)=>{
  const jwks=String(url)==='https://token.actions.githubusercontent.com/.well-known/jwks';
  if(jwks && Object.hasOwn(options.headers,'Authorization')) throw new Error('fixture-boundary');
  if(!jwks && options.headers.Authorization!=='Bearer synthetic-service-credential-no-authority') throw new Error('fixture-boundary');
  return new Response(JSON.stringify(jwks?{keys:[{...publicKey.export({format:'jwk'}),kid:'fixture-key',alg:'RS256',use:'sig'}]}:{value:token}));
};
await import(''' + json.dumps((source / 'producer_context_entry_v1.mjs').as_uri()) + ');\n')
        return directory

    def test_preload_cannot_read_credential_or_erase_its_own_marker(self):
        """An actual startup hook reads the fake token under direct Node but never runs under the launcher."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            driver = self.fixture(root / 'driver')
            marker = root / 'preload-read-token'
            hook = root / 'preload.cjs'
            hook.write_text("require('node:fs').writeFileSync(" + json.dumps(str(marker)) +
                ",process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN);" +
                "for(const k of ['NODE_OPTIONS','NODE_EXTRA_CA_CERTS','NODE_TLS_REJECT_UNAUTHORIZED','NODE_USE_ENV_PROXY'])delete process.env[k];\n")
            environment = {**self.credentials(), 'NODE_OPTIONS': '--require=' + str(hook),
                'NODE_USE_ENV_PROXY': '1', 'NODE_TLS_REJECT_UNAUTHORIZED': '0',
                'NODE_EXTRA_CA_CERTS': str(root / 'attacker-ca'), 'HTTP_PROXY': 'http://attacker.invalid',
                'PYTHONPATH': str(root / 'untrusted-modules'), 'LD_PRELOAD': str(root / 'untrusted.so')}
            payload = json.dumps(self.request()).encode()
            with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(launcher, 'ROOT', driver):
                observed = launcher.launch_producer_context(self.node, payload, hashlib.sha256(payload).hexdigest())
            self.assertFalse(marker.exists(), 'startup hook read the request credential')
            self.assertTrue(observed['startup_environment_isolated'])
            self.assertTrue(observed['observation']['oidc_job_identity_authenticated'])
            self.assertFalse(observed['production_node_catalog_accepted'])
            self.assertFalse(observed['signing_authorized'])
            self.assertFalse(observed['publication_authorized'])
            self.assertNotIn('synthetic-service-credential', json.dumps(observed))
            # This is an owned synthetic demonstration, never a real credential-bearing process.
            direct = {'PATH': '/usr/bin:/bin', 'NODE_OPTIONS': '--require=' + str(hook),
                'ACTIONS_ID_TOKEN_REQUEST_TOKEN': self.credentials()['ACTIONS_ID_TOKEN_REQUEST_TOKEN']}
            result = subprocess.run([str(self.node), '-e', ''], env=direct, cwd=root,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(marker.read_text(), self.credentials()['ACTIONS_ID_TOKEN_REQUEST_TOKEN'])

    def test_wrong_approval_and_node_bytes_fail_before_credentials(self):
        """Neither ambiguous policy bytes nor a substituted executable can reach the credential accessor."""
        payload = json.dumps(self.request()).encode()
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(launcher, '_credentials', side_effect=AssertionError('credential-read')):
            replacement = Path(temporary) / 'node'
            replacement.write_text('not an executable')
            with self.assertRaisesRegex(Failure, 'approval mismatch'):
                launcher.launch_producer_context(self.node, payload, '0' * 64)
            with self.assertRaisesRegex(Failure, 'native node mismatch'):
                launcher.launch_producer_context(replacement, payload, hashlib.sha256(payload).hexdigest())
            duplicate = b'{"schema_version":1,"schema_version":1}'
            with self.assertRaises(Exception):
                launcher.launch_producer_context(self.node, duplicate, hashlib.sha256(duplicate).hexdigest())

    def test_exact_credential_environment_excludes_all_startup_state(self):
        """The child receives only fixed OS paths and the credentials needed by its exact operation."""
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(os.environ,
                {**self.credentials(), 'NODE_OPTIONS': '--require=attacker', 'GH_TOKEN': 'other-fake-token',
                 'SSL_CERT_FILE': 'untrusted', 'PYTHONPATH': 'untrusted', 'HTTPS_PROXY': 'untrusted'}, clear=True):
            root = Path(temporary)
            environment = launcher._credentials('oidc', root)
            self.assertEqual(set(environment), {'PATH', 'LANG', 'HOME', 'TMPDIR',
                'ACTIONS_ID_TOKEN_REQUEST_URL', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN'})
            self.assertEqual(set(launcher._credentials('mapped', root)) - set(environment), {'ARMORER_WORKFLOW_READ_TOKEN'})

    def test_composite_boundary_fixes_interpreter_startup_before_code(self):
        """The actual action selects isolated absolute Python and never interpolates caller data into code."""
        action = launcher.ROOT.parent / '.github/actions/producer-launcher-v1/action.yml'
        text = action.read_text()
        self.assertIn("'/usr/bin/python3 -I {0}'", text)
        self.assertIn("'/opt/homebrew/bin/python3 -I {0}'", text)
        for name in ('NODE_OPTIONS', 'NODE_EXTRA_CA_CERTS', 'PYTHONPATH', 'PYTHONHOME', 'LD_PRELOAD', 'LD_AUDIT',
                     'LD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH', 'BASH_ENV', 'ENV'):
            self.assertIn('        ' + name + ": ''", text)
        body = text.split('      run: |\n', 1)[1]
        self.assertNotIn('${{', body)
        self.assertNotIn('using: node', text)
        self.assertNotIn('LD_TRACE_LOADED_OBJECTS:', text)
        self.assertIn('from armorer_runtime.producer_launcher_v1 import main', body)

    def test_unsupported_request_rejects_before_node_or_credentials(self):
        """An approved hash cannot make booleans, unknown operations or caller script fields admissible."""
        for request in ({**self.request(), 'schema_version': True}, {**self.request(), 'operation': 'shell'},
                        {**self.request(), 'script': 'untrusted'}, {**self.request(), 'intent': []}):
            payload = json.dumps(request).encode()
            with mock.patch.object(launcher, '_private_node', side_effect=AssertionError('node-read')):
                with self.assertRaisesRegex(Failure, 'independent request invalid'):
                    launcher.launch_producer_context(self.node, payload, hashlib.sha256(payload).hexdigest())

    def test_legacy_node_exports_reject_without_platform_reads(self):
        """Retired Node-first interfaces reject explicitly and cannot recreate proof objects from JSON."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            core = launcher.ROOT
            script = root / 'legacy.mjs'
            script.write_text("import assert from 'node:assert/strict';\nimport {authenticateProducerContext,producerContextRecord} from " +
                json.dumps((core / 'producer_oidc_v1.mjs').as_uri()) + ";\nimport {authenticateMappedProducerContext,mappedProducerContextRecord} from " +
                json.dumps((core / 'mapped_producer_v1.mjs').as_uri()) + ";\nimport {observeArtifactWriters,artifactWriterRecord} from " +
                json.dumps((core / 'artifact_writer_v1.mjs').as_uri()) + ";\n" +
                "process.env={get ACTIONS_ID_TOKEN_REQUEST_TOKEN(){throw new Error('must-not-read')}};\n" +
                "await assert.rejects(authenticateProducerContext({}),/oidc-startup-boundary-required/);\n" +
                "await assert.rejects(authenticateMappedProducerContext({}),/producer-context-startup-boundary-required/);\n" +
                "await assert.rejects(observeArtifactWriters({}),/artifact-writer-startup-boundary-required/);\n" +
                "assert.throws(()=>artifactWriterRecord({}),/artifact-writer-observation-denied/);\n" +
                "assert.throws(()=>producerContextRecord({}),/unverified-proof/);\nassert.throws(()=>mappedProducerContextRecord({}),/unverified-proof/);\n")
            result = subprocess.run([str(self.node), str(script)], cwd=root, env={'PATH': '/usr/bin:/bin'},
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            self.assertEqual(result.returncode, 0)

    def test_writer_qualification_never_inherits_a_preload_or_runtime_credential_hook(self):
        """The actual fixed writer worker passes all synthetic protocol groups in a sterile native child."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            core = launcher.ROOT
            driver = root / '.github/actions/qualify-artifact-writer-v1'
            driver.mkdir(parents=True)
            driver.joinpath('index.mjs').write_text("const write=process.stdout.write.bind(process.stdout);\n" +
                "process.stdout.write=s=>{const v=JSON.parse(s);v.publication_authorized=false;return write(JSON.stringify(v));};\n" +
                "await import(" + json.dumps((core.parent / 'tests/artifact_writer_v1.mjs').as_uri()) + ");\n")
            marker = root / 'writer-credential-hook'
            hook = root / 'preload.cjs'
            hook.write_text("require('node:fs').writeFileSync(" + json.dumps(str(marker)) +
                ",JSON.stringify([process.env.ARMORER_WORKFLOW_READ_TOKEN,process.env.ACTIONS_RUNTIME_TOKEN]));" +
                "for(const k of ['NODE_OPTIONS','NODE_EXTRA_CA_CERTS','NODE_TLS_REJECT_UNAUTHORIZED','NODE_USE_ENV_PROXY'])delete process.env[k];\n")
            environment = {'ARMORER_WORKFLOW_READ_TOKEN': 'synthetic-read-no-authority',
                'ACTIONS_RUNTIME_TOKEN': 'synthetic-runtime-no-authority',
                'GITHUB_REPOSITORY': 'brianluby/armorer-workflows', 'GITHUB_REPOSITORY_ID': '1398918288',
                'GITHUB_JOB': 'transport-evidence', 'GITHUB_EVENT_NAME': 'pull_request', 'GITHUB_SHA': 'a' * 40,
                'GITHUB_REF': 'refs/pull/21/merge', 'GITHUB_RUN_ID': '17', 'GITHUB_RUN_ATTEMPT': '2',
                'GITHUB_WORKSPACE': str(root), 'GITHUB_STEP_SUMMARY': str(root / 'summary'),
                'EXPECTED_HEAD': 'a' * 40, 'EXPECTED_BRANCH': 'main', 'EXPECTED_RUNNER_LABEL': 'macos-15',
                'GITHUB_SERVER_URL': 'https://github.com', 'GITHUB_ACTIONS': 'true',
                'ACTIONS_RESULTS_URL': 'https://results-receiver.actions.githubusercontent.com',
                'NODE_OPTIONS': '--require=' + str(hook), 'LD_AUDIT': 'untrusted', 'HTTPS_PROXY': 'untrusted'}
            with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(launcher, 'ROOT', root / 'armorer_runtime'):
                with mock.patch.object(launcher.sys, 'stdout') as output:
                    launcher.launch_native_qualification('artifact-writer', self.node)
                    observed = json.loads(output.buffer.write.call_args.args[0])
            self.assertFalse(marker.exists(), 'writer preload read platform credentials')
            self.assertEqual(observed['groups'], 35)
            self.assertFalse(observed['signing_authorized'])
            self.assertFalse(observed['publication_authorized'])
            direct = {'PATH': '/usr/bin:/bin', 'NODE_OPTIONS': '--require=' + str(hook),
                **{name: environment[name] for name in ('ARMORER_WORKFLOW_READ_TOKEN', 'ACTIONS_RUNTIME_TOKEN')}}
            result = subprocess.run([str(self.node), '-e', ''], env=direct, cwd=root,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(json.loads(marker.read_text()), ['synthetic-read-no-authority', 'synthetic-runtime-no-authority'])

    def test_all_reader_actions_fix_startup_before_any_credentialed_interpreter(self):
        """Actual composite reader actions prepare without credentials and allow only two fixed qualification kinds."""
        for name, kind in (('qualify-artifact-writer-v1', 'artifact-writer'), ('qualify-combined-handoff-v1', 'combined-handoff')):
            text = (launcher.ROOT.parent / '.github/actions' / name / 'action.yml').read_text()
            self.assertNotIn('using: node', text)
            self.assertNotIn('LD_TRACE_LOADED_OBJECTS:', text)
            self.assertEqual(text.count("        LD_AUDIT: ''"), 2)
            self.assertEqual(text.count("        GCONV_PATH: ''"), 2)
            self.assertIn("        ACTIONS_RUNTIME_TOKEN: ''", text.split('    - name: Run the fixed')[0])
            self.assertIn('uses: brianluby/armorer-workflows/.github/actions/native-' +
                ('artifact' if kind == 'artifact-writer' else 'combined') + '-reader-v1@', text)
            for body in text.split('      run: |\n')[1:]:
                self.assertNotIn('${{', body.split('    - name:', 1)[0])
        with mock.patch.object(launcher, '_private_node', side_effect=AssertionError('node-read')):
            with self.assertRaisesRegex(Failure, 'unsupported'):
                launcher.launch_native_qualification('caller-script', self.node)

    @unittest.skipUnless(sys.platform == 'linux', 'glibc audit execution requires a native Linux host')
    def test_linux_loader_audit_is_cleared_before_the_actual_python_interpreter(self):
        """A real owned glibc audit module reads only a fake token in the unsafe control and never in the fixed step."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / 'audit-read-token'
            module = root / 'audit.so'
            source = root / 'audit.c'
            source.write_text('#define _GNU_SOURCE\n#include <link.h>\n#include <stdlib.h>\n#include <stdio.h>\n' +
                'unsigned int la_version(unsigned int version){const char *s=getenv("ARMORER_WORKFLOW_READ_TOKEN");' +
                'if(s){FILE *f=fopen(' + json.dumps(str(marker)) + ',"w");if(f){fputs(s,f);fclose(f);}}return LAV_CURRENT;}\n')
            built = subprocess.run(['/usr/bin/cc', '-shared', '-fPIC', '-o', str(module), str(source)],
                env={'PATH': '/usr/bin:/bin'}, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=30)
            self.assertEqual(built.returncode, 0)
            environment = {'PATH': '/usr/bin:/bin', 'LD_AUDIT': str(module),
                'ARMORER_WORKFLOW_READ_TOKEN': 'synthetic-audit-no-authority'}
            result = subprocess.run(['/usr/bin/python3', '-I', '-c', 'pass'], env=environment,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(marker.read_text(), 'synthetic-audit-no-authority')
            marker.unlink()
            executed = root / 'python-executed'
            # glibc enables trace mode by presence, including the empty value.
            # A successful exit must not stand in for actual interpreter execution.
            traced = {**environment, 'LD_AUDIT': '', 'LD_TRACE_LOADED_OBJECTS': ''}
            result = subprocess.run(['/usr/bin/python3', '-I', '-c',
                'from pathlib import Path; Path(' + repr(str(executed)) + ').write_text("yes")'], env=traced,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            self.assertEqual(result.returncode, 0)
            self.assertFalse(executed.exists(), 'empty loader trace unexpectedly ran Python')
            for name in ('producer-launcher-v1', 'qualify-artifact-writer-v1', 'qualify-combined-handoff-v1'):
                text = (launcher.ROOT.parent / '.github/actions' / name / 'action.yml').read_text()
                for section in text.split('      env:\n')[1:]:
                    overrides = dict(re.findall(r"^        ([A-Z0-9_]+): '([^']*)'$", section.split('      run:', 1)[0], re.M))
                    safe = {**environment, **overrides}
                    # Reinsert only the owned fake credential; never a real platform value.
                    safe['ARMORER_WORKFLOW_READ_TOKEN'] = 'synthetic-audit-no-authority'
                    result = subprocess.run(['/usr/bin/python3', '-I', '-c', 'from pathlib import Path; Path(' + repr(str(executed)) + ').write_text("yes")'], env=safe,
                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
                    self.assertEqual(result.returncode, 0)
                    self.assertEqual(executed.read_text(), 'yes')
                    executed.unlink()
                    self.assertFalse(marker.exists(), 'audit loader ran before fixed Python startup')

    def test_exited_node_leader_cannot_leave_a_pipe_holder(self):
        """The launcher bounds stalled pipes and terminates its group after a successful leader exit."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / 'descendant-side-effect'
            code = "setTimeout(()=>require('node:fs').writeFileSync(" + json.dumps(str(marker)) + ",'bad'),1000);"
            (root / 'producer_context_entry_v1.mjs').write_text("import {spawn} from 'node:child_process';\nspawn(process.execPath,['-e'," + json.dumps(code) + "],{stdio:'inherit'});process.exit(0);\n")
            with mock.patch.object(launcher, 'ROOT', root), mock.patch.object(launcher, 'MAX_SECONDS', 0.4):
                with self.assertRaisesRegex(Failure, 'timed out'):
                    launcher._run_node(self.node, b'{}', {'PATH': '/usr/bin:/bin'}, root)
            time.sleep(1.1)
            self.assertFalse(marker.exists())

    def test_parent_cancellation_reaps_the_separate_native_child_group(self):
        """SIGTERM of the real Python launcher retains cleanup ownership and prevents its Node child's side effect."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ready, marker = root / 'child-ready', root / 'cancelled-child-side-effect'
            entry = root / 'producer_context_entry_v1.mjs'
            entry.write_text("import {writeFileSync} from 'node:fs';\nwriteFileSync(" + json.dumps(str(ready)) +
                ",String(process.pid));\nsetTimeout(()=>writeFileSync(" + json.dumps(str(marker)) + ",'bad'),1500);\n")
            code = 'import sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); from armorer_runtime import producer_launcher_v1 as m; m.ROOT=Path(sys.argv[2]); m._run_node(Path(sys.argv[3]),b"{}",{"PATH":"/usr/bin:/bin"},Path(sys.argv[2]))'
            process = subprocess.Popen([sys.executable, '-I', '-c', code, str(launcher.ROOT.parent), str(root), str(self.node)],
                env={'PATH': '/usr/bin:/bin'}, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            child = None
            try:
                deadline = time.monotonic() + 5
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(ready.exists())
                child = int(ready.read_text())
                process.send_signal(signal.SIGTERM)
                self.assertNotEqual(process.wait(timeout=10), 0)
                time.sleep(1.6)
                self.assertFalse(marker.exists(), 'cancelled parent left its credentialed child group running')
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait()
                if child:
                    try:
                        os.killpg(child, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
