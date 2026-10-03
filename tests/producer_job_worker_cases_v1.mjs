/** Qualify fixed worker/Python paths with actual read-only APIs; PR data cannot create an OIDC producer proof. */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, appendFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const label = process.env.EXPECTED_RUNNER_LABEL;
const hosts = {
  'ubuntu-24.04': ['linux', 'x64', '/usr/bin/python3'],
  'ubuntu-24.04-arm': ['linux', 'arm64', '/usr/bin/python3'],
  'macos-15': ['darwin', 'arm64', '/opt/homebrew/bin/python3'],
};
const host = hosts[label];
assert.ok(host && host[0] === process.platform && host[1] === process.arch);
assert.equal(process.env.GITHUB_REPOSITORY, 'brianluby/armorer-workflows');
assert.equal(process.env.GITHUB_REPOSITORY_ID, '1398918288');
assert.equal(process.env.GITHUB_EVENT_NAME, 'pull_request');
assert.equal(process.env.GITHUB_ACTOR_ID, '3779002');
assert.equal(process.env.GITHUB_ACTOR, 'brianluby');
assert.equal(process.env.EXPECTED_TRIGGERING_ACTOR, 'brianluby');
assert.equal(process.env.GITHUB_WORKFLOW_SHA, process.env.GITHUB_SHA);
assert.equal(process.env.GITHUB_WORKFLOW, 'Workflow runtime validation');
assert.equal(process.env.GITHUB_JOB, 'transport-evidence');
const pull = /^refs\/pull\/([1-9][0-9]*)\/merge$/.exec(process.env.GITHUB_REF);
assert.ok(pull);
const callerPath = '.github/workflows/development.yml';
const caller = await readFile(join(process.env.GITHUB_WORKSPACE, callerPath));
const expected = { source: {
  repository: 'brianluby/armorer-workflows', repository_id: '1398918288', owner_id: '3779002', default_branch: 'main',
  run_id: process.env.GITHUB_RUN_ID, run_attempt: process.env.GITHUB_RUN_ATTEMPT, workflow_id: '371830961',
  caller_path: callerPath, caller_commit: process.env.GITHUB_WORKFLOW_SHA,
  caller_sha256: createHash('sha256').update(caller).digest('hex'), head_commit: process.env.EXPECTED_HEAD,
  source_commit: process.env.GITHUB_SHA, head_branch: process.env.GITHUB_HEAD_REF,
  event: 'pull_request', ref: process.env.GITHUB_REF, actor_id: '3779002', actor_login: 'brianluby',
  triggering_actor_id: '3779002', triggering_actor_login: 'brianluby', referenced_workflows: [],
  pull_request: pull[1], base_commit: process.env.EXPECTED_BASE, base_branch: process.env.GITHUB_BASE_REF, max_age_seconds: 3600,
}, workflow_name: 'Workflow runtime validation', job_name: `transport-evidence (${label})`,
runner_label: label, qualification_only: true, environment: null };
const scratch = await mkdtemp(join(tmpdir(), 'armorer-worker-native-qualification-'));
let result;
try {
  const environment = { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C.UTF-8', HOME: scratch, TMPDIR: scratch };
  const python = spawnSync(host[2], ['-I', '-c', 'import json,sys; print(json.dumps(list(sys.version_info[:3])))'], {
    cwd: scratch, env: environment, stdio: ['ignore', 'pipe', 'ignore'], timeout: 10000, maxBuffer: 1024,
  });
  assert.equal(python.status, 0, 'fixed Python runtime unavailable');
  const version = JSON.parse(python.stdout);
  assert.ok(version[0] === 3 && version[1] >= 11, 'fixed Python runtime unsupported');
  const observed = spawnSync(host[2], ['-I', '-c',
    'import sys; sys.path.insert(0,sys.argv.pop()); from armorer_runtime.producer_job_worker_v1 import main; main()', root], {
    cwd: scratch, env: { ...environment, ARMORER_WORKFLOW_READ_TOKEN: process.env.ARMORER_WORKFLOW_READ_TOKEN },
    input: JSON.stringify(expected), stdio: ['pipe', 'pipe', 'ignore'], timeout: 240000,
    killSignal: 'SIGTERM', maxBuffer: 65536,
  });
  assert.equal(observed.status, 0, 'fixed native worker failed');
  result = JSON.parse(observed.stdout);
  assert.equal(result.candidate_qualification_only, true);
  assert.equal(result.source_provider_authenticated, true);
  assert.equal(result.current_job_mapping_observed, true);
  assert.equal(result.producer_job_authenticated, false);
  assert.equal(result.environment_protection_authenticated, false);
  assert.equal(result.signing_authorized, false);
  assert.equal(result.publication_authorized, false);
  assert.equal(result.job.name, expected.job_name);
  result.worker_qualification = { node: process.version, fixed_python: host[2], python_version: version,
    oidc_requested: false, platform: process.platform, arch: process.arch, sources: {} };
  for (const relative of ['armorer_runtime/producer_job_worker_v1.py', 'armorer_runtime/source_transport_v1.py',
    'armorer_runtime/controller_context_v1.py', 'tests/producer_job_worker_cases_v1.mjs']) {
    const bytes = await readFile(join(root, relative));
    result.worker_qualification.sources[relative] = { size: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') };
  }
} finally {
  await rm(scratch, { recursive: true, force: true });
}
console.log(JSON.stringify({ fixed_worker_native_qualification: result }));
await appendFile(process.env.GITHUB_STEP_SUMMARY,
  '### Fixed worker native qualification\n\n```json\n' + JSON.stringify(result, null, 2) + '\n```\n');
