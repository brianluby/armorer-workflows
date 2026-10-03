/** Join actual native archive reads and run-bound uploader observations in a nonproduction rehearsal. */
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, rm, readFile, appendFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { observeArtifactWriters } from '../armorer_runtime/artifact_writer_worker_v1.mjs';
import { joinArchives } from './combined_handoff_join_v1.mjs';
import { fixedWorkerFailureDecoder } from './combined_handoff_diagnostics_v1.mjs';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
let failure = Object.freeze({ phase: 'collector-context', code: 'unclassified' });
const platforms = {
  'ubuntu-24.04': { platform: 'linux', arch: 'x64', python: '/usr/bin/python3', target: 'x86_64-unknown-linux-gnu' },
  'ubuntu-24.04-arm': { platform: 'linux', arch: 'arm64', python: '/usr/bin/python3', target: 'aarch64-unknown-linux-gnu' },
  'macos-15': { platform: 'darwin', arch: 'arm64', python: '/opt/homebrew/bin/python3', target: 'aarch64-apple-darwin' },
};

/** Reject qualification contexts before any ephemeral credential or native worker is used. */
function requireCondition(value) {
  if (!value) throw new Error('combined-native-qualification-denied');
}

/** Run only the fixed owned Python qualification with bounded pipes and a sterile read-only environment. */
async function collect() {
  const native = platforms[process.env.EXPECTED_RUNNER_LABEL];
  requireCondition(native && native.platform === process.platform && native.arch === process.arch &&
    process.env.GITHUB_JOB === 'collect' && process.env.GITHUB_REPOSITORY === 'brianluby/armorer-workflows' &&
    process.env.GITHUB_REPOSITORY_ID === '1398918288');
  const scratch = await mkdtemp(join(tmpdir(), 'armorer-combined-reader-'));
  const diagnostics = fixedWorkerFailureDecoder();
  failure = Object.freeze({ phase: 'worker-no-coded-error', code: 'unclassified' });
  let child;
  try {
    const output = await new Promise((resolve, reject) => {
      let size = 0;
      const blocks = [];
      let failed = false;
      let grace;
      /** Cancel cooperatively; existing native reads are bounded and retain their own reaping guards. */
      function fail() {
        if (failed) return;
        failed = true;
        if (child?.pid) {
          try { process.kill(-child.pid, 'SIGTERM'); } catch { /* Close owns the fixed error. */ }
          /** Terminate only an unresponsive owned worker after bounded native cleanup time. */
          grace = setTimeout(function killUnresponsiveWorker() {
            try { process.kill(-child.pid, 'SIGKILL'); } catch { /* Close owns completion. */ }
          }, 75000);
        }
      }
      process.once('SIGTERM', fail);
      const environment = { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C.UTF-8', HOME: scratch, TMPDIR: scratch };
      for (const name of ['ARMORER_WORKFLOW_READ_TOKEN', 'GITHUB_REPOSITORY', 'GITHUB_REPOSITORY_ID', 'GITHUB_JOB',
        'GITHUB_EVENT_NAME', 'GITHUB_SHA', 'GITHUB_REF', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'EXPECTED_HEAD', 'EXPECTED_BRANCH']) {
        requireCondition(typeof process.env[name] === 'string' && process.env[name].length > 0);
        environment[name] = process.env[name];
      }
      child = spawn(native.python, ['-I', '-c',
        'import sys; sys.path.insert(0,sys.argv.pop()); sys.path.insert(0,sys.argv.pop()); from combined_handoff_cases_v1 import main; main()',
        join(process.env.GITHUB_WORKSPACE, 'source'), join(process.env.GITHUB_WORKSPACE, 'producer-runtime'),
        join(root, 'tests'), root], { cwd: scratch, env: environment, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
      const timer = setTimeout(fail, 1200000);
      child.on('error', fail);
      child.stdout.on('error', fail);
      child.stderr.on('error', fail);
      child.stderr.on('data', diagnostics.push);
      child.stdout.on('data', block => {
        if (failed) return;
        size += block.length;
        if (size > 4 * 1024 * 1024) { fail(); return; }
        blocks.push(Buffer.from(block));
      });
      child.on('close', status => {
        process.removeListener('SIGTERM', fail);
        clearTimeout(timer);
        clearTimeout(grace);
        const diagnostic = diagnostics.snapshot();
        if (failed || status !== 0 || size === 0 || diagnostics.hasFailure()) {
          failure = diagnostic;
          reject(new Error('combined-native-qualification-denied'));
          return;
        }
        resolve(Buffer.concat(blocks, size));
      });
    });
    failure = Object.freeze({ phase: 'worker-output', code: 'metadata-decode' });
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(output));
  } finally {
    if (child && child.exitCode === null && child.signalCode === null) {
      try { process.kill(-child.pid, 'SIGKILL'); } catch { /* No successful result is returned. */ }
    }
    await rm(scratch, { recursive: true, force: true });
  }
}

/** Derive all eighteen uploader jobs from the fixed reviewed rehearsal shape, never offered artifact names. */
function writerIntent(collection) {
  const run = process.env.GITHUB_RUN_ID;
  const attempt = process.env.GITHUB_RUN_ATTEMPT;
  const artifacts = [];
  for (const [runner, platform] of Object.entries(platforms)) {
    for (const [id, feature] of [['rehearsal-library', 'minimal'], ['rehearsal-cli', 'minimal'], ['rehearsal-service', 'json']]) {
      const key = `${id}--${platform.target}--${feature}`;
      artifacts.push({ name: `${key}-handoff-v3-run-${run}-attempt-${attempt}`,
        writer_job_name: `build / build (${key}, ${runner})`, writer_runner: runner });
      artifacts.push({ name: `policy-v1-${key}-${run}-${attempt}`,
        writer_job_name: `policy / verify (${key}, ${runner})`, writer_runner: runner });
    }
  }
  return { repository: 'brianluby/armorer-workflows', repository_id: '1398918288', run_id: run, run_attempt: attempt,
    head_sha: process.env.EXPECTED_HEAD, head_branch: process.env.EXPECTED_BRANCH, event: process.env.GITHUB_EVENT_NAME,
    workflow_id: collection.workflow_id, workflow_path: '.github/workflows/rehearsal-combined-v1.yml',
    workflow_name: 'Unsigned combined producer handoff rehearsal', reader_job_name: `collect (${process.env.EXPECTED_RUNNER_LABEL})`,
    reader_runner: process.env.EXPECTED_RUNNER_LABEL, artifacts };
}

try {
  const collection = await collect();
  failure = Object.freeze({ phase: 'writer-observer', code: 'unclassified' });
  const proof = await observeArtifactWriters(writerIntent(collection));
  failure = Object.freeze({ phase: 'archive-writer-join', code: 'invariant-rejected' });
  const writer = joinArchives(collection, proof);
  // The real private proof remains required for this live negative join. Mutating
  // copied archive audit data cannot change the authenticated provider digest.
  const tampered = structuredClone(collection);
  Object.values(tampered.artifacts)[0].archive.sha256 = '0'.repeat(64);
  let rejected = false;
  try { joinArchives(tampered, proof); } catch { rejected = true; }
  failure = Object.freeze({ phase: 'negative-archive-join', code: 'invariant-rejected' });
  requireCondition(rejected);
  collection.actual_writer_archive_bindings = writer.snapshot.artifacts;
  collection.writer_archive_bindings_verified = true;
  collection.tampered_archive_join_rejected_with_real_writer_proof = true;
  collection.native_node_version = process.version;
  failure = Object.freeze({ phase: 'qualification-source-read', code: 'io-unclassified' });
  for (const relative of ['tests/combined_handoff_cases_v1.mjs', 'tests/combined_handoff_join_v1.mjs',
    'tests/combined_handoff_diagnostics_v1.mjs',
    'armorer_runtime/artifact_writer_worker_v1.mjs',
    '.github/actions/qualify-combined-handoff-v1/index.mjs', '.github/actions/qualify-combined-handoff-v1/action.yml']) {
    const bytes = await readFile(join(root, relative));
    collection.qualification_sources[relative] = { sha256: createHash('sha256').update(bytes).digest('hex'), size: bytes.length };
  }
  console.log(JSON.stringify(collection));
  failure = Object.freeze({ phase: 'qualification-summary', code: 'io-unclassified' });
  await appendFile(process.env.GITHUB_STEP_SUMMARY,
    '\nCombined handoff qualification: 18 actual build/policy archives, nine complete semantic pairs and 18 uploader bindings verified. PR refs remain unsupported for the final release layout; unsigned Apple finalization remains required. No OIDC, signing or publication authority.\n');
} catch {
  console.error(`combined-native-qualification-failed:${failure.phase}:${failure.code}`);
  process.exitCode = 1;
}
