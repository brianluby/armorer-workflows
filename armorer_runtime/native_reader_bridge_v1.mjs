/** Internal runner-token bridge. Supported fixed composites control interpreter startup before this file loads. */
import { spawn } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const scripts = { 'artifact-writer': 'artifact-writer', 'combined-handoff': 'combined-handoff' };

/** Admit only bounded scalar platform data; never return values in errors. */
function value(name, maximum = 4096) {
  const offered = process.env[name];
  if (typeof offered !== 'string' || offered.length === 0 || offered.length > maximum || /[\x00-\x1f\x7f]/.test(offered)) {
    throw new Error('native-reader-context-unavailable');
  }
  return offered;
}

/** Receive runner-injected artifact scope only after the outer composite has fixed actual Node startup. */
export async function runNativeQualification(kind) {
  if (!Object.hasOwn(scripts, kind)) throw new Error('native-reader-kind-unsupported');
  // This check documents the fixed wrapper contract; it cannot repair an unsafe Node-first caller.
  for (const [name, expected] of Object.entries({ NODE_OPTIONS: '', NODE_EXTRA_CA_CERTS: '',
    NODE_TLS_REJECT_UNAUTHORIZED: '1', NODE_USE_ENV_PROXY: '0', LD_AUDIT: '', LD_PRELOAD: '', LD_LIBRARY_PATH: '' })) {
    if (process.env[name] !== expected) throw new Error('native-reader-fixed-wrapper-required');
  }
  const python = process.platform === 'linux' ? '/usr/bin/python3' :
    process.platform === 'darwin' && process.arch === 'arm64' ? '/opt/homebrew/bin/python3' : null;
  if (!python || !['x64', 'arm64'].includes(process.arch)) throw new Error('native-reader-platform-unsupported');
  const environment = { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C.UTF-8' };
  for (const name of ['GITHUB_REPOSITORY', 'GITHUB_REPOSITORY_ID', 'GITHUB_JOB', 'GITHUB_EVENT_NAME',
    'GITHUB_SHA', 'GITHUB_REF', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_WORKSPACE', 'GITHUB_STEP_SUMMARY',
    'GITHUB_SERVER_URL', 'GITHUB_ACTIONS', 'ACTIONS_RESULTS_URL', 'EXPECTED_HEAD', 'EXPECTED_BRANCH',
    'EXPECTED_RUNNER_LABEL', 'ARMORER_NODE_DIRECTORY', 'ARMORER_WORKFLOW_READ_TOKEN', 'ACTIONS_RUNTIME_TOKEN']) {
    environment[name] = value(name, name === 'ACTIONS_RUNTIME_TOKEN' ? 16384 : 4096);
  }
  delete process.env.ARMORER_WORKFLOW_READ_TOKEN;
  delete process.env.ACTIONS_RUNTIME_TOKEN;
  // Kind is selected by the fixed internal action. No input chooses code, an executable or a URL.
  const code = 'import sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); ' +
    'from armorer_runtime.producer_launcher_v1 import launch_native_qualification; ' +
    'launch_native_qualification(sys.argv[2],Path(sys.argv[3])/"node")';
  const child = spawn(python, ['-I', '-c', code, root, scripts[kind], environment.ARMORER_NODE_DIRECTORY],
    { env: environment, cwd: root, detached: true, stdio: ['ignore', 'pipe', 'ignore'] });
  await new Promise((resolve, reject) => {
    let size = 0;
    let failed = false;
    let grace;
    const blocks = [];
    /** Give Python time to cancel its separately owned native workers before forceful cleanup. */
    function cancel() {
      if (failed) return;
      failed = true;
      try { process.kill(-child.pid, 'SIGTERM'); } catch { /* Fixed close error below. */ }
      grace = setTimeout(function forceOwnedGroup() {
        try { process.kill(-child.pid, 'SIGKILL'); } catch { /* Close retains completion. */ }
      }, 95000);
    }
    const timer = setTimeout(cancel, 1650000);
    process.once('SIGTERM', cancel);
    child.on('error', cancel);
    child.stdout.on('error', cancel);
    child.stdout.on('data', block => {
      if (failed) return;
      size += block.length;
      if (size > 4 * 1024 * 1024 + 1) { cancel(); return; }
      blocks.push(Buffer.from(block));
    });
    child.on('close', status => {
      clearTimeout(timer);
      clearTimeout(grace);
      process.removeListener('SIGTERM', cancel);
      try { process.kill(-child.pid, 'SIGKILL'); } catch { /* Reap even after the leader exits. */ }
      if (failed || status !== 0 || size === 0) { reject(new Error('native-reader-qualification-failed')); return; }
      process.stdout.write(Buffer.concat(blocks, size));
      resolve();
    });
  });
}
