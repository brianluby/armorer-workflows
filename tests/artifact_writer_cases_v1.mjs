/** Qualify real cross-job uploader mappings for the exact three existing policy artifacts. */
import { createHash } from 'node:crypto';
import { readFile, appendFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { observeArtifactWriters, artifactWriterRecord } from '../armorer_runtime/artifact_writer_worker_v1.mjs';

/** Reject unsupported qualification contexts before reading tokens or calling a provider. */
function expected() {
  if (process.env.GITHUB_REPOSITORY !== 'brianluby/armorer-workflows' ||
    process.env.GITHUB_REPOSITORY_ID !== '1398918288' || process.env.GITHUB_JOB !== 'transport-evidence' ||
    !['ubuntu-24.04', 'ubuntu-24.04-arm', 'macos-15'].includes(process.env.EXPECTED_RUNNER_LABEL)) {
    throw new Error('artifact-writer-qualification-context-denied');
  }
  const run = process.env.GITHUB_RUN_ID;
  const attempt = process.env.GITHUB_RUN_ATTEMPT;
  return { repository: 'brianluby/armorer-workflows', repository_id: '1398918288',
    run_id: run, run_attempt: attempt, head_sha: process.env.EXPECTED_HEAD,
    head_branch: process.env.EXPECTED_BRANCH, event: process.env.GITHUB_EVENT_NAME, workflow_id: '371830961',
    workflow_path: '.github/workflows/development.yml', workflow_name: 'Workflow runtime validation',
    reader_job_name: `transport-evidence (${process.env.EXPECTED_RUNNER_LABEL})`,
    reader_runner: process.env.EXPECTED_RUNNER_LABEL,
    artifacts: ['ubuntu-24.04', 'ubuntu-24.04-arm', 'macos-15'].map(runner => ({
      name: `policy-native-v1-${runner}-${run}-${attempt}`, writer_job_name: `policy-evidence (${runner})`,
      writer_runner: runner })) };
}

try {
  const record = artifactWriterRecord(await observeArtifactWriters(expected()));
  record.qualification_only = true;
  record.native_node_version = process.version;
  record.qualification_sources = {};
  for (const relative of ['../armorer_runtime/artifact_writer_worker_v1.mjs', './artifact_writer_cases_v1.mjs',
    '../.github/actions/qualify-artifact-writer-v1/index.mjs', '../.github/actions/qualify-artifact-writer-v1/action.yml']) {
    const bytes = await readFile(fileURLToPath(new URL(relative, import.meta.url)));
    record.qualification_sources[relative] = { sha256: createHash('sha256').update(bytes).digest('hex'), size: bytes.length };
  }
  console.log(JSON.stringify(record));
  await appendFile(process.env.GITHUB_STEP_SUMMARY,
    '\nNative artifact writer mapping v1: all three provider uploader IDs joined to exact successful native jobs. Signing and publication remain unauthorized.\n');
} catch (error) {
  console.error('artifact-writer-native-qualification-failed');
  if (['artifact-writer-observation-denied', ...['workflowRunBackendId', 'workflowJobRunBackendId',
    'name', 'size', 'digest', 'createdAt'].map(name => `artifact-writer-service-${name}-denied`),
    ...['shape', 'workflowRunBackendId', 'workflowJobRunBackendId', 'databaseId', 'name', 'size', 'digest', 'createdAt']
      .map(name => `artifact-writer-service-wire-${name}-denied`),
    ...['run', 'jobs', 'reader', 'listing', 'service', 'writer', 'artifact', 'join'].map(name => `artifact-writer-phase-${name}-denied`),
    ...['NODE_OPTIONS', 'NODE_EXTRA_CA_CERTS', 'NODE_TLS_REJECT_UNAUTHORIZED', 'NODE_USE_ENV_PROXY'].map(name => `artifact-writer-environment-${name}-denied`),
    'artifact-writer-platform-context-denied', 'artifact-writer-results-origin-denied'].includes(error.message)) {
    console.error(error.message);
  }
  process.exitCode = 1;
}
