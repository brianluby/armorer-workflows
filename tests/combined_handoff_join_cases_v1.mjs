/** Synthetic integration regressions use the unchanged private writer observer, never fabricated handles. */
import assert from 'node:assert/strict';
import { observeArtifactWriters, artifactWriterRecord } from '../armorer_runtime/artifact_writer_worker_v1.mjs';
import { joinArchives } from './combined_handoff_join_v1.mjs';

const realFetch = globalThis.fetch;
const realNow = Date.now;
const now = realNow();
const iso = offset => new Date(now + offset).toISOString();
const backendRun = '10000000-0000-0000-0000-000000000001';
const backendReader = '20000000-0000-0000-0000-000000000001';
const sha = 'a'.repeat(40);
const digest = 'sha256:' + 'b'.repeat(64);
const root = 'https://api.github.com/repos/fixture/writers';
const route = root + '/actions/runs/17';
const rpc = 'https://results-receiver.actions.githubusercontent.com/twirp/github.actions.results.api.v1.ArtifactService/ListArtifacts';
let groups = 0;

/** Supply eighteen exact provider records with decimal-string ProtoJSON sizes and numeric measured byte counts. */
function fixture() {
  const artifacts = Array.from({ length: 18 }, (_, index) => ({
    name: `unsigned-${index}-17-2`, writer_job_name: `writer-${index} (ubuntu-24.04)`, writer_runner: 'ubuntu-24.04',
  }));
  const expected = { repository: 'fixture/writers', repository_id: '33', run_id: '17', run_attempt: '2',
    head_sha: sha, head_branch: 'main', event: 'workflow_dispatch', workflow_id: '37',
    workflow_path: '.github/workflows/development.yml', workflow_name: 'Native writer validation',
    reader_job_name: 'reader (ubuntu-24.04)', reader_runner: 'ubuntu-24.04', artifacts };
  const repository = { id: 33, full_name: expected.repository, fork: false };
  const run = { id: 17, run_attempt: 2, workflow_id: 37, head_sha: sha, head_branch: 'main',
    path: expected.workflow_path, name: expected.workflow_name, event: expected.event,
    status: 'in_progress', conclusion: null, repository, head_repository: repository,
    run_started_at: iso(-60000), check_suite_id: 41 };
  const job = { run_id: 17, run_attempt: 2, head_sha: sha, head_branch: 'main',
    workflow_name: expected.workflow_name, labels: ['ubuntu-24.04'], runner_id: 47, started_at: iso(-50000) };
  const reader = { ...job, id: 29, name: expected.reader_job_name, status: 'in_progress', conclusion: null,
    completed_at: null, check_run_url: root + '/check-runs/31' };
  const check = { head_sha: sha, check_suite: { id: 41 }, app: { slug: 'github-actions', id: 15368 } };
  const jobs = [reader];
  const uploads = [];
  const service = [];
  const collection = { state: 'combined-build-policy-transport-observed', qualification_only: true,
    authentication_mode: 'isolated-workflow-token', archive_bytes_verified: true, repository: expected.repository,
    repository_id: '33', head_commit: sha, run_id: '17', run_attempt: '2', artifacts: {} };
  const documents = new Map([[route, run], [route + '/attempts/2', structuredClone(run)],
    [root + '/check-runs/31', { ...check, id: 31, name: reader.name, status: 'in_progress', conclusion: null, external_id: backendReader }]]);
  for (const [index, item] of artifacts.entries()) {
    const id = 100 + index;
    const checkId = 200 + index;
    const backend = '30000000-0000-0000-0000-' + String(index + 1).padStart(12, '0');
    const writer = { ...job, id: 300 + index, name: item.writer_job_name, status: 'completed',
      conclusion: 'success', completed_at: iso(-20000), check_run_url: root + `/check-runs/${checkId}` };
    const artifact = { id, name: item.name, expired: false, size_in_bytes: 1024 + index, digest,
      workflow_run: { id: 17, repository_id: 33, head_repository_id: 33, head_sha: sha, head_branch: 'main' },
      created_at: iso(-30000), updated_at: iso(-30000), expires_at: iso(86400000) };
    jobs.push(writer);
    uploads.push(artifact);
    service.push({ workflow_run_backend_id: backendRun, workflow_job_run_backend_id: backend,
      database_id: String(id), name: item.name, size: String(artifact.size_in_bytes), digest, created_at: artifact.created_at });
    documents.set(root + `/check-runs/${checkId}`, { ...check, id: checkId, name: writer.name,
      status: 'completed', conclusion: 'success', external_id: backend });
    documents.set(root + `/actions/artifacts/${id}`, structuredClone(artifact));
    collection.artifacts[item.name] = { provider: structuredClone(artifact),
      archive: { size: artifact.size_in_bytes, sha256: digest.slice(7) } };
  }
  documents.set(route + '/attempts/2/jobs?per_page=100', { total_count: jobs.length, jobs });
  documents.set(route + '/artifacts?per_page=100', { total_count: uploads.length, artifacts: uploads });
  documents.set(rpc, { artifacts: service });
  return { expected, documents, collection, calls: [] };
}

/** Install bounded synthetic responses on the observer's exact fixed authorities without live credentials. */
function install(value) {
  process.env.GITHUB_SERVER_URL = 'https://github.com';
  process.env.GITHUB_ACTIONS = 'true';
  process.env.ACTIONS_RESULTS_URL = 'https://results-receiver.actions.githubusercontent.com/';
  process.env.ARMORER_WORKFLOW_READ_TOKEN = 'synthetic-rest-token';
  process.env.ACTIONS_RUNTIME_TOKEN = 'e30.' + Buffer.from(JSON.stringify({ scp: 'Actions.Results:' + backendRun + ':' + backendReader })).toString('base64url') + '.eA';
  const runtimeToken = process.env.ACTIONS_RUNTIME_TOKEN;
  globalThis.fetch = async (url, options) => {
    assert.equal(options.redirect, 'error');
    assert.ok(value.documents.has(url), 'Unexpected network route');
    assert.equal(options.method, url === rpc ? 'POST' : 'GET');
    assert.equal(options.headers.Authorization, 'Bearer ' + (url === rpc ? runtimeToken : 'synthetic-rest-token'));
    if (url === rpc) assert.deepEqual(JSON.parse(options.body), { workflowRunBackendId: backendRun, workflowJobRunBackendId: backendReader });
    else assert.equal(options.body, undefined);
    value.calls.push(url);
    return new Response(JSON.stringify(value.documents.get(url)), { status: 200, headers: { 'content-type': 'application/json' } });
  };
}

// This fixture action is intentionally separate from the credentialed native
// reader. Never overwrite or copy live workflow/runtime credentials in tests.
assert.equal(process.env.ARMORER_WORKFLOW_READ_TOKEN, undefined);
assert.equal(process.env.ACTIONS_RUNTIME_TOKEN, undefined);
try {
  const value = fixture();
  install(value);
  const proof = await observeArtifactWriters(value.expected);
  const writer = joinArchives(value.collection, proof);
  assert.equal(writer.snapshot.artifacts.length, 18);
  assert.equal(writer.snapshot.artifacts[0].artifact.size, '1024');
  assert.equal(value.collection.artifacts['unsigned-0-17-2'].archive.size, 1024);
  assert.equal(writer.signing_authorized, false);
  assert.equal(writer.publication_authorized, false);
  assert.equal(value.calls.filter(url => url === rpc).length, 2);
  groups += 1;
  for (const size of ['1024', 0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 9007199254740992, 1025]) {
    const copy = structuredClone(value.collection);
    copy.artifacts['unsigned-0-17-2'].archive.size = size;
    assert.throws(() => joinArchives(copy, proof), /combined-native-qualification-denied/);
    groups += 1;
  }
  for (const mutate of [
    copy => { copy.artifacts['unsigned-0-17-2'].archive.sha256 = '0'.repeat(64); },
    copy => { copy.artifacts['unsigned-0-17-2'].provider.id += 1; },
    copy => { copy.artifacts['unsigned-0-17-2'].provider.name = 'wrong'; },
    copy => { copy.artifacts['unsigned-0-17-2'].provider.created_at = iso(-35000); },
    copy => { copy.artifacts['unsigned-0-17-2'].provider.size_in_bytes += 1; },
    copy => { delete copy.artifacts['unsigned-0-17-2']; },
    copy => { copy.artifacts.extra = copy.artifacts['unsigned-0-17-2']; },
    copy => { copy.run_attempt = '3'; },
    copy => { copy.head_commit = 'c'.repeat(40); },
    copy => { copy.qualification_only = false; },
  ]) {
    const copy = structuredClone(value.collection);
    mutate(copy);
    assert.throws(() => joinArchives(copy, proof), /combined-native-qualification-denied/);
    groups += 1;
  }
  assert.throws(() => joinArchives(value.collection, { ...proof }), /artifact-writer-observation-denied/);
  assert.throws(() => joinArchives(value.collection, artifactWriterRecord(proof)), /artifact-writer-observation-denied/);
  groups += 1;
  Date.now = () => realNow() + 31000;
  assert.throws(() => joinArchives(value.collection, proof), /artifact-writer-observation-denied/);
  groups += 1;
  console.log(JSON.stringify({ state: 'synthetic-combined-writer-join-passed', groups, archive_bindings: 18,
    live_provider_authenticated: false, signing_authorized: false, publication_authorized: false }));
} finally {
  globalThis.fetch = realFetch;
  Date.now = realNow;
  for (const name of ['ARMORER_WORKFLOW_READ_TOKEN', 'ACTIONS_RUNTIME_TOKEN']) delete process.env[name];
}
