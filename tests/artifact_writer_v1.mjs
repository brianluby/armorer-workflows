/** Adversarial protocol fixtures; synthetic responses never establish live provider authentication. */
import assert from 'node:assert/strict';
import { observeArtifactWriters, artifactWriterRecord } from '../armorer_runtime/artifact_writer_v1.mjs';

const realFetch = globalThis.fetch;
const realNow = Date.now;
const now = realNow();
const iso = offset => new Date(now + offset).toISOString();
const backendRun = '10000000-0000-0000-0000-000000000001';
const backendReader = '20000000-0000-0000-0000-000000000001';
const backendWriter = '30000000-0000-0000-0000-000000000001';
const sha = 'a'.repeat(40);
const digest = 'sha256:' + 'b'.repeat(64);
const root = 'https://api.github.com/repos/fixture/writers';
const runRoute = root + '/actions/runs/17';
const rpc = 'https://results-receiver.actions.githubusercontent.com/twirp/github.actions.results.api.v1.ArtifactService/ListArtifacts';
let count = 0;

/** Provide valid independent intent and consistent, distinct job/check IDs to exercise the actual join. */
function fixture() {
  const expected = { repository: 'fixture/writers', repository_id: '33', run_id: '17', run_attempt: '2',
    head_sha: sha, head_branch: 'main', event: 'workflow_dispatch', workflow_id: '37',
    workflow_path: '.github/workflows/development.yml', workflow_name: 'Native writer validation',
    reader_job_name: 'reader (ubuntu-24.04)', reader_runner: 'ubuntu-24.04',
    artifacts: [{ name: 'unsigned-17-2', writer_job_name: 'writer (ubuntu-24.04)', writer_runner: 'ubuntu-24.04' }] };
  const repository = { id: 33, full_name: expected.repository, fork: false };
  const run = { id: 17, run_attempt: 2, workflow_id: 37, head_sha: sha, head_branch: 'main',
    path: expected.workflow_path, name: expected.workflow_name, event: expected.event,
    status: 'in_progress', conclusion: null, repository, head_repository: repository,
    run_started_at: iso(-60000), check_suite_id: 41 };
  const job = { run_id: 17, run_attempt: 2, head_sha: sha, head_branch: 'main',
    workflow_name: expected.workflow_name, labels: ['ubuntu-24.04'], runner_id: 47, started_at: iso(-50000) };
  const writer = { ...job, id: 19, name: expected.artifacts[0].writer_job_name, status: 'completed',
    conclusion: 'success', completed_at: iso(-20000), check_run_url: root + '/check-runs/23' };
  const reader = { ...job, id: 29, name: expected.reader_job_name, status: 'in_progress', conclusion: null,
    completed_at: null, check_run_url: root + '/check-runs/31' };
  const check = { head_sha: sha, check_suite: { id: 41 }, app: { slug: 'github-actions', id: 15368 } };
  const artifact = { id: 55, name: 'unsigned-17-2', expired: false, size_in_bytes: 1024, digest,
    workflow_run: { id: 17, repository_id: 33, head_repository_id: 33, head_sha: sha, head_branch: 'main' },
    created_at: iso(-30000), updated_at: iso(-30000), expires_at: iso(86400000) };
  const documents = new Map([
    [runRoute, run], [runRoute + '/attempts/2', structuredClone(run)],
    [runRoute + '/attempts/2/jobs?per_page=100', { total_count: 2, jobs: [reader, writer] }],
    [root + '/check-runs/23', { ...check, id: 23, name: writer.name, status: 'completed', conclusion: 'success', external_id: backendWriter }],
    [root + '/check-runs/31', { ...check, id: 31, name: reader.name, status: 'in_progress', conclusion: null, external_id: backendReader }],
    [runRoute + '/artifacts?per_page=100', { total_count: 1, artifacts: [artifact] }],
    [root + '/actions/artifacts/55', structuredClone(artifact)],
    [rpc, { artifacts: [{ workflowRunBackendId: backendRun, workflowJobRunBackendId: backendWriter,
      databaseId: '55', name: artifact.name, size: '1024', digest, createdAt: artifact.created_at }] }],
  ]);
  return { expected, documents, calls: [], rounds: 0 };
}

/** Model only exact TLS authorities/routes and the distinct REST/runtime credentials. */
function install(value, change = () => {}) {
  for (const name of ['NODE_OPTIONS', 'NODE_EXTRA_CA_CERTS', 'NODE_TLS_REJECT_UNAUTHORIZED', 'NODE_USE_ENV_PROXY']) delete process.env[name];
  process.env.GITHUB_SERVER_URL = 'https://github.com';
  process.env.GITHUB_ACTIONS = 'true';
  process.env.ACTIONS_RESULTS_URL = 'https://results-receiver.actions.githubusercontent.com/';
  process.env.ARMORER_WORKFLOW_READ_TOKEN = 'synthetic-rest-token';
  process.env.ACTIONS_RUNTIME_TOKEN = 'e30.' + Buffer.from(JSON.stringify({ scp: 'Actions.Results:' + backendRun + ':' + backendReader })).toString('base64url') + '.eA';
  const runtimeToken = process.env.ACTIONS_RUNTIME_TOKEN;
  globalThis.fetch = async (url, options) => {
    assert.equal(options.redirect, 'error');
    assert.ok(value.documents.has(url), 'Unexpected network authority or route');
    assert.equal(options.method, url === rpc ? 'POST' : 'GET');
    assert.equal(options.headers.Authorization, 'Bearer ' + (url === rpc ? runtimeToken : 'synthetic-rest-token'));
    if (url === rpc) assert.deepEqual(JSON.parse(options.body), { workflowRunBackendId: backendRun, workflowJobRunBackendId: backendReader });
    else assert.equal(options.body, undefined);
    if (url === runRoute) value.rounds += 1;
    value.calls.push(url);
    const document = structuredClone(value.documents.get(url));
    const replacement = change(url, document, value);
    return replacement ?? new Response(JSON.stringify(document), { status: 200, headers: { 'content-type': 'application/json' } });
  };
}

/** Assert a forged provider join yields no reusable proof and only the fixed redacted error. */
async function denied(name, modify, change) {
  const value = fixture();
  install(value, change);
  modify(value);
  await assert.rejects(observeArtifactWriters(value.expected), /^Error: artifact-writer-[A-Za-z_-]+-denied$/, name);
  count += 1;
}

try {
  const value = fixture();
  install(value);
  process.env.ACTIONS_RESULTS_URL = "https://results-receiver.actions.githubusercontent.com";
  const service = value.documents.get(rpc).artifacts[0];
  for (const [name, original] of [['workflowRunBackendId', 'workflow_run_backend_id'],
    ['workflowJobRunBackendId', 'workflow_job_run_backend_id'], ['databaseId', 'database_id'], ['createdAt', 'created_at']]) {
    service[original] = service[name];
    delete service[name];
  }
  service.database_id = 55;
  service.size = 1024;
  const pending = observeArtifactWriters(value.expected);
  value.expected.artifacts[0].writer_job_name = 'attacker-changed-after-read-start';
  const proof = await pending;
  const record = artifactWriterRecord(proof);
  assert.equal(record.snapshot.artifacts[0].writer.id, '19');
  assert.equal(record.snapshot.artifacts[0].writer.check_id, '23');
  assert.equal(record.snapshot.artifacts[0].writer.backend_job_id, backendWriter);
  assert.equal(record.expected.artifacts[0].writer_job_name, 'writer (ubuntu-24.04)');
  assert.equal(value.rounds, 2);
  assert.equal(process.env.ACTIONS_RUNTIME_TOKEN, undefined);
  assert.equal(process.env.ARMORER_WORKFLOW_READ_TOKEN, undefined);
  for (const key of ['signing_authorized', 'publication_authorized', 'producer_oidc_authenticated',
    'environment_protection_authenticated', 'production_catalog_accepted', 'artifact_executed', 'payload_downloaded']) assert.equal(record[key], false);
  record.snapshot.artifacts[0].writer.backend_job_id = backendReader;
  assert.equal(artifactWriterRecord(proof).snapshot.artifacts[0].writer.backend_job_id, backendWriter);
  assert.throws(() => artifactWriterRecord({ ...proof }), /artifact-writer-observation-denied/);
  assert.throws(() => artifactWriterRecord(JSON.parse(JSON.stringify(record))), /artifact-writer-observation-denied/);
  Date.now = () => now - 1;
  assert.throws(() => artifactWriterRecord(proof), /artifact-writer-observation-denied/);
  Date.now = () => realNow() + 31000;
  assert.throws(() => artifactWriterRecord(proof), /artifact-writer-observation-denied/);
  Date.now = realNow;
  count += 1;

  await denied('wrong service origin never receives credentials', value => {
    process.env.ACTIONS_RESULTS_URL = 'https://attacker.invalid/';
    setImmediate(() => assert.equal(value.calls.length, 0));
  });
  await denied('duplicate routing scope is ambiguous', () => {
    process.env.ACTIONS_RUNTIME_TOKEN = 'e30.' + Buffer.from(JSON.stringify({ scp: ['Actions.Results:' + backendRun + ':' + backendReader,
      'Actions.Results:' + backendRun + ':' + backendReader].join(' ') })).toString('base64url') + '.eA';
  });
  await denied('caller accessors are not intent', value => Object.defineProperty(value.expected, 'run_id', { get() { throw new Error('must-not-run'); } }));
  await denied('duplicate expected artifacts', value => value.expected.artifacts.push({ ...value.expected.artifacts[0] }));
  await denied('unsafe REST integer', value => { value.documents.get(runRoute).id = 9007199254740992; });
  await denied('cross-run artifact substitution', value => { value.documents.get(runRoute + '/artifacts?per_page=100').artifacts[0].workflow_run.id = 18; });
  await denied('wrong source head', value => { value.documents.get(root + '/check-runs/23').head_sha = 'c'.repeat(40); });
  await denied('wrong check suite', value => { value.documents.get(root + '/check-runs/23').check_suite.id = 42; });
  await denied('another app cannot supply native job UUID', value => { value.documents.get(root + '/check-runs/23').app.slug = 'attacker'; });
  await denied('missing backend writer UUID', value => { value.documents.get(root + '/check-runs/23').external_id = ''; });
  await denied('reader JWT does not match independent native check', value => { value.documents.get(root + '/check-runs/31').external_id = backendWriter; });
  await denied('builder output cannot replace actual writer', value => { value.documents.get(rpc).artifacts[0].workflowJobRunBackendId = backendReader; });
  await denied('wrong backend run', value => { value.documents.get(rpc).artifacts[0].workflowRunBackendId = backendWriter; });
  await denied('wrong backend artifact ID', value => { value.documents.get(rpc).artifacts[0].databaseId = '56'; });
  await denied('ambiguous ProtoJSON aliases', value => { value.documents.get(rpc).artifacts[0].database_id = '55'; });
  await denied('lossy ProtoJSON integer is rejected', value => { value.documents.get(rpc).artifacts[0].databaseId = 9007199254740992; });
  await denied('duplicated backend artifact', value => { value.documents.get(rpc).artifacts.push({ ...value.documents.get(rpc).artifacts[0] }); });
  await denied('artifact digest changed', value => { value.documents.get(rpc).artifacts[0].digest = 'sha256:' + 'c'.repeat(64); });
  await denied('artifact size changed', value => { value.documents.get(rpc).artifacts[0].size = '1025'; });
  await denied('writer did not succeed', value => { value.documents.get(runRoute + '/attempts/2/jobs?per_page=100').jobs[1].conclusion = 'failure'; });
  await denied('ambiguous named job', value => { const list = value.documents.get(runRoute + '/attempts/2/jobs?per_page=100'); list.jobs.push({ ...list.jobs[1], id: 20 }); list.total_count += 1; });
  await denied('old job attempt', value => { value.documents.get(runRoute + '/attempts/2/jobs?per_page=100').jobs[1].run_attempt = 1; });
  await denied('pagination cannot truncate a complete set', value => { value.documents.get(runRoute + '/artifacts?per_page=100').total_count = 2; });
  await denied('detail/listing race', value => { value.documents.get(root + '/actions/artifacts/55').digest = 'sha256:' + 'c'.repeat(64); });
  await denied('second snapshot mutation', () => {}, (url, document, value) => {
    if (value.rounds === 2 && url === root + '/check-runs/23') document.external_id = backendReader;
  });
  await denied('artifact created outside writer job', value => {
    const date = iso(-55000);
    for (const path of [runRoute + '/artifacts?per_page=100', root + '/actions/artifacts/55']) {
      const doc = value.documents.get(path); (doc.artifacts?.[0] ?? doc).created_at = date;
    }
    value.documents.get(rpc).artifacts[0].createdAt = date;
  });
  await denied('expired artifact', value => { value.documents.get(runRoute + '/artifacts?per_page=100').artifacts[0].expired = true; });
  await denied('authorization denial stays redacted', () => {}, () => new Response('synthetic-secret-error', { status: 403 }));
  await denied('redirect cannot forward a credential', () => {}, () => new Response('', { status: 302, headers: { location: 'https://attacker.invalid/' } }));
  await denied('oversized provider body is rejected', () => {}, () => new Response('x', { status: 200, headers: { 'content-type': 'application/json', 'content-length': '4194305' } }));
  await denied('malformed provider body is redacted', () => {}, () => new Response('synthetic-secret-error', { status: 200, headers: { 'content-type': 'application/json' } }));
  await denied('TLS overrides are rejected before requests', value => { process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; });
  const realSetTimeout = globalThis.setTimeout;
  try {
    globalThis.setTimeout = (callback, delay, ...arguments_) => realSetTimeout(callback, Math.min(delay, 10), ...arguments_);
    await denied('provider header stall cannot extend the deadline', () => {}, () => new Promise(() => {}));
    await denied('streaming body stall cannot extend the deadline', () => {}, () => new Response(new ReadableStream({
      start(controller) { controller.enqueue(new TextEncoder().encode('{')); },
    }), { status: 200, headers: { 'content-type': 'application/json' } }));
  } finally { globalThis.setTimeout = realSetTimeout; }
  console.log(JSON.stringify({ state: 'synthetic-artifact-writer-protocol-passed', groups: count,
    live_provider_authenticated: false, payload_executed: false, signing_authorized: false }));
} finally {
  globalThis.fetch = realFetch;
  Date.now = realNow;
  for (const name of ['ARMORER_WORKFLOW_READ_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'NODE_TLS_REJECT_UNAUTHORIZED']) delete process.env[name];
}
