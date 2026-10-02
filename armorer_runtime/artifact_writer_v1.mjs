/** Join authenticated artifact-service uploader IDs to independently observed Actions jobs. */
import { createHash } from 'node:crypto';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ID = /^[1-9][0-9]{0,18}$/;
const RESULTS = 'https://results-receiver.actions.githubusercontent.com';
const RPC = '/twirp/github.actions.results.api.v1.ArtifactService/ListArtifacts';
const MAX_BYTES = 4 * 1024 * 1024;
const MAX_SECONDS = 120;
const records = new WeakMap();

/** Return only fixed errors, without provider bodies, URLs, tokens or offered values. */
function requireCondition(value, code = 'artifact-writer-observation-denied') {
  if (!value) throw new Error(code);
}

/** Keep numeric provider identities exact; reject coercion and unsafe JavaScript integers. */
function identifier(value) {
  requireCondition(typeof value === 'string' && ID.test(value) && BigInt(value) <= 9223372036854775807n);
  return value;
}

/** Convert independently observed REST integers without loss of precision. */
function restId(value) {
  requireCondition(Number.isSafeInteger(value) && value > 0);
  return identifier(String(value));
}

/** Copy only plain own data properties, so caller mutation cannot change the expected set. */
function plain(value, names) {
  requireCondition(value && Object.getPrototypeOf(value) === Object.prototype &&
    Reflect.ownKeys(value).length === names.length);
  const copy = {};
  for (const name of names) {
    const property = Object.getOwnPropertyDescriptor(value, name);
    requireCondition(property && Object.hasOwn(property, 'value'));
    copy[name] = property.value;
  }
  return copy;
}

/** Validate independent controller intent before accessing runtime credentials or the network. */
function intent(offered) {
  const value = plain(offered, ['repository', 'repository_id', 'run_id', 'run_attempt', 'head_sha',
    'head_branch', 'event', 'workflow_id', 'workflow_path', 'workflow_name', 'reader_job_name',
    'reader_runner', 'artifacts']);
  requireCondition(typeof value.repository === 'string' &&
    /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/.test(value.repository));
  for (const name of ['repository_id', 'run_id', 'run_attempt', 'workflow_id']) identifier(value[name]);
  requireCondition(typeof value.head_sha === 'string' && /^[0-9a-f]{40}$/.test(value.head_sha) &&
    ['pull_request', 'push', 'workflow_dispatch'].includes(value.event));
  for (const name of ['head_branch', 'workflow_name', 'reader_job_name']) {
    requireCondition(typeof value[name] === 'string' && value[name].length > 0 && value[name].length <= 255 &&
      !/[\x00-\x1f\x7f]/.test(value[name]));
  }
  requireCondition(typeof value.workflow_path === 'string' &&
    /^\.github\/workflows\/[A-Za-z0-9_.-]+\.ya?ml$/.test(value.workflow_path));
  requireCondition(['ubuntu-24.04', 'ubuntu-24.04-arm', 'macos-15'].includes(value.reader_runner) &&
    Array.isArray(value.artifacts) && value.artifacts.length > 0 && value.artifacts.length <= 64);
  value.artifacts = value.artifacts.map(row => {
    const item = plain(row, ['name', 'writer_job_name', 'writer_runner']);
    requireCondition(typeof item.name === 'string' && /^[A-Za-z0-9_.-]{1,255}$/.test(item.name) &&
      typeof item.writer_job_name === 'string' && item.writer_job_name.length > 0 &&
      item.writer_job_name.length <= 255 && !/[\x00-\x1f\x7f]/.test(item.writer_job_name) &&
      ['ubuntu-24.04', 'ubuntu-24.04-arm', 'macos-15'].includes(item.writer_runner));
    return item;
  }).sort((a, b) => a.name.localeCompare(b.name));
  requireCondition(new Set(value.artifacts.map(row => row.name)).size === value.artifacts.length);
  return value;
}

/** Decode routing IDs only; the artifact server authenticates this token, never this decoder. */
function runtimeScope(token) {
  requireCondition(typeof token === 'string' && token.length > 0 && token.length <= 16384 &&
    !/[\s\x00-\x1f\x7f]/.test(token));
  const parts = token.split('.');
  requireCondition(parts.length === 3 && parts.every(part => /^[A-Za-z0-9_-]+$/.test(part)));
  let value;
  try { value = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')); }
  catch { throw new Error('artifact-writer-observation-denied'); }
  requireCondition(value && typeof value.scp === 'string' && value.scp.length <= 4096);
  const scopes = value.scp.split(' ').filter(scope => scope.startsWith('Actions.Results:'));
  requireCondition(scopes.length === 1);
  const scope = scopes[0].split(':');
  requireCondition(scope.length === 3 && UUID.test(scope[1]) && UUID.test(scope[2]));
  return { workflowRunBackendId: scope[1], workflowJobRunBackendId: scope[2] };
}

/** Bound headers and streaming body through completion, with redirects and retries disabled. */
async function read(url, token, method, body, deadline) {
  requireCondition(performance.now() < deadline);
  const controller = new AbortController();
  let timer;
  let reader;
  const operation = async () => {
    const response = await fetch(url, { method, redirect: 'error', signal: controller.signal,
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json',
        'Content-Type': 'application/json', 'X-GitHub-Api-Version': '2026-03-10' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    requireCondition(response.status === 200 && response.body &&
      response.headers.get('content-type')?.startsWith('application/json'));
    const advertised = response.headers.get('content-length');
    requireCondition(advertised === null || (/^[0-9]+$/.test(advertised) && Number(advertised) <= MAX_BYTES));
    reader = response.body.getReader();
    const blocks = [];
    let size = 0;
    for (;;) {
      const block = await reader.read();
      requireCondition(performance.now() < deadline);
      if (block.done) break;
      size += block.value.byteLength;
      requireCondition(size <= MAX_BYTES);
      blocks.push(Buffer.from(block.value));
    }
    requireCondition(size > 0);
    return JSON.parse(Buffer.concat(blocks, size).toString('utf8'));
  };
  try {
    return await Promise.race([operation(), new Promise((_resolve, reject) => {
      timer = setTimeout(() => { controller.abort(); reject(new Error('artifact-writer-observation-denied')); },
        Math.min(30000, Math.max(1, deadline - performance.now())));
    })]);
  } catch { throw new Error('artifact-writer-observation-denied'); }
  finally {
    clearTimeout(timer);
    controller.abort();
    if (reader) { try { void reader.cancel().catch(() => {}); } catch { /* No proof is returned. */ } }
  }
}

/** Bind the run and current attempt to independently selected repository, source and workflow. */
function runRecord(value, expected, now) {
  requireCondition(value && restId(value.id) === expected.run_id &&
    restId(value.run_attempt) === expected.run_attempt && restId(value.workflow_id) === expected.workflow_id &&
    value.head_sha === expected.head_sha && value.head_branch === expected.head_branch &&
    value.path === expected.workflow_path && value.name === expected.workflow_name && value.event === expected.event &&
    value.status === 'in_progress' && value.conclusion === null);
  for (const name of ['repository', 'head_repository']) {
    requireCondition(value[name] && restId(value[name].id) === expected.repository_id &&
      value[name].full_name === expected.repository && value[name].fork === false);
  }
  const started = Date.parse(value.run_started_at);
  requireCondition(Number.isFinite(started) && started <= now && now - started <= 3600000);
  return { id: expected.run_id, attempt: expected.run_attempt, started_at: value.run_started_at,
    check_suite_id: restId(value.check_suite_id) };
}

/** Select one exact named hosted job; reader active, every artifact writer completed successfully. */
function jobRecord(jobs, name, runner, expected, reader) {
  const matches = jobs.filter(job => job.name === name);
  requireCondition(matches.length === 1);
  const job = matches[0];
  const id = restId(job.id);
  requireCondition(restId(job.run_id) === expected.run_id && restId(job.run_attempt) === expected.run_attempt &&
    job.head_sha === expected.head_sha && job.head_branch === expected.head_branch &&
    job.workflow_name === expected.workflow_name && Array.isArray(job.labels) &&
    job.labels.length === 1 && job.labels[0] === runner && Number.isSafeInteger(job.runner_id) && job.runner_id > 0 &&
    job.status === (reader ? 'in_progress' : 'completed') && job.conclusion === (reader ? null : 'success'));
  const match = typeof job.check_run_url === 'string' && job.check_run_url.match(
    /^https:\/\/api\.github\.com\/repos\/([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)\/check-runs\/([1-9][0-9]*)$/);
  requireCondition(match && match[1] === expected.repository);
  return { id, check_id: identifier(match[2]), name, runner, started_at: job.started_at,
    completed_at: job.completed_at };
}

/** Require native Actions ownership and exact check identity before using the integrator reference. */
function checkRecord(value, job, run, expected, reader) {
  requireCondition(value && restId(value.id) === job.check_id && value.name === job.name &&
    value.head_sha === expected.head_sha && value.check_suite &&
    restId(value.check_suite.id) === run.check_suite_id && value.app?.slug === 'github-actions' && value.app.id === 15368 &&
    value.status === (reader ? 'in_progress' : 'completed') && value.conclusion === (reader ? null : 'success') &&
    typeof value.external_id === 'string' && UUID.test(value.external_id));
  return { ...job, backend_job_id: value.external_id };
}

/** Whitelist a nonexpired exact run artifact; its offered content is never read or executed. */
function artifactRecord(value, expected, name, run, now) {
  requireCondition(value && value.name === name && value.expired === false &&
    Number.isSafeInteger(value.size_in_bytes) && value.size_in_bytes > 0 && value.size_in_bytes <= 1073741824 &&
    typeof value.digest === 'string' && /^sha256:[0-9a-f]{64}$/.test(value.digest) &&
    value.workflow_run && restId(value.workflow_run.id) === expected.run_id &&
    restId(value.workflow_run.repository_id) === expected.repository_id &&
    restId(value.workflow_run.head_repository_id) === expected.repository_id &&
    value.workflow_run.head_sha === expected.head_sha && value.workflow_run.head_branch === expected.head_branch);
  const created = Date.parse(value.created_at);
  const updated = Date.parse(value.updated_at);
  const expires = Date.parse(value.expires_at);
  requireCondition(Number.isFinite(created) && Number.isFinite(updated) && Number.isFinite(expires) &&
    created >= Date.parse(run.started_at) && created <= updated && updated <= now && expires > now);
  return { id: restId(value.id), name, size: String(value.size_in_bytes), digest: value.digest,
    created_at: value.created_at, updated_at: value.updated_at, expires_at: value.expires_at };
}

/** Join one full provider snapshot through artifact IDs and service-reported uploader backend IDs. */
async function snapshot(expected, scope, token, runtimeToken, deadline) {
  const base = `https://api.github.com/repos/${expected.repository}`;
  const route = `${base}/actions/runs/${expected.run_id}`;
  const get = path => read(path, token, 'GET', undefined, deadline);
  const now = Date.now();
  const run = runRecord(await get(route), expected, now);
  requireCondition(JSON.stringify(runRecord(await get(`${route}/attempts/${expected.run_attempt}`), expected, now)) ===
    JSON.stringify(run));
  const listedJobs = await get(`${route}/attempts/${expected.run_attempt}/jobs?per_page=100`);
  requireCondition(listedJobs && Number.isSafeInteger(listedJobs.total_count) &&
    Array.isArray(listedJobs.jobs) && listedJobs.jobs.length === listedJobs.total_count &&
    listedJobs.total_count > 0 && listedJobs.total_count <= 100 &&
    new Set(listedJobs.jobs.map(job => restId(job.id))).size === listedJobs.jobs.length);
  const reader = jobRecord(listedJobs.jobs, expected.reader_job_name, expected.reader_runner, expected, true);
  const mappedReader = checkRecord(await get(`${base}/check-runs/${reader.check_id}`), reader, run, expected, true);
  requireCondition(mappedReader.backend_job_id === scope.workflowJobRunBackendId);
  const listing = await get(`${route}/artifacts?per_page=100`);
  requireCondition(listing && Array.isArray(listing.artifacts) &&
    listing.total_count === expected.artifacts.length && listing.artifacts.length === listing.total_count &&
    new Set(listing.artifacts.map(item => item.name)).size === listing.total_count &&
    new Set(listing.artifacts.map(item => restId(item.id))).size === listing.total_count);
  const results = await read(RESULTS + RPC, runtimeToken, 'POST', scope, deadline);
  requireCondition(results && Array.isArray(results.artifacts) && results.artifacts.length === listing.total_count);
  const joined = [];
  const used = new Set();
  const writers = new Map();
  for (const item of expected.artifacts) {
    let writer = writers.get(item.writer_job_name);
    if (writer) requireCondition(writer.runner === item.writer_runner);
    else {
      const job = jobRecord(listedJobs.jobs, item.writer_job_name, item.writer_runner, expected, false);
      writer = checkRecord(await get(`${base}/check-runs/${job.check_id}`), job, run, expected, false);
      writers.set(item.writer_job_name, writer);
    }
    requireCondition(writer.backend_job_id !== mappedReader.backend_job_id);
    const matches = listing.artifacts.filter(value => value.name === item.name);
    requireCondition(matches.length === 1);
    const artifact = artifactRecord(matches[0], expected, item.name, run, Date.now());
    requireCondition(JSON.stringify(artifactRecord(await get(`${base}/actions/artifacts/${artifact.id}`),
      expected, item.name, run, Date.now())) === JSON.stringify(artifact));
    const backend = results.artifacts.filter(value => value.databaseId === artifact.id);
    requireCondition(backend.length === 1 && !used.has(artifact.id));
    used.add(artifact.id);
    const value = backend[0];
    for (const [field, wanted] of [['workflowRunBackendId', scope.workflowRunBackendId],
      ['workflowJobRunBackendId', writer.backend_job_id], ['name', artifact.name],
      ['size', artifact.size], ['digest', artifact.digest]]) {
      requireCondition(value[field] === wanted, `artifact-writer-service-${field}-denied`);
    }
    // REST exposes whole seconds; retain the service precision while comparing that same second.
    requireCondition(typeof value.createdAt === 'string' && Number.isFinite(Date.parse(value.createdAt)) &&
      Math.floor(Date.parse(value.createdAt) / 1000) === Math.floor(Date.parse(artifact.created_at) / 1000),
      'artifact-writer-service-createdAt-denied');
    const created = Date.parse(artifact.created_at);
    requireCondition(Number.isFinite(Date.parse(writer.started_at)) &&
      Number.isFinite(Date.parse(writer.completed_at)) && created >= Date.parse(writer.started_at) &&
      created <= Date.parse(writer.completed_at));
    joined.push({ artifact, writer, service_created_at: value.createdAt });
  }
  requireCondition(new Set([...writers.values()].map(writer => writer.backend_job_id)).size === writers.size);
  return { run, reader: mappedReader, backend_run_id: scope.workflowRunBackendId, artifacts: joined };
}

/** Read twice from fixed HTTPS authorities; return only a process-local observation handle. */
export async function observeArtifactWriters(offered) {
  const expected = intent(offered);
  requireCondition(process.env.GITHUB_SERVER_URL === 'https://github.com' &&
    process.env.ACTIONS_RESULTS_URL === RESULTS + '/' && process.env.GITHUB_ACTIONS === 'true' &&
    !['NODE_OPTIONS', 'NODE_EXTRA_CA_CERTS', 'NODE_TLS_REJECT_UNAUTHORIZED', 'NODE_USE_ENV_PROXY']
      .some(name => process.env[name] !== undefined));
  const token = process.env.ARMORER_WORKFLOW_READ_TOKEN;
  const runtimeToken = process.env.ACTIONS_RUNTIME_TOKEN;
  delete process.env.ARMORER_WORKFLOW_READ_TOKEN;
  delete process.env.ACTIONS_RUNTIME_TOKEN;
  requireCondition(typeof token === 'string' && token.length > 0 && token.length <= 4096 &&
    !/[\s\x00-\x1f\x7f]/.test(token));
  const scope = runtimeScope(runtimeToken);
  const deadline = performance.now() + MAX_SECONDS * 1000;
  const started = Date.now();
  const before = await snapshot(expected, scope, token, runtimeToken, deadline);
  const after = await snapshot(expected, scope, token, runtimeToken, deadline);
  const canonical = JSON.stringify(before);
  requireCondition(Date.now() >= started && performance.now() < deadline && canonical === JSON.stringify(after));
  const proof = Object.freeze({});
  records.set(proof, { expected, snapshot: after,
    snapshot_sha256: createHash('sha256').update(canonical).digest('hex'), observed_at: Date.now() });
  return proof;
}

/** Export a fresh credential-free audit record; JSON and copied handles cannot restore this observation. */
export function artifactWriterRecord(proof) {
  const value = records.get(proof);
  requireCondition(value && Date.now() >= value.observed_at && Date.now() - value.observed_at <= 30000);
  return structuredClone({ schema_version: 1, state: 'artifact-writer-mapping-observed', ...value,
    artifact_writer_mapping_observed: true, payload_downloaded: false, artifact_executed: false,
    producer_oidc_authenticated: false, environment_protection_authenticated: false,
    production_catalog_accepted: false, signing_authorized: false, publication_authorized: false });
}
