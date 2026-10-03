/** Synthetic issuer/native protocol joins: real RSA and owned subprocesses, never live producer authority. */
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import { generateKeyPairSync, sign } from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';
import { access } from 'node:fs/promises';
import { inspect } from 'node:util';
import { afterEach, beforeEach, test } from 'node:test';
import { authenticateMappedProducerContext, mappedProducerContextRecord } from '../armorer_runtime/mapped_producer_v1.mjs';

const CLOCK = 2000000000;
const ISSUER = 'https://token.actions.githubusercontent.com';
const SERVICE = 'https://pipelines.actions.githubusercontent.com/fixture/_apis/distributedtask/hubs/build/plans/fixture/jobs/fixture/idtoken?api-version=2.0';
const AUDIENCE = 'armorer:producer-context:v1';
const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const foreign = generateKeyPairSync('rsa', { modulusLength: 2048 });
const originals = { fetch: globalThis.fetch, clock: Date.now, spawn: childProcess.spawn };
const transportNames = ['NODE_OPTIONS', 'NODE_EXTRA_CA_CERTS', 'NODE_TLS_REJECT_UNAUTHORIZED', 'NODE_USE_ENV_PROXY'];
const envNames = ['ACTIONS_ID_TOKEN_REQUEST_URL', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'ARMORER_WORKFLOW_READ_TOKEN',
  'APPLE_CERTIFICATE', 'GH_TOKEN', 'GH_DEBUG', 'HTTP_PROXY', 'PYTHONPATH', ...transportNames];
const originalEnvironment = new Map(envNames.map(name => [name, process.env[name]]));
const target = process.platform === 'darwin' ? {
  label: 'macos-15', python: '/opt/homebrew/bin/python3', name: 'aarch64-apple-darwin', size: 39834784,
  digest: '8a4258433c81106343144857750316241759d06dcf16265cf3c4864a8f2f2ad6',
} : process.arch === 'arm64' ? {
  label: 'ubuntu-24.04-arm', python: '/usr/bin/python3', name: 'aarch64-unknown-linux-gnu', size: 39059616,
  digest: '93308395c2d296a63a662742c6366e4db413d2a4870d07bd9b84e491c065d65d',
} : {
  label: 'ubuntu-24.04', python: '/usr/bin/python3', name: 'x86_64-unknown-linux-gnu', size: 42086560,
  digest: '7469124f706944133d6a169691dd1c6c3511b12e85878d255e044e2948df4c9b',
};
let scenario;

/** Construct independent source/job and issuer expectations without an offered check-run identity. */
function intent() {
  return { mapping: { source: {
    repository: 'fixture-owner/fixture-repo', repository_id: '7', owner_id: '8', default_branch: 'main',
    run_id: '17', run_attempt: '1', workflow_id: '23', caller_path: '.github/workflows/release.yml',
    caller_commit: 'a'.repeat(40), caller_sha256: 'c'.repeat(64), head_commit: 'a'.repeat(40), source_commit: 'a'.repeat(40),
    head_branch: 'main', event: 'workflow_dispatch', ref: 'refs/heads/main', actor_id: '11', actor_login: 'fixture-actor',
    triggering_actor_id: '11', triggering_actor_login: 'fixture-actor',
    referenced_workflows: [[`brianluby/armorer-workflows/.github/workflows/release-cli.yml@${'b'.repeat(40)}`, 'b'.repeat(40)]],
    pull_request: null, base_commit: null, base_branch: null, max_age_seconds: 3600,
  }, workflow_name: 'Release workflow', job_name: 'trusted finalizer (native)', runner_label: target.label,
  qualification_only: false, environment: null }, oidc: {
    repository: 'fixture-owner/fixture-repo', repository_id: '7', repository_owner_id: '8', repository_visibility: 'public',
    source_sha: 'a'.repeat(40), ref: 'refs/heads/main', event: 'workflow_dispatch', default_branch: 'main',
    actor: 'fixture-actor', actor_id: '11', caller_path: '.github/workflows/release.yml', caller_sha: 'a'.repeat(40),
    signer_repository: 'brianluby/armorer-workflows', signer_path: '.github/workflows/release-cli.yml', signer_sha: 'b'.repeat(40),
    run_id: '17', run_attempt: '1', environment: null, environment_node_id: null, subject_mode: 'immutable', protected_ref: true,
  } };
}

/** Return a compact fixture response independently of the issuer claims and policy inputs. */
function record(expected = intent()) {
  const source = expected.mapping.source;
  return { schema_version: 1, state: 'independently-mapped-producer-job', observed_at: CLOCK, run_started_at: CLOCK - 10,
    snapshot_sha256: 'd'.repeat(64), candidate_qualification_only: false,
    source: { repository: source.repository, repository_id: source.repository_id, owner_id: source.owner_id,
      commit: source.source_commit, caller_commit: source.caller_commit, caller_sha256: source.caller_sha256,
      run_id: source.run_id, run_attempt: source.run_attempt },
    job: { job_id: '31', check_run_id: '47', name: expected.mapping.job_name, workflow_name: expected.mapping.workflow_name,
      runner_label: target.label, started_at: CLOCK - 5 }, environment: expected.mapping.environment === null ? null : {
      name: expected.mapping.environment.name, id: expected.mapping.environment.environment_id,
      node_id: expected.mapping.environment.node_id, configuration_sha256: 'e'.repeat(64), state: 'unknown',
      current_attempt_approval: 'unsupported', effective_enforcement: 'unsupported',
    }, native_distribution: { schema_version: 1, state: 'native-distribution-byte-qualified', version: '2.102.0',
      source_commit: 'fc4b137cdef0a6bd28fd461b7cf9c84a5812a8cd', target: target.name,
      executable: { size: target.size, sha256: target.digest }, production_catalog_accepted: false,
      upstream_signature_authenticated: false, signing_authorized: false },
    source_provider_authenticated: true, current_job_mapping_observed: true, producer_job_authenticated: false,
    environment_protection_authenticated: false, production_catalog_accepted: false, signing_authorized: false,
    publication_authorized: false };
}

/** Sign only synthetic source/job claims with an ephemeral test key; no token is persisted. */
function token(expected = intent(), overrides = {}, key = keys.privateKey) {
  const oidc = expected.oidc;
  const [owner, repository] = oidc.repository.split('/');
  const scope = oidc.environment === null ? `ref:${oidc.ref}` : `environment:${oidc.environment}`;
  const subject = oidc.subject_mode === 'immutable' ? `${owner}@${oidc.repository_owner_id}/${repository}@${oidc.repository_id}` : oidc.repository;
  const claims = { iss: ISSUER, aud: AUDIENCE, sub: `repo:${subject}:${scope}`, repository: oidc.repository,
    repository_id: oidc.repository_id, repository_owner: owner, repository_owner_id: oidc.repository_owner_id,
    repository_visibility: oidc.repository_visibility, sha: oidc.source_sha, ref: oidc.ref,
    ref_type: oidc.event === 'push' ? 'tag' : 'branch', ref_protected: 'true', event_name: oidc.event,
    actor: oidc.actor, actor_id: oidc.actor_id,
    workflow_ref: `${oidc.repository}/${oidc.caller_path}@${oidc.ref}`, workflow_sha: oidc.caller_sha,
    job_workflow_ref: `${oidc.signer_repository}/${oidc.signer_path}@${oidc.signer_sha}`, job_workflow_sha: oidc.signer_sha,
    run_id: oidc.run_id, run_attempt: oidc.run_attempt, check_run_id: '47', runner_environment: 'github-hosted',
    iat: CLOCK - 5, nbf: CLOCK - 5, exp: CLOCK + 295,
    ...(oidc.environment === null ? {} : { environment: oidc.environment, environment_node_id: oidc.environment_node_id }), ...overrides };
  const input = [ { alg: 'RS256', typ: 'JWT', kid: 'fixture' }, claims ].map(value => Buffer.from(JSON.stringify(value)).toString('base64url')).join('.');
  return `${input}.${sign('RSA-SHA256', Buffer.from(input), key).toString('base64url')}`;
}

/** Intercept fixed HTTP endpoints only; all native/OIDC fixtures are clearly synthetic. */
async function syntheticFetch(url, options) {
  scenario.requests.push(String(url));
  assert.equal(options.method, 'GET');
  assert.equal(options.redirect, 'error');
  if (String(url) === `${ISSUER}/.well-known/jwks`) {
    assert.equal(Object.hasOwn(options.headers, 'Authorization'), false);
    return new Response(JSON.stringify({ keys: [{ ...keys.publicKey.export({ format: 'jwk' }), kid: 'fixture', alg: 'RS256', use: 'sig' }] }));
  }
  assert.equal(String(url), `${SERVICE}&audience=${encodeURIComponent(AUDIENCE)}`);
  assert.equal(options.headers.Authorization, 'Bearer synthetic-issuer-credential');
  return new Response(JSON.stringify({ value: scenario.token }));
}

/** Substitute owned fixture children only inside tests while inspecting the actual production spawn contract. */
function syntheticSpawn(executable, arguments_, options) {
  assert.equal(executable, target.python);
  assert.deepEqual(arguments_.slice(0, 2), ['-I', '-c']);
  assert.equal(arguments_[2], 'import sys; sys.path.insert(0,sys.argv.pop()); from armorer_runtime.producer_job_worker_v1 import main; main()');
  assert.equal(options.detached, true);
  assert.deepEqual(options.stdio, ['pipe', 'pipe', 'ignore']);
  assert.deepEqual(Object.keys(options.env).sort(), ['PATH', 'LANG', 'HOME', 'TMPDIR', 'ARMORER_WORKFLOW_READ_TOKEN'].sort());
  assert.equal(options.env.ARMORER_WORKFLOW_READ_TOKEN, 'synthetic-native-read-token');
  assert.equal(options.env.HOME, options.cwd);
  assert.equal(options.env.TMPDIR, options.cwd);
  const index = scenario.children.length;
  const native = scenario.records[index] ?? scenario.records[0];
  const output = Buffer.isBuffer(native) ? native.toString('base64') : Buffer.from(typeof native === 'string' ? native : JSON.stringify(native)).toString('base64');
  const code = 'let size=0;process.stdin.on("data",b=>size+=b.length);process.stdin.on("end",()=>{' +
    'process.stderr.write("provider-secret-marker");process.stdout.write(Buffer.from(process.argv[1],"base64"));' +
    'if(process.argv[2]==="stall"){process.on("SIGTERM",()=>process.exit(1));setInterval(()=>{},1000);}' +
    'else process.exit(Number(process.argv[2]));});';
  const child = originals.spawn(process.execPath, ['-e', code, output, scenario.childMode ?? '0'], options);
  scenario.children.push({ child, cwd: options.cwd, arguments_ });
  return child;
}

/** Reset the synthetic platform for every case without leaking state across test groups. */
beforeEach(function prepare() {
  scenario = { records: [record(), record()], token: token(), requests: [], children: [] };
  process.env.ACTIONS_ID_TOKEN_REQUEST_URL = SERVICE;
  process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN = 'synthetic-issuer-credential';
  process.env.ARMORER_WORKFLOW_READ_TOKEN = 'synthetic-native-read-token';
  for (const name of envNames.slice(3).filter(name => !transportNames.includes(name))) {
    process.env[name] = 'unrelated-ambient-marker';
  }
  for (const name of transportNames) delete process.env[name];
  globalThis.fetch = syntheticFetch;
  /** Supply a fixed test-only clock without changing production deadline behavior. */
  Date.now = function fixedClock() { return CLOCK * 1000; };
  childProcess.spawn = syntheticSpawn;
  syncBuiltinESMExports();
});

/** Restore globals and verify each completed owned worker had its private scratch removed. */
afterEach(async function restore() {
  globalThis.fetch = originals.fetch;
  Date.now = originals.clock;
  childProcess.spawn = originals.spawn;
  syncBuiltinESMExports();
  for (const [name, value] of originalEnvironment) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  for (const { child, cwd } of scenario.children) {
    assert.ok(child.exitCode !== null || child.signalCode !== null);
    await assert.rejects(access(cwd));
  }
});

/** Require one fixed redacted coordinator error regardless of signed/provider-controlled values. */
async function denied(expected = intent()) {
  /** Check that no provider or credential detail can escape a rejected coordinator stage. */
  await assert.rejects(authenticateMappedProducerContext(expected), function fixedError(error) {
    assert.equal(error.message, 'producer-context-authentication-failed');
    assert.equal(error.cause, undefined);
    assert.equal(/provider-secret|synthetic-.*credential|native-read-token/.test(error.stack), false);
    return true;
  });
}

/** Deliberately separate job ID from check-run ID and prove JSON audit data cannot construct a proof. */
test('independent native mapping joins signed check-run identity without granting release authority', async function success() {
  const proof = await authenticateMappedProducerContext(intent());
  const audit = mappedProducerContextRecord(proof);
  assert.equal(audit.native_job.job_id, '31');
  assert.equal(audit.native_job.check_run_id, '47');
  assert.equal(audit.oidc.context.check_run_id, '47');
  assert.equal(audit.current_job_mapping_authenticated, true);
  assert.equal(audit.producer_job_authenticated, true);
  for (const flag of ['environment_protection_authenticated', 'artifact_producer_authenticated', 'cryptographic_release_authenticated',
    'production_catalog_accepted', 'signing_authorized', 'publication_authorized']) assert.equal(audit[flag], false);
  assert.equal(scenario.children.length, 2);
  assert.equal(scenario.requests.length, 2);
  assert.equal(inspect(proof), '[MappedProducerContext]');
  assert.throws(() => JSON.stringify(proof), /serialization-denied/);
  for (const forgery of [{}, audit, JSON.parse(JSON.stringify(audit)), Object.create(Object.getPrototypeOf(proof))]) {
    assert.throws(() => mappedProducerContextRecord(forgery), /unverified-proof/);
  }
  assert.ok(Object.isFrozen(audit.native_job));
  assert.equal(/synthetic-.*credential|native-read-token|provider-secret/.test(JSON.stringify(audit)), false);
});

/** A native mapping cannot bypass the token helper's transport boundary or reach either issuer endpoint. */
test('inherited transport overrides cannot join an OIDC context', async function transportEnvironment() {
  for (const name of transportNames) {
    try {
      for (const value of ['', 'synthetic-transport-override']) {
        process.env[name] = value;
        await denied();
        assert.equal(scenario.requests.length, 0);
      }
    } finally {
      delete process.env[name];
    }
  }
});

/** Unsafe caller policy must fail before any native child, token request or issuer lookup. */
test('unsafe triggers, offered check IDs and cross-policy substitutions reject before credentials', async function earlyPolicy() {
  const changes = [
    value => { value.mapping.source.event = 'pull_request_target'; },
    value => { value.mapping.qualification_only = true; },
    value => { value.mapping.source.run_id = 17; },
    value => { value.mapping.source.run_attempt = '01'; },
    value => { value.oidc.check_run_id = '47'; },
    value => { value.worker_command = 'provider-secret-marker'; },
    value => { value.mapping.job_name += '\n'; },
    value => { value.mapping.source.source_commit = 'e'.repeat(40); },
    value => { value.oidc.signer_sha = 'e'.repeat(40); },
    value => { value.mapping.source.ref = 'refs/tags/latest'; },
    value => { value.oidc.protected_ref = false; },
    value => { value.mapping.source.pull_request = '3'; },
  ];
  for (const change of changes) { const value = intent(); change(value); await denied(value); }
  assert.equal(scenario.children.length, 0);
  assert.equal(scenario.requests.length, 0);
});

/** Reject accessors, sparse arrays, extra symbols and prototype objects without executing property getters. */
test('policy copies admit only exact own data and bounded dense arrays', async function ownData() {
  const value = intent();
  let executed = false;
  Object.defineProperty(value.mapping, 'job_name', { enumerable: true,
    /** Mark an accessor attack; the production data copier must never invoke this getter. */
    get() { executed = true; return 'bad'; } });
  await denied(value);
  assert.equal(executed, false);
  const coercion = intent();
  coercion.mapping.runner_label = {
    /** Mark a string-coercion attack; runner lookup must first require a literal policy string. */
    toString() { executed = true; return target.label; },
  };
  await denied(coercion);
  assert.equal(executed, false);
  for (const change of [v => { v.mapping.source.referenced_workflows = new Array(2); },
    v => { v.mapping.source[Symbol('extra')] = 1; }, v => { Object.setPrototypeOf(v.oidc, { caller: 'extra' }); }]) {
    const other = intent(); change(other); await denied(other);
  }
  assert.equal(scenario.children.length, 0);
});

/** Native observations cannot assert authority, substitute source/job IDs or use stale timestamps. */
test('malformed, stale and mismatched native observations deny before token access', async function nativeBindings() {
  const changes = [r => { r.producer_job_authenticated = true; }, r => { r.source.commit = 'e'.repeat(40); },
    r => { r.job.name = 'other'; }, r => { r.job.check_run_id = '01'; }, r => { r.observed_at = CLOCK - 31; },
    r => { r.observed_at = CLOCK + 1; }, r => { r.job.started_at = CLOCK + 1; },
    r => { r.native_distribution.executable.sha256 = 'e'.repeat(64); }, r => { r.candidate_qualification_only = true; }];
  for (const change of changes) { const native = record(); change(native); scenario.records = [native]; await denied(); }
  assert.equal(scenario.requests.length, 0);
});

/** A signed token with job-ID equality is wrong when independent API mapping yields a distinct check ID. */
test('signed wrong check-run, source, rerun, signer and foreign signatures cannot join', async function signedBindings() {
  for (const changes of [{ check_run_id: '31' }, { run_attempt: '2' }, { sha: 'e'.repeat(40) },
    { job_workflow_sha: 'e'.repeat(40) }, { runner_environment: 'self-hosted' }]) {
    scenario.token = token(intent(), changes);
    const before = scenario.children.length;
    scenario.records = Array(50).fill(record());
    await denied();
    assert.equal(scenario.children.length - before, 1);
  }
  scenario.token = token(intent(), {}, foreign.privateKey);
  await denied();
});

/** Any late prerequisite digest or selected identity change rejects the otherwise valid issuer proof. */
test('post-OIDC native changes and reread failure reject the joined proof', async function lateRace() {
  for (const change of [r => { r.snapshot_sha256 = 'e'.repeat(64); }, r => { r.job.job_id = '32'; },
    r => { r.job.check_run_id = '48'; }, r => { r.source.run_attempt = '2'; }]) {
    const after = record(); change(after);
    scenario.records = [...Array(scenario.children.length).fill(record()), record(), after];
    await denied();
  }
});

/** Strict decoding rejects duplicate keys, prototype keys, invalid UTF-8, BOM and oversized worker output. */
test('bounded native JSON rejects unsafe encodings and cancels oversized real children', async function boundedOutput() {
  const valid = JSON.stringify(record());
  for (const bad of [valid.replace('"schema_version":1', '"schema_version":1,"schema_version":1'),
    valid.replace('"schema_version":1', '"__proto__":{},"schema_version":1'), '\ufeff' + valid,
    Buffer.from([0xc3, 0x28]), valid + ' trailing', '{}', Buffer.alloc(65537, 120)]) {
    scenario.records = [bad];
    await denied();
  }
  assert.equal(scenario.requests.length, 0);
});

/** A stalled child with excessive output must close and clean its scratch before failure returns. */
test('oversized worker cancellation waits for owned child close and deletes private scratch', async function cancellation() {
  scenario.childMode = 'stall';
  scenario.records = [Buffer.alloc(65537, 120)];
  await denied();
  assert.equal(scenario.requests.length, 0);
  assert.equal(scenario.children.length, 1);
});

/** Environment identity can join while configuration, effective approval and release authority remain distinct. */
test('environment claim and configuration never imply protection or approval', async function environment() {
  const expected = intent();
  expected.mapping.environment = { name: 'release-signing', environment_id: '61', node_id: 'EN_fixture',
    reviewer_ids: ['11'], default_branch: 'main', wait_minutes: 0 };
  expected.oidc.environment = 'release-signing';
  expected.oidc.environment_node_id = 'EN_fixture';
  scenario.records = [record(expected), record(expected)];
  scenario.token = token(expected);
  const audit = mappedProducerContextRecord(await authenticateMappedProducerContext(expected));
  assert.equal(audit.environment_configuration.state, 'unknown');
  assert.equal(audit.oidc.effective_environment_claim_authenticated, true);
  assert.equal(audit.environment_protection_authenticated, false);
  assert.equal(audit.signing_authorized, false);
});

/** Exact canonical strings retain large IDs across native mapping, RS256 claims and audit export. */
test('identifiers above 2^53 retain exact cross-language identity', async function precision() {
  const expected = intent();
  expected.mapping.source.run_id = expected.oidc.run_id = '9007199254740993';
  const native = record(expected);
  native.job.check_run_id = '9007199254740995';
  scenario.records = [native, native];
  scenario.token = token(expected, { check_run_id: '9007199254740995' });
  const audit = mappedProducerContextRecord(await authenticateMappedProducerContext(expected));
  assert.equal(audit.native_source.run_id, '9007199254740993');
  assert.equal(audit.oidc.context.check_run_id, '9007199254740995');
});

/** A joined proof is usable only while the final native observation and issuer proof are both fresh. */
test('native freshness, clock rollback and expired issuer proof reject audit use', async function expiry() {
  const proof = await authenticateMappedProducerContext(intent());
  for (const seconds of [CLOCK + 31, CLOCK - 1, CLOCK + 300]) {
    /** Move only the test clock to demonstrate final native and issuer proof expiration. */
    Date.now = function changedClock() { return seconds * 1000; };
    assert.throws(() => mappedProducerContextRecord(proof), /expired/);
  }
});

/** Parent authentication failures stay fixed and cannot fall back to ambient provider credentials. */
test('missing read token and failed worker exit deny without OIDC request', async function parentFailures() {
  delete process.env.ARMORER_WORKFLOW_READ_TOKEN;
  await denied();
  assert.equal(scenario.children.length, 0);
  process.env.ARMORER_WORKFLOW_READ_TOKEN = 'synthetic-native-read-token';
  scenario.childMode = '1';
  await denied();
  assert.equal(scenario.requests.length, 0);
});
