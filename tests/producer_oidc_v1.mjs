/** Synthetic issuer protocol tests: native RSA verification, never live OIDC or signing authority. */
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { inspect } from 'node:util';
import { afterEach, beforeEach, test } from 'node:test';
import { authenticateProducerContext, producerContextRecord } from '../armorer_runtime/producer_oidc_v1.mjs';

const ISSUER = 'https://token.actions.githubusercontent.com';
const JWKS = `${ISSUER}/.well-known/jwks`;
const SERVICE = 'https://pipelines.actions.githubusercontent.com/fixture/_apis/distributedtask/hubs/build/plans/fixture/jobs/fixture/idtoken?api-version=2.0';
const AUDIENCE = 'armorer:producer-context:v1';
const CLOCK = 2000000000;
const originalFetch = globalThis.fetch;
const originalClock = Date.now;
const originalUrl = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
const originalCredential = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const foreignKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const weakKeys = generateKeyPairSync('rsa', { modulusLength: 1024 });
let scenario;

/** Construct independent controller expectations; no value is read from the signed token. */
function intent(overrides = {}) {
  return {
    repository: 'fixture-owner/fixture-repo', repository_id: '7', repository_owner_id: '8',
    repository_visibility: 'public', source_sha: 'a'.repeat(40), ref: 'refs/heads/main',
    event: 'workflow_dispatch', default_branch: 'main', actor: 'fixture-actor', actor_id: '11',
    caller_path: '.github/workflows/release.yml', caller_sha: 'a'.repeat(40),
    signer_repository: 'brianluby/armorer-workflows', signer_path: '.github/workflows/release-cli.yml',
    signer_sha: 'b'.repeat(40), run_id: '17', run_attempt: '1', check_run_id: '19',
    environment: null, environment_node_id: null, subject_mode: 'immutable', protected_ref: true,
    ...overrides,
  };
}

/** Build synthetic issuer claims for the independent fixture, including exact subject and job identity. */
function claims(expected = intent(), overrides = {}) {
  const [owner, repository] = expected.repository.split('/');
  const immutable = expected.subject_mode === 'immutable';
  const source = immutable ? `${owner}@${expected.repository_owner_id}/${repository}@${expected.repository_id}` : expected.repository;
  const scope = expected.environment === null ? `ref:${expected.ref}` : `environment:${expected.environment}`;
  const result = {
    iss: ISSUER, aud: AUDIENCE, sub: `repo:${source}:${scope}`, jti: 'synthetic-jti-never-exported',
    repository: expected.repository, repository_id: expected.repository_id,
    repository_owner: owner, repository_owner_id: expected.repository_owner_id,
    repository_visibility: expected.repository_visibility, sha: expected.source_sha,
    ref: expected.ref, ref_type: expected.event === 'push' ? 'tag' : 'branch', ref_protected: 'true',
    event_name: expected.event, actor: expected.actor, actor_id: expected.actor_id,
    workflow_ref: `${expected.repository}/${expected.caller_path}@${expected.ref}`, workflow_sha: expected.caller_sha,
    job_workflow_ref: `${expected.signer_repository}/${expected.signer_path}@${expected.signer_sha}`,
    job_workflow_sha: expected.signer_sha, run_id: expected.run_id, run_attempt: expected.run_attempt,
    check_run_id: expected.check_run_id, runner_environment: 'github-hosted',
    iat: CLOCK - 5, nbf: CLOCK - 5, exp: CLOCK + 295,
  };
  if (expected.environment !== null) {
    result.environment = expected.environment;
    result.environment_node_id = expected.environment_node_id;
  }
  return { ...result, ...overrides };
}

/** Encode supplied fixture bytes without changing malformed JSON used by parser regressions. */
function encoded(value) {
  return (Buffer.isBuffer(value) ? value : Buffer.from(typeof value === 'string' ? value : JSON.stringify(value))).toString('base64url');
}

/** Sign exactly the offered fixture header and payload with an ephemeral in-memory test key. */
function jwt(payload = claims(), header = { alg: 'RS256', typ: 'JWT', kid: 'fixture-key' }, privateKey = keys.privateKey) {
  const signingInput = `${encoded(header)}.${encoded(payload)}`;
  return `${signingInput}.${sign('RSA-SHA256', Buffer.from(signingInput), privateKey).toString('base64url')}`;
}

/** Publish only synthetic public RSA parameters, with independent malformed-key overrides. */
function publicKey(overrides = {}, key = keys.publicKey) {
  return { ...key.export({ format: 'jwk' }), kid: 'fixture-key', use: 'sig', alg: 'RS256', ...overrides };
}

/** Return bounded synthetic HTTP responses without credential diagnostics or network access. */
function response(body, options = {}) {
  const bytes = Buffer.isBuffer(body) ? body : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
  return new Response(bytes, { status: options.status ?? 200, headers: options.headers ?? {} });
}

/** Intercept only the two fixed protocol endpoints and retain credential presence as booleans. */
async function syntheticFetch(url, options) {
  const destination = String(url);
  scenario.requests.push({ url: destination, method: options.method, redirect: options.redirect,
    authorization: Object.hasOwn(options.headers, 'Authorization'), signal: options.signal });
  assert.equal(options.method, 'GET');
  assert.equal(options.redirect, 'error');
  if (destination === JWKS) {
    assert.equal(Object.hasOwn(options.headers, 'Authorization'), false);
    return scenario.jwksResponse ? scenario.jwksResponse() : response(scenario.jwks);
  }
  assert.equal(destination, `${SERVICE}&audience=${encodeURIComponent(AUDIENCE)}`);
  assert.equal(options.headers.Authorization, 'Bearer synthetic-service-credential-no-authority');
  return scenario.tokenResponse ? scenario.tokenResponse() : response({ value: scenario.token });
}

/** Keep each case's platform state and synthetic service independent of prior cases. */
beforeEach(function prepareSyntheticService() {
  scenario = { token: jwt(), jwks: { keys: [publicKey()] }, requests: [] };
  process.env.ACTIONS_ID_TOKEN_REQUEST_URL = SERVICE;
  process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN = 'synthetic-service-credential-no-authority';
  globalThis.fetch = syntheticFetch;
  Date.now = fixedClock;
});

/** Supply a stable test clock without altering production clock or deadline APIs. */
function fixedClock() { return CLOCK * 1000; }

/** Restore every overwritten global and platform variable, including on failed assertions. */
afterEach(function restorePlatformState() {
  globalThis.fetch = originalFetch;
  Date.now = originalClock;
  for (const [name, value] of [['ACTIONS_ID_TOKEN_REQUEST_URL', originalUrl], ['ACTIONS_ID_TOKEN_REQUEST_TOKEN', originalCredential]]) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
});

/** Require only fixed redacted stage errors; signed or provider-controlled data cannot appear. */
async function denied(expected = intent(), pattern = /^oidc-[a-z-]+$/) {
  await assert.rejects(authenticateProducerContext(expected), function fixedStage(error) {
    assert.match(error.message, pattern);
    assert.equal(error.cause, undefined);
    assert.equal(error.stack.includes('synthetic-service-credential'), false);
    assert.equal(error.stack.includes('provider-secret-marker'), false);
    return true;
  });
}

/** Verify both reviewed exact subject modes for protected dispatch, stable tags and named environments. */
test('native RS256 success binds complete context without exporting credentials or release authority', async function completeIdentity() {
  for (const subject_mode of ['legacy', 'immutable']) {
    for (const options of [{}, { event: 'push', ref: 'refs/tags/v0.1.0' },
      { environment: 'release-signing', environment_node_id: 'EN_fixture' },
      { environment: 'release-publish', environment_node_id: 'EN_publish' }]) {
      const expected = intent({ subject_mode, ...options });
      scenario.token = jwt(claims(expected, { arbitrary_private_metadata: 'provider-secret-marker' }));
      const proof = await authenticateProducerContext(expected);
      const record = producerContextRecord(proof);
      assert.equal(record.oidc_job_identity_authenticated, true);
      assert.equal(record.effective_environment_claim_authenticated, expected.environment !== null);
      assert.equal(record.context.check_run_id, '19');
      assert.equal(record.context.run_attempt, '1');
      assert.equal(record.context.job_workflow_sha, expected.signer_sha);
      assert.equal(record.context.environment, expected.environment);
      assert.equal(record.context.subject_mode, subject_mode);
      assert.equal(record.expires_at, CLOCK + 295);
      assert.equal(record.jwks.url, JWKS);
      assert.match(record.jwks.sha256, /^[a-f0-9]{64}$/);
      for (const flag of ['environment_protection_authenticated', 'artifact_producer_authenticated',
        'cryptographic_release_authenticated', 'production_catalog_accepted', 'signing_authorized', 'publication_authorized']) {
        assert.equal(record[flag], false);
      }
      const serialized = JSON.stringify(record);
      for (const forbidden of [scenario.token, 'synthetic-service-credential', 'provider-secret-marker', 'synthetic-jti', '"sub"']) {
        assert.equal(serialized.includes(forbidden), false);
      }
      assert.equal(Object.isFrozen(proof), true);
      assert.equal(Object.isFrozen(record.context), true);
      assert.equal(inspect(proof), '[VerifiedProducerContext]');
      assert.throws(() => JSON.stringify(proof), /oidc-proof-serialization-denied/);
      assert.throws(() => new proof.constructor(null, record), /oidc-proof-construction-denied/);
      for (const offered of [record, JSON.parse(serialized), structuredClone(proof),
        Object.create(Object.getPrototypeOf(proof)), null, undefined, 'proof']) {
        assert.throws(() => producerContextRecord(offered), /oidc-unverified-proof/);
      }
    }
  }
  assert.equal(scenario.requests.length, 16);
});

/** Reject every exact source/caller/signer/job field substitution after native signature verification. */
test('signed source signer actor run attempt job runner and protection substitutions fail', async function identitySubstitutions() {
  const substitutions = {
    iss: `${ISSUER}/extra`, aud: [AUDIENCE], repository: 'other-owner/fixture-repo', repository_id: '9',
    repository_owner: 'other-owner', repository_owner_id: '9', repository_visibility: 'private',
    sha: 'c'.repeat(40), ref: 'refs/heads/other', ref_type: 'tag', ref_protected: true,
    event_name: 'pull_request_target', actor: 'other-actor', actor_id: '12',
    workflow_ref: 'fixture-owner/fixture-repo/.github/workflows/other.yml@refs/heads/main',
    workflow_sha: 'c'.repeat(40), job_workflow_ref: 'brianluby/armorer-workflows/.github/workflows/release-cli.yml@main',
    job_workflow_sha: 'c'.repeat(40), run_id: '18', run_attempt: '2', check_run_id: '20', runner_environment: 'self-hosted',
  };
  for (const [name, value] of Object.entries(substitutions)) {
    scenario.token = jwt(claims(intent(), { [name]: value }));
    await denied(intent(), /^oidc-identity-mismatch$/);
    const absent = claims();
    delete absent[name];
    scenario.token = jwt(absent);
    await denied(intent(), /^oidc-identity-mismatch$/);
  }
  for (const value of ['false', null, 'TRUE', 1]) {
    scenario.token = jwt(claims(intent(), { ref_protected: value }));
    await denied();
  }
});

/** Bind environment presence/node identity and exact subject mode without custom-format fallback. */
test('subject and environment substitutions never fall back or authorize protections', async function subjectEnvironment() {
  for (const overrides of [{ sub: 'repo:fixture-owner/fixture-repo:ref:refs/heads/main' },
    { sub: 'repo:fixture-owner@8/fixture-repo@7:pull_request' }, { sub: 'job_workflow_ref:custom' }]) {
    scenario.token = jwt(claims(intent(), overrides));
    await denied(intent(), /^oidc-subject-mismatch$/);
  }
  for (const overrides of [{ environment: null }, { environment_node_id: null }, { environment: 'release-signing' }]) {
    scenario.token = jwt(claims(intent(), overrides));
    await denied(intent(), /^oidc-environment-mismatch$/);
  }
  const expected = intent({ environment: 'release-signing', environment_node_id: 'EN_fixture' });
  for (const overrides of [{ environment: 'release-publish' }, { environment_node_id: 'EN_other' },
    { environment_node_id: undefined }]) {
    scenario.token = jwt(claims(expected, overrides));
    await denied(expected, /^oidc-environment-mismatch$/);
  }
});

/** Startup transport changes must reject before either credential access or issuer/service requests. */
test('inherited transport overrides fail before credential reads or HTTP', async function transportEnvironment() {
  const environment = process.env;
  try {
    for (const name of ['NODE_OPTIONS', 'NODE_EXTRA_CA_CERTS', 'NODE_TLS_REJECT_UNAUTHORIZED', 'NODE_USE_ENV_PROXY']) {
      for (const value of ['', 'synthetic-transport-override']) {
        process.env = {
          [name]: value,
          ACTIONS_ID_TOKEN_REQUEST_URL: SERVICE,
          /** Detect any access to the synthetic credential before the transport boundary rejects. */
          get ACTIONS_ID_TOKEN_REQUEST_TOKEN() { throw new Error('request-token-must-not-be-read'); },
        };
        await denied(intent(), /^oidc-transport-environment-denied$/);
        assert.equal(scenario.requests.length, 0);
      }
    }
  } finally {
    process.env = environment;
  }
});

/** Unsafe triggers and malformed independent expectations are rejected before credentials or HTTP. */
test('untrusted independent intent fails before any token request', async function intentBoundary() {
  const overrides = [
    { event: 'pull_request' }, { event: 'pull_request_target' }, { event: 'workflow_run' },
    { event: 'push', ref: 'refs/heads/main' }, { event: 'push', ref: 'refs/tags/v01.2.3' },
    { event: 'push', ref: 'refs/tags/v1.2.3-rc1' }, { ref: 'refs/heads/other' }, { protected_ref: false },
    { signer_repository: 'other/armorer-workflows' }, { signer_sha: 'main' }, { caller_sha: 'c'.repeat(40) },
    { source_sha: 'A'.repeat(40) }, { caller_path: '.github/workflows/../release.yml' },
    { signer_path: '.github/workflows/release.yml;false' }, { actor: 'fixture-actor\n' },
    { environment: 'unknown', environment_node_id: 'EN_fixture' }, { environment_node_id: 'EN_fixture' },
    { subject_mode: 'custom' }, { default_branch: '../main' }, { default_branch: 'main.lock' },
    { repository_visibility: 'internal' }, { repository: 'https://github.com/fixture/repo' },
    { extra_claim: true },
  ];
  for (const name of ['repository_id', 'repository_owner_id', 'actor_id', 'run_id', 'run_attempt', 'check_run_id']) {
    for (const value of [1, true, '0', '01', '-1', '9223372036854775808']) overrides.push({ [name]: value });
  }
  for (const [name, value] of Object.entries(intent())) {
    if (typeof value === 'string') overrides.push({ [name]: `${value}\n` });
  }
  process.env.ACTIONS_ID_TOKEN_REQUEST_URL = 'not-a-url';
  for (const value of overrides) await denied(intent(value), /^oidc-independent-[a-z-]+$/);
  const accessor = intent();
  Object.defineProperty(accessor, 'actor', { enumerable: true,
    /** Fail the test if an untrusted intent accessor executes. */
    get() { throw new Error('getter-must-not-run'); },
  });
  await denied(accessor, /^oidc-independent-intent-invalid$/);
  const missing = intent();
  delete missing.actor;
  for (const offered of [missing, null, [], new Date(), { ...intent(), [Symbol('unknown')]: true }]) {
    await denied(offered, /^oidc-independent-intent-invalid$/);
  }
  assert.equal(scenario.requests.length, 0);
});

/** Service origin/route/query and authorization framing cannot be chosen by supplied URLs. */
test('token-service URL and missing credential fail closed before fetch', async function serviceOrigin() {
  for (const url of ['https://attacker.invalid/idtoken', SERVICE.replace('https:', 'http:'),
    SERVICE.replace('pipelines.actions.githubusercontent.com', 'pipelines.actions.githubusercontent.com.attacker.invalid'),
    SERVICE.replace('/idtoken?', '/other?'), `${SERVICE}&audience=attacker`, `${SERVICE}&api-version=2.0`,
    `${SERVICE}#fragment`, SERVICE.replace('https://', 'https://user:password@'),
    SERVICE.replace('.com/', '.com:444/'), `${SERVICE}\n`, SERVICE.replace('/fixture/', '/%66ixture/')]) {
    process.env.ACTIONS_ID_TOKEN_REQUEST_URL = url;
    await denied(intent(), /^oidc-request-url-invalid$/);
  }
  process.env.ACTIONS_ID_TOKEN_REQUEST_URL = SERVICE;
  for (const token of ['', 'contains space', 'has\nnewline', 'x'.repeat(8193)]) {
    process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN = token;
    await denied(intent(), /^oidc-request-credential-unavailable$/);
  }
  delete process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  await denied();
  assert.equal(scenario.requests.length, 0);
});

/** Algorithm confusion, foreign signatures, malformed segments and remote-key headers fail closed. */
test('exact RS256 header and canonical signatures reject confusion and tampering', async function signatureBoundary() {
  for (const header of [{ alg: 'none', typ: 'JWT', kid: 'fixture-key' },
    { alg: 'HS256', typ: 'JWT', kid: 'fixture-key' }, { alg: 'RS512', typ: 'JWT', kid: 'fixture-key' },
    { alg: 'RS256', typ: 'JWS', kid: 'fixture-key' }, { alg: 'RS256', typ: 'JWT' },
    { alg: 'RS256', typ: 'JWT', kid: 'fixture-key', jku: 'https://attacker.invalid' },
    { alg: 'RS256', typ: 'JWT', kid: 'fixture-key', x5u: 'https://attacker.invalid' },
    { alg: 'RS256', typ: 'JWT', kid: 'fixture-key', crit: ['custom'] }]) {
    scenario.token = jwt(claims(), header);
    await denied(intent(), /^oidc-token-header-invalid$/);
  }
  scenario.token = jwt(claims(), undefined, foreignKeys.privateKey);
  await denied(intent(), /^oidc-signature-invalid$/);
  const valid = jwt().split('.');
  for (const token of [`${valid[0]}.${encoded(claims(intent(), { actor_id: '12' }))}.${valid[2]}`,
    `${valid[0]}.${valid[1]}.${encoded(Buffer.alloc(256))}`]) {
    scenario.token = token;
    await denied(intent(), /^oidc-signature-invalid$/);
  }
  for (const token of ['', 'only-one-segment', `${jwt()}.extra`, `${valid[0]}=.${valid[1]}.${valid[2]}`,
    `${valid[0]}.${valid[1]}\n.${valid[2]}`, `${valid[0]}.${valid[1]}.`]) {
    scenario.token = token;
    await denied();
  }
});

/** Require a unique, public, strong RSA key and never retry with an alternate issuer or algorithm. */
test('ambiguous weak private and substituted issuer keys are rejected', async function jwksBoundary() {
  const privateJwk = keys.privateKey.export({ format: 'jwk' });
  for (const key of [publicKey({ kid: 'other-key' }), publicKey({ kty: 'EC' }), publicKey({ use: 'enc' }),
    publicKey({ alg: 'RS512' }), publicKey({ key_ops: ['verify', 'sign'] }), publicKey({ d: privateJwk.d }),
    publicKey({ e: 'Aw' }), publicKey({}, weakKeys.publicKey), publicKey({ n: `${publicKey().n}=` }),
    publicKey({ n: Buffer.concat([Buffer.from([0]), Buffer.alloc(256, 1)]).toString('base64url') })]) {
    scenario.jwks = { keys: [key] };
    await denied();
  }
  for (const document of [{ keys: [] }, { keys: [publicKey(), publicKey()] },
    { keys: Array.from({ length: 33 }, (_, index) => publicKey({ kid: `fixture-${index}` })) },
    { keys: 'not-an-array' }, []]) {
    scenario.jwks = document;
    await denied(intent(), /^oidc-jwks-invalid$/);
  }
  scenario.jwks = { keys: [publicKey({}, foreignKeys.publicKey)] };
  await denied(intent(), /^oidc-signature-invalid$/);
});

/** Duplicate decoded keys, unsafe prototypes, invalid UTF-8, depth and node overflow never reach claims. */
test('strict bounded JSON rejects ambiguous token and issuer documents', async function jsonBoundary() {
  const valid = JSON.stringify(claims());
  const malformed = [valid.replace('"iss":', '"iss":"first","\\u0069ss":'),
    valid.replace('"iss":', '"__proto__":{},"iss":'), `${valid} false`, Buffer.from([0xff]),
    Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(valid)]),
    '{"unterminated":"value\\', '{"number":1e999}', '{"x":01}', '{"x":true,}',
    `${'['.repeat(18)}0${']'.repeat(18)}`, JSON.stringify(Array(4097).fill(0)),
    '{"x":"bad\nstring"}', '{"x":"\\q"}', '\u00a0{}'];
  for (const payload of malformed) {
    scenario.token = jwt(payload);
    await denied(intent(), /^oidc-json-[a-z-]+$/);
  }
  scenario.token = jwt();
  for (const document of ['{"keys":[],"\\u006beys":[]}', '{"constructor":{},"keys":[]}',
    '{"keys":[]}{}', Buffer.from([0xff]), Buffer.alloc(256 * 1024 + 1, 32)]) {
    scenario.jwksResponse = function malformedJwksResponse() { return response(document); };
    await denied();
  }
});

/** Fresh integer temporal claims and still-live private proofs are required without grace or downgrade. */
test('expiration freshness clock rollback and invalid numeric claims are rejected', async function temporalBoundary() {
  for (const overrides of [{ exp: CLOCK }, { iat: CLOCK + 1 }, { nbf: CLOCK + 1 },
    { iat: CLOCK - 301, exp: CLOCK + 299 }, { exp: CLOCK + 596 }, { exp: CLOCK - 6 },
    { iat: '2000000000' }, { nbf: 1.5 }, { exp: Number.MAX_SAFE_INTEGER + 1 }, { exp: 0 }]) {
    scenario.token = jwt(claims(intent(), overrides));
    await denied(intent(), /^oidc-time-invalid$/);
  }
  scenario.token = jwt();
  const proof = await authenticateProducerContext(intent());
  Date.now = function expiredClock() { return (CLOCK + 295) * 1000; };
  assert.throws(() => producerContextRecord(proof), /oidc-proof-expired/);
  Date.now = function rolledBackClock() { return (CLOCK - 1) * 1000; };
  assert.throws(() => producerContextRecord(proof), /oidc-proof-expired/);
  Date.now = fixedClock;
  scenario.jwksResponse = function rollbackDuringFetch() {
    Date.now = function earlierClock() { return (CLOCK - 1) * 1000; };
    return response(scenario.jwks);
  };
  await denied(intent(), /^oidc-stage-expired$/);
});

/** Bound error, redirect, length and streamed bodies; provider diagnostics are never propagated. */
test('provider errors redirects and oversized bodies are redacted without retries', async function providerBoundary() {
  const factories = [
    function providerFailure() { throw new Error('provider-secret-marker'); },
    function forbiddenStatus() { return response('provider-secret-marker', { status: 403 }); },
    function lyingLength() { return response('{}', { headers: { 'content-length': '9999999' } }); },
    function invalidLength() { return response('{}', { headers: { 'content-length': '-1' } }); },
    function oversizedBody() { return response(Buffer.alloc(256 * 1024 + 1, 32)); },
    function missingBody() { return { status: 200, redirected: false, body: null }; },
    function redirectedResponse() { return { status: 200, redirected: true, body: {} }; },
  ];
  for (const factory of factories) {
    scenario.tokenResponse = factory;
    const before = scenario.requests.length;
    await denied(intent(), /^oidc-provider-read-failed$/);
    assert.equal(scenario.requests.length, before + 1);
  }
  scenario.tokenResponse = function emptyResponse() { return response({ value: 7 }); };
  await denied(intent(), /^oidc-token-response-invalid$/);
});

/** A stalled reader and stalled cancellation cannot extend the production ten-second read deadline. */
test('body and cancellation stalls remain bounded and abort the request', { timeout: 15000 }, async function stalledProvider() {
  scenario.tokenResponse = function stalledResponse() {
    return { status: 200, redirected: false, headers: new Headers(), body: {
      /** Model an HTTP reader that ignores both abort and cancellation. */
      getReader() {
        return {
          /** Leave the simulated stream read unresolved without opening a network connection. */
          read() { return new Promise(function neverResolveRead() {}); },
          /** Leave cleanup unresolved so the test covers the independent cleanup deadline. */
          cancel() { return new Promise(function neverResolveCancel() {}); },
        };
      },
    } };
  };
  const started = performance.now();
  await denied(intent(), /^oidc-provider-read-failed$/);
  assert.ok(performance.now() - started < 13000);
  assert.equal(scenario.requests.length, 1);
  assert.equal(scenario.requests[0].signal.aborted, true);
});
