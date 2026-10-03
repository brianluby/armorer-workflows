/** Fixed GitHub OIDC job authentication; no bearer token or release authority is exported. */
import { constants, createHash, createPublicKey, verify } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { inspect } from 'node:util';

const ISSUER = 'https://token.actions.githubusercontent.com';
const JWKS = `${ISSUER}/.well-known/jwks`;
const AUDIENCE = 'armorer:producer-context:v1';
const MAX_TOKEN = 128 * 1024;
const MAX_JWKS = 256 * 1024;
const records = new WeakMap();
const brand = Symbol('internal verified OIDC context');

/** Fail with a fixed stage code, never provider diagnostics, tokens or offered claim values. */
function requireCondition(condition, code) {
  if (!condition) throw new Error(code);
}

/** Decode exactly one canonical unpadded base64url value within its independent byte bound. */
function decode(value, limit) {
  requireCondition(typeof value === 'string' && value.length > 0 &&
    value.length <= Math.ceil(limit * 4 / 3) && /^[A-Za-z0-9_-]+$/.test(value), 'oidc-encoding-invalid');
  const bytes = Buffer.from(value, 'base64url');
  requireCondition(bytes.length > 0 && bytes.length <= limit && bytes.toString('base64url') === value,
    'oidc-encoding-invalid');
  return bytes;
}

/** Parse bounded JSON while rejecting duplicate decoded keys, prototype keys and trailing input. */
function parseJson(bytes, limit) {
  requireCondition(Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= limit, 'oidc-json-bound');
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { throw new Error('oidc-json-invalid'); }
  requireCondition(text.charCodeAt(0) !== 0xfeff, 'oidc-json-invalid');
  let position = 0;
  let nodes = 0;

  /** Consume only JSON whitespace, without accepting other Unicode separators. */
  function whitespace() {
    while (position < text.length && ' \t\r\n'.includes(text[position])) position += 1;
  }

  /** Decode one bounded JSON string and preserve exact decoded-key identity for duplicate checks. */
  function string() {
    const start = position;
    requireCondition(text[position] === '"', 'oidc-json-invalid');
    position += 1;
    while (position < text.length) {
      const char = text[position];
      position += 1;
      if (char === '\\') {
        requireCondition(position < text.length, 'oidc-json-invalid');
        position += 1;
      } else if (char === '"') {
        try { return JSON.parse(text.slice(start, position)); }
        catch { throw new Error('oidc-json-invalid'); }
      }
    }
    throw new Error('oidc-json-invalid');
  }

  /** Walk one JSON value with explicit depth/node limits before accepting any metadata object. */
  function value(depth) {
    nodes += 1;
    requireCondition(depth <= 16 && nodes <= 4096, 'oidc-json-bound');
    whitespace();
    const char = text[position];
    if (char === '"') return string();
    if (char === '{') {
      const result = Object.create(null);
      position += 1;
      whitespace();
      if (text[position] === '}') { position += 1; return result; }
      while (position < text.length) {
        const key = string();
        requireCondition(!['__proto__', 'constructor', 'prototype'].includes(key) &&
          !Object.hasOwn(result, key), 'oidc-json-key-invalid');
        whitespace();
        requireCondition(text[position] === ':', 'oidc-json-invalid');
        position += 1;
        result[key] = value(depth + 1);
        whitespace();
        const separator = text[position];
        position += 1;
        if (separator === '}') return result;
        requireCondition(separator === ',', 'oidc-json-invalid');
        whitespace();
      }
      throw new Error('oidc-json-invalid');
    }
    if (char === '[') {
      const result = [];
      position += 1;
      whitespace();
      if (text[position] === ']') { position += 1; return result; }
      while (position < text.length) {
        result.push(value(depth + 1));
        whitespace();
        const separator = text[position];
        position += 1;
        if (separator === ']') return result;
        requireCondition(separator === ',', 'oidc-json-invalid');
      }
      throw new Error('oidc-json-invalid');
    }
    const matched = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(position));
    requireCondition(matched !== null, 'oidc-json-invalid');
    position += matched[0].length;
    const result = JSON.parse(matched[0]);
    requireCondition(typeof result !== 'number' || Number.isFinite(result), 'oidc-json-invalid');
    return result;
  }

  const result = value(0);
  whitespace();
  requireCondition(position === text.length, 'oidc-json-invalid');
  return result;
}

/** Admit canonical positive decimal identifiers without number coercion or unsafe precision. */
function identifier(value) {
  return typeof value === 'string' && /^[1-9][0-9]{0,18}$/.test(value) && BigInt(value) <= 2n ** 63n - 1n;
}

/** Validate one conservative Git ref component before deriving exact token expectations. */
function branch(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 200 &&
    /^[A-Za-z0-9_./-]+$/.test(value) && !value.includes('..') &&
    value.split('/').every(part => part && !part.startsWith('.') && !part.endsWith('.') && !part.endsWith('.lock'));
}

/** Require plain data-only independent intent; token contents may never choose source, signer or job. */
function independentIntent(offered) {
  const names = ['repository', 'repository_id', 'repository_owner_id', 'repository_visibility',
    'source_sha', 'ref', 'event', 'default_branch', 'actor', 'actor_id', 'caller_path', 'caller_sha',
    'signer_repository', 'signer_path', 'signer_sha', 'run_id', 'run_attempt', 'check_run_id',
    'environment', 'environment_node_id', 'subject_mode', 'protected_ref'];
  requireCondition(offered && [Object.prototype, null].includes(Object.getPrototypeOf(offered)) &&
    Reflect.ownKeys(offered).length === names.length, 'oidc-independent-intent-invalid');
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(offered, name);
    requireCondition(descriptor && Object.hasOwn(descriptor, 'value') && descriptor.enumerable,
      'oidc-independent-intent-invalid');
  }
  const expected = Object.freeze({ ...offered });
  // JavaScript's end anchor also matches before a final newline; intent strings must be exact data.
  for (const value of Object.values(expected)) {
    requireCondition(typeof value !== 'string' || !/[\s\x00-\x1f\x7f]/.test(value),
      'oidc-independent-context-invalid');
  }
  requireCondition(typeof expected.repository === 'string' &&
    /^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/.test(expected.repository) &&
    expected.signer_repository === 'brianluby/armorer-workflows', 'oidc-independent-repository-invalid');
  for (const name of ['repository_id', 'repository_owner_id', 'actor_id', 'run_id', 'run_attempt', 'check_run_id']) {
    requireCondition(identifier(expected[name]), 'oidc-independent-identifier-invalid');
  }
  for (const name of ['source_sha', 'caller_sha', 'signer_sha']) {
    requireCondition(typeof expected[name] === 'string' && /^[0-9a-f]{40}$/.test(expected[name]),
      'oidc-independent-commit-invalid');
  }
  for (const name of ['caller_path', 'signer_path']) {
    requireCondition(typeof expected[name] === 'string' &&
      /^\.github\/workflows\/[A-Za-z0-9_-][A-Za-z0-9_.-]*\.yml$/.test(expected[name]) &&
      !expected[name].includes('..') && expected[name].length <= 200, 'oidc-independent-workflow-invalid');
  }
  requireCondition(typeof expected.actor === 'string' && /^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/.test(expected.actor) &&
    ['public', 'private'].includes(expected.repository_visibility) && branch(expected.default_branch) &&
    ['legacy', 'immutable'].includes(expected.subject_mode) && expected.protected_ref === true &&
    expected.caller_sha === expected.source_sha, 'oidc-independent-context-invalid');
  requireCondition((expected.event === 'workflow_dispatch' && expected.ref === `refs/heads/${expected.default_branch}`) ||
    (expected.event === 'push' && typeof expected.ref === 'string' && expected.ref.length <= 200 &&
      /^refs\/tags\/v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/.test(expected.ref)),
    'oidc-independent-trigger-invalid');
  requireCondition((expected.environment === null && expected.environment_node_id === null) ||
    (['release-signing', 'release-publish'].includes(expected.environment) &&
      typeof expected.environment_node_id === 'string' && /^[A-Za-z0-9+/_=-]{1,128}$/.test(expected.environment_node_id)),
    'oidc-independent-environment-invalid');
  return expected;
}

/** Limit bearer-token delivery to the hosted GitHub Actions token-service origin and known route. */
function tokenRequestUrl(value) {
  requireCondition(typeof value === 'string' && value.length <= 2048 && !/[\s\x00-\x1f\x7f]/.test(value),
    'oidc-request-url-invalid');
  let url;
  try { url = new URL(value); }
  catch { throw new Error('oidc-request-url-invalid'); }
  requireCondition(url.protocol === 'https:' && !url.username && !url.password && !url.port && !url.hash &&
    /^[a-z0-9-]+(?:\.[a-z0-9-]+)*\.actions\.githubusercontent\.com$/.test(url.hostname) &&
    /^\/[A-Za-z0-9-]+\/_apis\/distributedtask\/hubs\/build\/plans\/[A-Za-z0-9-]+\/jobs\/[A-Za-z0-9-]+\/idtoken$/.test(url.pathname) &&
    [...url.searchParams.keys()].every(key => key === 'api-version') &&
    url.searchParams.getAll('api-version').length <= 1 &&
    (!url.searchParams.has('api-version') || /^[0-9]+\.[0-9]+(?:-preview\.[0-9]+)?$/.test(url.searchParams.get('api-version'))),
    'oidc-request-url-invalid');
  url.searchParams.set('audience', AUDIENCE);
  return url;
}

/** Fetch a single bounded fixed-origin JSON body with no redirect, retries or diagnostic propagation. */
async function fetchBody(url, authorization, limit, deadline) {
  const remaining = Math.min(10000, deadline - performance.now());
  requireCondition(remaining > 0, 'oidc-stage-expired');
  const controller = new AbortController();
  let reader;
  let timer;
  /** Bound the whole fetch/read operation even if a provider body stalls. */
  async function receive() {
    const headers = { Accept: 'application/json' };
    if (authorization !== null) headers.Authorization = `Bearer ${authorization}`;
    const response = await fetch(url, { method: 'GET', headers, redirect: 'error', signal: controller.signal });
    requireCondition(response.status === 200 && !response.redirected && response.body, 'oidc-provider-read-failed');
    const length = response.headers.get('content-length');
    requireCondition(length === null || (/^[0-9]{1,8}$/.test(length) && Number(length) <= limit), 'oidc-provider-bound');
    reader = response.body.getReader();
    const blocks = [];
    let size = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      requireCondition(size <= limit && performance.now() < deadline, 'oidc-provider-bound');
      blocks.push(Buffer.from(value));
    }
    requireCondition(size > 0, 'oidc-provider-read-failed');
    return Buffer.concat(blocks, size);
  }
  /** Signal the same fixed timeout code without retaining provider error details. */
  function expire(_resolve, reject) {
    timer = setTimeout(() => {
      controller.abort();
      reject(new Error('oidc-provider-timeout'));
    }, remaining);
  }
  try {
    return await Promise.race([receive(), new Promise(expire)]);
  } catch {
    throw new Error('oidc-provider-read-failed');
  } finally {
    clearTimeout(timer);
    controller.abort();
    if (reader) {
      // Cleanup must not extend the deadline when a body ignores abort/cancellation.
      try { void reader.cancel().catch(ignoreCancellationFailure); } catch { /* No proof is returned. */ }
    }
  }
}

/** Discard only asynchronous cancellation diagnostics after the bounded read has settled. */
function ignoreCancellationFailure() {}

/** Select one unambiguous strong RSA signing key from the issuer's fresh bounded JWKS. */
function issuerKey(bytes, kid) {
  const document = parseJson(bytes, MAX_JWKS);
  requireCondition(document && !Array.isArray(document) && Array.isArray(document.keys) &&
    document.keys.length > 0 && document.keys.length <= 32, 'oidc-jwks-invalid');
  const seen = new Set();
  let selected;
  for (const key of document.keys) {
    requireCondition(key && !Array.isArray(key) && typeof key.kid === 'string' &&
      /^[A-Za-z0-9_.=-]{1,128}$/.test(key.kid) && !/[\s\x00-\x1f\x7f]/.test(key.kid) &&
      !seen.has(key.kid), 'oidc-jwks-invalid');
    seen.add(key.kid);
    if (key.kid === kid) selected = key;
  }
  requireCondition(selected && selected.kty === 'RSA' && selected.use === 'sig' &&
    (selected.alg === undefined || selected.alg === 'RS256') &&
    (selected.key_ops === undefined || (Array.isArray(selected.key_ops) && selected.key_ops.length === 1 &&
      selected.key_ops[0] === 'verify')) &&
    !['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'].some(name => Object.hasOwn(selected, name)), 'oidc-signing-key-invalid');
  const modulus = decode(selected.n, 1024);
  requireCondition(modulus.length >= 256 && modulus[0] !== 0 && selected.e === 'AQAB', 'oidc-signing-key-invalid');
  let key;
  try { key = createPublicKey({ key: { kty: 'RSA', n: selected.n, e: selected.e }, format: 'jwk' }); }
  catch { throw new Error('oidc-signing-key-invalid'); }
  requireCondition(key.asymmetricKeyType === 'rsa' && key.asymmetricKeyDetails.modulusLength >= 2048 &&
    key.asymmetricKeyDetails.modulusLength <= 8192, 'oidc-signing-key-invalid');
  return key;
}

/** Match signed claims to one independent source/caller/signer/job and supported exact subject form. */
function matchedClaims(claims, expected, now) {
  requireCondition(claims && typeof claims === 'object' && !Array.isArray(claims), 'oidc-claims-invalid');
  const matches = {
    iss: ISSUER, aud: AUDIENCE, repository: expected.repository,
    repository_id: expected.repository_id, repository_owner: expected.repository.split('/')[0],
    repository_owner_id: expected.repository_owner_id, repository_visibility: expected.repository_visibility,
    sha: expected.source_sha, ref: expected.ref, ref_type: expected.event === 'push' ? 'tag' : 'branch',
    ref_protected: 'true', event_name: expected.event, actor: expected.actor, actor_id: expected.actor_id,
    workflow_ref: `${expected.repository}/${expected.caller_path}@${expected.ref}`, workflow_sha: expected.caller_sha,
    job_workflow_ref: `${expected.signer_repository}/${expected.signer_path}@${expected.signer_sha}`,
    job_workflow_sha: expected.signer_sha, run_id: expected.run_id, run_attempt: expected.run_attempt,
    check_run_id: expected.check_run_id, runner_environment: 'github-hosted',
  };
  for (const [name, value] of Object.entries(matches)) {
    requireCondition(claims[name] === value, 'oidc-identity-mismatch');
  }
  const [owner, repository] = expected.repository.split('/');
  const ownerPart = expected.subject_mode === 'immutable' ? `${owner}@${expected.repository_owner_id}` : owner;
  const repositoryPart = expected.subject_mode === 'immutable' ? `${repository}@${expected.repository_id}` : repository;
  const scope = expected.environment === null ? `ref:${expected.ref}` : `environment:${expected.environment}`;
  requireCondition(claims.sub === `repo:${ownerPart}/${repositoryPart}:${scope}`, 'oidc-subject-mismatch');
  if (expected.environment === null) {
    requireCondition(!Object.hasOwn(claims, 'environment') && !Object.hasOwn(claims, 'environment_node_id'),
      'oidc-environment-mismatch');
  } else {
    requireCondition(claims.environment === expected.environment && claims.environment_node_id === expected.environment_node_id,
      'oidc-environment-mismatch');
  }
  for (const name of ['iat', 'nbf', 'exp']) {
    requireCondition(Number.isSafeInteger(claims[name]) && claims[name] > 0, 'oidc-time-invalid');
  }
  requireCondition(claims.iat <= now && claims.nbf <= now && claims.exp > now && claims.exp > claims.iat &&
    claims.exp - claims.iat <= 600 && now - claims.iat <= 300 && claims.nbf <= claims.exp, 'oidc-time-invalid');
  return matches;
}

/** Freeze the fixed noncredential evidence tree before retaining any private proof. */
function freezeTree(value) {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) freezeTree(child);
    Object.freeze(value);
  }
  return value;
}

class VerifiedProducerContext {
  /** Seal only authenticated records using a module-private construction capability. */
  constructor(capability, record) {
    requireCondition(capability === brand, 'oidc-proof-construction-denied');
    records.set(this, freezeTree(record));
    Object.freeze(this);
  }

  /** Prevent accidental serialization from turning a private proof into an offered permit. */
  toJSON() {
    throw new Error('oidc-proof-serialization-denied');
  }

  /** Keep inspection independent of bearer tokens, claims and arbitrary provider metadata. */
  [inspect.custom]() {
    return '[VerifiedProducerContext]';
  }
}

/** Authenticate the current trusted job with fixed-origin RS256 OIDC; never accept a caller token or keyset. */
export async function authenticateProducerContext(offered) {
  // Node applies some transport overrides at startup; removing them here cannot restore trust.
  for (const name of ['NODE_OPTIONS', 'NODE_EXTRA_CA_CERTS', 'NODE_TLS_REJECT_UNAUTHORIZED', 'NODE_USE_ENV_PROXY']) {
    requireCondition(process.env[name] === undefined, 'oidc-transport-environment-denied');
  }
  const expected = independentIntent(offered);
  const requestUrl = tokenRequestUrl(process.env.ACTIONS_ID_TOKEN_REQUEST_URL);
  const requestToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  requireCondition(typeof requestToken === 'string' && requestToken.length > 0 && requestToken.length <= 8192 &&
    !/[\s\x00-\x1f\x7f]/.test(requestToken), 'oidc-request-credential-unavailable');
  const deadline = performance.now() + 20000;
  const startedAt = Math.floor(Date.now() / 1000);
  const responseBytes = await fetchBody(requestUrl, requestToken, MAX_TOKEN * 2, deadline);
  const response = parseJson(responseBytes, MAX_TOKEN * 2);
  requireCondition(response && !Array.isArray(response) && typeof response.value === 'string' &&
    response.value.length <= MAX_TOKEN, 'oidc-token-response-invalid');
  const parts = response.value.split('.');
  requireCondition(parts.length === 3, 'oidc-token-format-invalid');
  const header = parseJson(decode(parts[0], 4096), 4096);
  requireCondition(header && !Array.isArray(header) && header.alg === 'RS256' && header.typ === 'JWT' &&
    typeof header.kid === 'string' && /^[A-Za-z0-9_.=-]{1,128}$/.test(header.kid) &&
    !/[\s\x00-\x1f\x7f]/.test(header.kid) &&
    Object.keys(header).every(name => ['alg', 'typ', 'kid', 'x5t', 'x5t#S256'].includes(name)), 'oidc-token-header-invalid');
  for (const name of ['x5t', 'x5t#S256']) {
    requireCondition(!Object.hasOwn(header, name) || (typeof header[name] === 'string' &&
      /^[A-Za-z0-9_-]{1,128}={0,2}$/.test(header[name]) && !/[\s\x00-\x1f\x7f]/.test(header[name])),
      'oidc-token-header-invalid');
  }
  const payload = decode(parts[1], 65536);
  const signature = decode(parts[2], 1024);
  const jwksBytes = await fetchBody(new URL(JWKS), null, MAX_JWKS, deadline);
  const key = issuerKey(jwksBytes, header.kid);
  let authenticated;
  try {
    authenticated = verify('RSA-SHA256', Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii'),
      { key, padding: constants.RSA_PKCS1_PADDING }, signature);
  } catch { throw new Error('oidc-signature-invalid'); }
  requireCondition(authenticated, 'oidc-signature-invalid');
  const now = Math.floor(Date.now() / 1000);
  requireCondition(now >= startedAt && performance.now() < deadline, 'oidc-stage-expired');
  const claims = parseJson(payload, 65536);
  const matched = matchedClaims(claims, expected, now);
  return new VerifiedProducerContext(brand, {
    schema_version: 1, state: 'oidc-job-context-observed', observed_at: now, expires_at: claims.exp,
    issuer: ISSUER, audience: AUDIENCE, key_id: header.kid,
    jwks: { url: JWKS, sha256: createHash('sha256').update(jwksBytes).digest('hex'), size: jwksBytes.length },
    context: { ...matched, environment: expected.environment, environment_node_id: expected.environment_node_id,
      subject_mode: expected.subject_mode },
    oidc_job_identity_authenticated: true,
    effective_environment_claim_authenticated: expected.environment !== null,
    environment_protection_authenticated: false, artifact_producer_authenticated: false,
    cryptographic_release_authenticated: false, production_catalog_accepted: false,
    signing_authorized: false, publication_authorized: false,
  });
}

/** Export only whitelisted noncredential observations from a live private proof; JSON cannot recreate it. */
export function producerContextRecord(proof) {
  requireCondition(records.has(proof), 'oidc-unverified-proof');
  const record = records.get(proof);
  const now = Math.floor(Date.now() / 1000);
  requireCondition(now >= record.observed_at && now < record.expires_at && now - record.observed_at <= 300,
    'oidc-proof-expired');
  return freezeTree(structuredClone(record));
}
