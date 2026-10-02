/** Fixed current-job/issuer join; no offered receipt, signing operation or credential authority. */
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspect } from 'node:util';
import { authenticateProducerContext, producerContextRecord } from './producer_oidc_v1.mjs';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const proofs = new WeakMap();
const brand = Symbol('independently mapped producer');
const MAX_BYTES = 64 * 1024;
const SOURCE_FIELDS = ['repository', 'repository_id', 'owner_id', 'default_branch', 'run_id', 'run_attempt',
  'workflow_id', 'caller_path', 'caller_commit', 'caller_sha256', 'head_commit', 'source_commit', 'head_branch',
  'event', 'ref', 'actor_id', 'actor_login', 'triggering_actor_id', 'triggering_actor_login', 'referenced_workflows',
  'pull_request', 'base_commit', 'base_branch', 'max_age_seconds'];
const OIDC_FIELDS = ['repository', 'repository_id', 'repository_owner_id', 'repository_visibility', 'source_sha',
  'ref', 'event', 'default_branch', 'actor', 'actor_id', 'caller_path', 'caller_sha', 'signer_repository',
  'signer_path', 'signer_sha', 'run_id', 'run_attempt', 'environment', 'environment_node_id', 'subject_mode', 'protected_ref'];
const NATIVE = {
  'ubuntu-24.04': { platform: 'linux', arch: 'x64', python: '/usr/bin/python3', target: 'x86_64-unknown-linux-gnu', size: 42086560,
    sha256: '7469124f706944133d6a169691dd1c6c3511b12e85878d255e044e2948df4c9b' },
  'ubuntu-24.04-arm': { platform: 'linux', arch: 'arm64', python: '/usr/bin/python3', target: 'aarch64-unknown-linux-gnu', size: 39059616,
    sha256: '93308395c2d296a63a662742c6366e4db413d2a4870d07bd9b84e491c065d65d' },
  'macos-15': { platform: 'darwin', arch: 'arm64', python: '/opt/homebrew/bin/python3', target: 'aarch64-apple-darwin', size: 39834784,
    sha256: '8a4258433c81106343144857750316241759d06dcf16265cf3c4864a8f2f2ad6' },
};

/** Throw only fixed codes; provider output, stdin values and credential values never become diagnostics. */
function requireCondition(value, code = 'producer-context-invalid') {
  if (!value) throw new Error(code);
}

/** Parse bounded JSON while rejecting duplicate decoded keys, prototype keys and trailing input. */
function parseJson(bytes, limit) {
  requireCondition(Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= limit, 'producer-json-bound');
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { throw new Error('producer-json-invalid'); }
  requireCondition(text.charCodeAt(0) !== 0xfeff, 'producer-json-invalid');
  let position = 0;
  let nodes = 0;

  /** Consume only JSON whitespace, without accepting other Unicode separators. */
  function whitespace() {
    while (position < text.length && ' \t\r\n'.includes(text[position])) position += 1;
  }

  /** Decode one bounded JSON string and preserve exact decoded-key identity for duplicate checks. */
  function string() {
    const start = position;
    requireCondition(text[position] === '"', 'producer-json-invalid');
    position += 1;
    while (position < text.length) {
      const char = text[position];
      position += 1;
      if (char === '\\') {
        requireCondition(position < text.length, 'producer-json-invalid');
        position += 1;
      } else if (char === '"') {
        try { return JSON.parse(text.slice(start, position)); }
        catch { throw new Error('producer-json-invalid'); }
      }
    }
    throw new Error('producer-json-invalid');
  }

  /** Walk one JSON value with explicit depth/node limits before accepting any metadata object. */
  function value(depth) {
    nodes += 1;
    requireCondition(depth <= 16 && nodes <= 4096, 'producer-json-bound');
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
          !Object.hasOwn(result, key), 'producer-json-key-invalid');
        whitespace();
        requireCondition(text[position] === ':', 'producer-json-invalid');
        position += 1;
        result[key] = value(depth + 1);
        whitespace();
        const separator = text[position];
        position += 1;
        if (separator === '}') return result;
        requireCondition(separator === ',', 'producer-json-invalid');
        whitespace();
      }
      throw new Error('producer-json-invalid');
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
        requireCondition(separator === ',', 'producer-json-invalid');
      }
      throw new Error('producer-json-invalid');
    }
    const matched = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(position));
    requireCondition(matched !== null, 'producer-json-invalid');
    position += matched[0].length;
    const result = JSON.parse(matched[0]);
    requireCondition(typeof result !== 'number' || Number.isFinite(result), 'producer-json-invalid');
    return result;
  }

  const result = value(0);
  whitespace();
  requireCondition(position === text.length, 'producer-json-invalid');
  return result;
}

/** Copy exactly one plain data record without executing getters or inheriting hidden policy fields. */
function data(value, names) {
  requireCondition(value && [Object.prototype, null].includes(Object.getPrototypeOf(value)) &&
    Reflect.ownKeys(value).length === names.length);
  const result = Object.create(null);
  for (const name of names) {
    const item = Object.getOwnPropertyDescriptor(value, name);
    requireCondition(item && Object.hasOwn(item, 'value') && item.enumerable);
    result[name] = item.value;
  }
  return result;
}

/** Keep platform identifiers exact across the Python/Node boundary, including IDs above 2^53. */
function identifier(value) {
  return typeof value === 'string' && /^[1-9][0-9]{0,18}$/.test(value) &&
    !/[\s\x00-\x1f\x7f]/.test(value) && BigInt(value) <= 2n ** 63n - 1n;
}

/** Admit bounded fixed policy strings without controls, whitespace or normalization. */
function text(value, maximum = 255) {
  return typeof value === 'string' && value.length > 0 && value.length <= maximum &&
    !/[\s\x00-\x1f\x7f]/.test(value);
}

/** Preserve exact display names with internal spaces while rejecting controls and edge whitespace. */
function displayText(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 255 && value === value.trim() &&
    !/[\x00-\x1f\x7f]/.test(value);
}

/** Clone a bounded plain array of own data elements before sending any independent expectation. */
function array(value, limit) {
  requireCondition(Array.isArray(value) && Object.getPrototypeOf(value) === Array.prototype &&
    value.length <= limit && Reflect.ownKeys(value).length === value.length + 1);
  const result = [];
  for (let index = 0; index < value.length; index += 1) {
    const item = Object.getOwnPropertyDescriptor(value, String(index));
    requireCondition(item && Object.hasOwn(item, 'value') && item.enumerable);
    result.push(item.value);
  }
  return result;
}

/** Freeze only checked data; no external reference can change expectations during native/OIDC reads. */
function freeze(value) {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

/** Independently cross-bind source, caller, immutable reusable signer and exact intended job. */
function intent(offered) {
  const expected = data(offered, ['mapping', 'oidc']);
  expected.mapping = data(expected.mapping, ['source', 'workflow_name', 'job_name', 'runner_label',
    'qualification_only', 'environment']);
  const mapping = expected.mapping;
  mapping.source = data(mapping.source, SOURCE_FIELDS);
  expected.oidc = data(expected.oidc, OIDC_FIELDS);
  const source = mapping.source;
  const oidc = expected.oidc;
  requireCondition(mapping.qualification_only === false && ['push', 'workflow_dispatch'].includes(source.event) &&
    source.pull_request === null && source.base_commit === null && source.base_branch === null,
    'producer-trigger-denied');
  for (const name of ['repository_id', 'owner_id', 'run_id', 'run_attempt', 'workflow_id', 'actor_id', 'triggering_actor_id']) {
    requireCondition(identifier(source[name]));
  }
  for (const name of ['caller_commit', 'head_commit', 'source_commit']) {
    requireCondition(text(source[name], 40) && /^[0-9a-f]{40}$/.test(source[name]));
  }
  requireCondition(text(source.caller_sha256, 64) && /^[0-9a-f]{64}$/.test(source.caller_sha256) &&
    source.caller_commit === source.source_commit && source.head_commit === source.source_commit &&
    Number.isSafeInteger(source.max_age_seconds) && source.max_age_seconds > 0 && source.max_age_seconds <= 3600);
  for (const name of ['repository', 'default_branch', 'head_branch', 'event', 'ref', 'actor_login',
    'triggering_actor_login', 'caller_path']) requireCondition(text(source[name]));
  source.referenced_workflows = array(source.referenced_workflows, 64).map(row => {
    const parts = array(row, 2);
    requireCondition(parts.length === 2 && text(parts[0]) && text(parts[1], 40) && /^[0-9a-f]{40}$/.test(parts[1]));
    return parts;
  });
  requireCondition(displayText(mapping.workflow_name) && displayText(mapping.job_name));
  requireCondition(text(mapping.runner_label));
  const native = NATIVE[mapping.runner_label];
  requireCondition(native && native.platform === process.platform && native.arch === process.arch,
    'producer-native-platform-unsupported');
  const matches = { repository: 'repository', repository_id: 'repository_id', owner_id: 'repository_owner_id',
    source_commit: 'source_sha', caller_commit: 'caller_sha', caller_path: 'caller_path', default_branch: 'default_branch',
    event: 'event', ref: 'ref', actor_login: 'actor', actor_id: 'actor_id', run_id: 'run_id', run_attempt: 'run_attempt' };
  for (const [name, counterpart] of Object.entries(matches)) requireCondition(source[name] === oidc[counterpart]);
  requireCondition(oidc.signer_repository === 'brianluby/armorer-workflows' && text(oidc.signer_sha, 40) &&
    /^[0-9a-f]{40}$/.test(oidc.signer_sha) && text(oidc.signer_path, 200) &&
    /^\.github\/workflows\/[A-Za-z0-9_-][A-Za-z0-9_.-]*\.yml$/.test(oidc.signer_path) &&
    !oidc.signer_path.includes('..') && source.referenced_workflows.some(row =>
      row[0] === `${oidc.signer_repository}/${oidc.signer_path}@${oidc.signer_sha}` && row[1] === oidc.signer_sha));
  requireCondition(['public', 'private'].includes(oidc.repository_visibility) &&
    ['legacy', 'immutable'].includes(oidc.subject_mode) && oidc.protected_ref === true);
  if (mapping.environment === null) {
    requireCondition(oidc.environment === null && oidc.environment_node_id === null);
  } else {
    mapping.environment = data(mapping.environment, ['name', 'environment_id', 'node_id', 'reviewer_ids',
      'default_branch', 'wait_minutes']);
    const environment = mapping.environment;
    environment.reviewer_ids = array(environment.reviewer_ids, 6);
    requireCondition(['release-signing', 'release-publish'].includes(environment.name) &&
      identifier(environment.environment_id) && text(environment.node_id, 128) &&
      environment.reviewer_ids.length > 0 && environment.reviewer_ids.every(identifier) &&
      environment.default_branch === source.default_branch && Number.isSafeInteger(environment.wait_minutes) &&
      environment.wait_minutes >= 0 && environment.wait_minutes <= 43200 &&
      environment.name === oidc.environment && environment.node_id === oidc.environment_node_id);
  }
  requireCondition((source.event === 'workflow_dispatch' && source.ref === `refs/heads/${source.default_branch}`) ||
    (source.event === 'push' && /^refs\/tags\/v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/.test(source.ref)),
    'producer-trigger-denied');
  return freeze(expected);
}

/** Run only the bundled isolated Python worker with bounded pipes and no OIDC/Apple/proxy/debug state. */
async function observeNative(expected) {
  const token = process.env.ARMORER_WORKFLOW_READ_TOKEN;
  requireCondition(typeof token === 'string' && token.length > 0 && token.length <= 4096 &&
    !/[\s\x00-\x1f\x7f]/.test(token), 'producer-read-token-unavailable');
  const payload = Buffer.from(JSON.stringify(expected.mapping));
  requireCondition(payload.length > 0 && payload.length <= MAX_BYTES);
  const scratch = await mkdtemp(join(tmpdir(), 'armorer-mapped-producer-'));
  const native = NATIVE[expected.mapping.runner_label];
  const code = 'import sys; sys.path.insert(0,sys.argv.pop()); from armorer_runtime.producer_job_worker_v1 import main; main()';
  let child;
  try {
    const output = await new Promise((resolve, reject) => {
      let timer;
      let grace;
      let size = 0;
      const blocks = [];
      let settled = false;
      let failed = false;
      /** Cancel cooperatively so the worker can reap native children before its own close event. */
      function fail() {
        if (settled || failed) return;
        failed = true;
        clearTimeout(timer);
        if (child?.pid) {
          try { process.kill(-child.pid, 'SIGTERM'); } catch { /* Fixed error below. */ }
          /** Kill only an unresponsive worker after its cancellation-aware native cleanup grace. */
          grace = setTimeout(function killUnresponsiveWorker() {
            try { process.kill(-child.pid, 'SIGKILL'); } catch { /* Close still owns completion. */ }
          }, 75000);
        }
      }
      child = spawn(native.python, ['-I', '-c', code, root], {
        cwd: scratch, detached: true, stdio: ['pipe', 'pipe', 'ignore'],
        env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C.UTF-8', HOME: scratch,
          TMPDIR: scratch, ARMORER_WORKFLOW_READ_TOKEN: token },
      });
      timer = setTimeout(fail, 240000);
      child.on('error', fail);
      child.stdin.on('error', fail);
      child.stdout.on('error', fail);
      child.stdout.on('data', block => {
        if (failed) return;
        size += block.length;
        if (size > MAX_BYTES) { fail(); return; }
        blocks.push(Buffer.from(block));
      });
      child.on('close', status => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        clearTimeout(grace);
        if (failed || status !== 0 || size === 0) { reject(new Error('producer-native-observation-failed')); return; }
        resolve(Buffer.concat(blocks, size));
      });
      child.stdin.end(payload);
    });
    return nativeRecord(parseJson(output, MAX_BYTES), expected);
  } finally {
    if (child && child.exitCode === null && child.signalCode === null) {
      try { process.kill(-child.pid, 'SIGKILL'); } catch { /* No proof is returned. */ }
    }
    await rm(scratch, { recursive: true, force: true });
  }
}

/** Validate only compact worker data, exact IDs and freshness; a caller cannot offer this record. */
function nativeRecord(offered, expected) {
  const record = data(offered, ['schema_version', 'state', 'observed_at', 'run_started_at', 'snapshot_sha256',
    'candidate_qualification_only', 'source', 'job', 'environment', 'native_distribution',
    'source_provider_authenticated', 'current_job_mapping_observed', 'producer_job_authenticated',
    'environment_protection_authenticated', 'production_catalog_accepted', 'signing_authorized', 'publication_authorized']);
  const now = Math.floor(Date.now() / 1000);
  requireCondition(record.schema_version === 1 && record.state === 'independently-mapped-producer-job' &&
    record.candidate_qualification_only === false && Number.isSafeInteger(record.observed_at) &&
    record.observed_at > 0 && record.observed_at <= now && now - record.observed_at <= 30 &&
    Number.isSafeInteger(record.run_started_at) && record.run_started_at > 0 &&
    record.run_started_at <= record.observed_at && record.observed_at - record.run_started_at <= expected.mapping.source.max_age_seconds &&
    text(record.snapshot_sha256, 64) && /^[0-9a-f]{64}$/.test(record.snapshot_sha256));
  requireCondition(record.source_provider_authenticated === true && record.current_job_mapping_observed === true &&
    ['producer_job_authenticated', 'environment_protection_authenticated', 'production_catalog_accepted',
      'signing_authorized', 'publication_authorized'].every(name => record[name] === false));
  record.source = data(record.source, ['repository', 'repository_id', 'owner_id', 'commit', 'caller_commit',
    'caller_sha256', 'run_id', 'run_attempt']);
  const source = expected.mapping.source;
  for (const [name, wanted] of Object.entries({ repository: source.repository, repository_id: source.repository_id,
    owner_id: source.owner_id, commit: source.source_commit, caller_commit: source.caller_commit,
    caller_sha256: source.caller_sha256, run_id: source.run_id, run_attempt: source.run_attempt })) {
    requireCondition(record.source[name] === wanted);
  }
  record.job = data(record.job, ['job_id', 'check_run_id', 'name', 'workflow_name', 'runner_label', 'started_at']);
  requireCondition(identifier(record.job.job_id) && identifier(record.job.check_run_id) &&
    record.job.name === expected.mapping.job_name && record.job.workflow_name === expected.mapping.workflow_name &&
    record.job.runner_label === expected.mapping.runner_label && Number.isSafeInteger(record.job.started_at) &&
    record.job.started_at >= record.run_started_at && record.job.started_at <= record.observed_at);
  if (expected.mapping.environment === null) requireCondition(record.environment === null);
  else {
    record.environment = data(record.environment, ['name', 'id', 'node_id', 'configuration_sha256', 'state',
      'current_attempt_approval', 'effective_enforcement']);
    const environment = expected.mapping.environment;
    requireCondition(record.environment.name === environment.name && record.environment.id === environment.environment_id &&
      record.environment.node_id === environment.node_id && text(record.environment.configuration_sha256, 64) &&
      /^[0-9a-f]{64}$/.test(record.environment.configuration_sha256) &&
      ['unknown', 'configured', 'disabled'].includes(record.environment.state) &&
      record.environment.current_attempt_approval === 'unsupported' && record.environment.effective_enforcement === 'unsupported');
  }
  const native = NATIVE[expected.mapping.runner_label];
  requireCondition(record.native_distribution?.version === '2.102.0' &&
    record.native_distribution.source_commit === 'fc4b137cdef0a6bd28fd461b7cf9c84a5812a8cd' &&
    record.native_distribution.target === native.target && record.native_distribution.executable?.sha256 === native.sha256 &&
    record.native_distribution.executable.size === native.size &&
    record.native_distribution.production_catalog_accepted === false && record.native_distribution.upstream_signature_authenticated === false);
  return freeze(record);
}

class MappedProducerContext {
  /** Retain only module-created native/issuer joins with no serialized construction capability. */
  constructor(capability, oidcProof, native) {
    requireCondition(capability === brand, 'producer-proof-construction-denied');
    proofs.set(this, { oidcProof, native });
    Object.freeze(this);
  }

  /** Keep audit JSON from being mistaken for an in-memory authenticated producer context. */
  toJSON() {
    throw new Error('producer-proof-serialization-denied');
  }

  /** Inspect only a fixed type marker, never credentials or arbitrary provider metadata. */
  [inspect.custom]() {
    return '[MappedProducerContext]';
  }
}

/** Join independently mapped source/job identity with fresh fixed-issuer OIDC and final native rechecks. */
export async function authenticateMappedProducerContext(offered) {
  try {
    const expected = intent(offered);
    const before = await observeNative(expected);
    const oidc = await authenticateProducerContext({ ...expected.oidc, check_run_id: before.job.check_run_id });
    const after = await observeNative(expected);
    requireCondition(after.snapshot_sha256 === before.snapshot_sha256 &&
      after.job.job_id === before.job.job_id && after.job.check_run_id === before.job.check_run_id &&
      after.observed_at >= before.observed_at, 'producer-prerequisites-changed');
    // Revalidate the original private issuer proof after the final source/API observation.
    producerContextRecord(oidc);
    return new MappedProducerContext(brand, oidc, after);
  } catch {
    throw new Error('producer-context-authentication-failed');
  }
}

/** Export whitelisted identity audit data only while both the private issuer proof and native view are fresh. */
export function mappedProducerContextRecord(proof) {
  requireCondition(proofs.has(proof), 'producer-unverified-proof');
  const { oidcProof, native } = proofs.get(proof);
  const now = Math.floor(Date.now() / 1000);
  requireCondition(now >= native.observed_at && now - native.observed_at <= 30, 'producer-proof-expired');
  const oidc = producerContextRecord(oidcProof);
  return freeze({ schema_version: 1, state: 'mapped-producer-context-authenticated', observed_at: native.observed_at,
    native_source: { ...native.source }, native_job: { ...native.job }, source_snapshot_sha256: native.snapshot_sha256,
    oidc, source_provider_authenticated: true, current_job_mapping_authenticated: true,
    producer_job_authenticated: true, environment_configuration: native.environment,
    environment_protection_authenticated: false, artifact_producer_authenticated: false,
    cryptographic_release_authenticated: false, production_catalog_accepted: false,
    signing_authorized: false, publication_authorized: false });
}
