/** Exercise real diagnostic decoding boundaries with inert strings and no native credentials or network. */
import assert from 'node:assert/strict';
import { fixedWorkerFailureDecoder, WORKER_PHASES, WORKER_CODES } from './combined_handoff_diagnostics_v1.mjs';

const prefix = 'ARMORER_COMBINED_FAILURE_V1';
const generic = { phase: 'worker-no-coded-error', code: 'unclassified', coded: false };
let groups = 0;

/** Feed exact chunks through the original decoder and return only its closed diagnostic snapshot. */
function decode(chunks) {
  const reader = fixedWorkerFailureDecoder();
  for (const chunk of chunks) reader.push(Buffer.from(chunk));
  return reader.snapshot();
}

for (const phase of WORKER_PHASES) {
  for (const code of WORKER_CODES) {
    assert.deepEqual(decode([`${prefix} ${phase} ${code}\n`]), { phase, code, coded: true });
  }
}
groups += 1;
const valid = `${prefix} reviewed-tool-members http-forbidden\n`;
for (let offset = 0; offset <= valid.length; offset += 1) {
  assert.deepEqual(decode([valid.slice(0, offset), valid.slice(offset)]),
    { phase: 'reviewed-tool-members', code: 'http-forbidden', coded: true });
}
groups += 1;
for (const offered of ['', valid.slice(0, -1), `${prefix} unsupported http-forbidden\n`,
  `${prefix} native-gh-api credential-marker-not-for-output\n`, `wrong ${valid}`, ` ${valid}`, `${valid.trim()} \n`,
  `${prefix} native-gh-api unclassified\r\n`, `${prefix} native-gh-api \0unclassified\n`, `${valid}${valid}`,
  `${prefix} native-gh-api ü\n`, `${prefix} native-gh-api ${'x'.repeat(200)}\n`, 'x'.repeat(20000)]) {
  assert.deepEqual(decode([offered]), generic);
}
groups += 1;
assert.deepEqual(decode(['unrelated credential-marker-not-for-output\n', valid]),
  { phase: 'reviewed-tool-members', code: 'http-forbidden', coded: true });
assert.deepEqual(decode(['x'.repeat(200) + '\n', valid]),
  { phase: 'reviewed-tool-members', code: 'http-forbidden', coded: true });
assert.deepEqual(decode([valid, 'x'.repeat(20000)]), generic);
groups += 1;
const frozen = fixedWorkerFailureDecoder();
assert.ok(Object.isFrozen(frozen));
assert.ok(Object.isFrozen(frozen.snapshot()));
assert.ok(!JSON.stringify(frozen.snapshot()).includes('credential-marker-not-for-output'));
assert.ok(!('proof' in frozen.snapshot()) && !('token' in frozen.snapshot()));
groups += 1;
for (const chunks of [[valid], [valid, valid], [valid, 'x'.repeat(20000)]]) {
  const reader = fixedWorkerFailureDecoder();
  for (const chunk of chunks) reader.push(Buffer.from(chunk));
  assert.equal(reader.hasFailure(), true);
}
for (const offered of ['', valid.slice(0, -1), `${prefix} unsupported http-forbidden\n`, 'x'.repeat(20000)]) {
  const reader = fixedWorkerFailureDecoder();
  reader.push(Buffer.from(offered));
  assert.equal(reader.hasFailure(), false);
}
groups += 1;
console.log(JSON.stringify({ fixed_diagnostic_groups: groups, worker_phases: WORKER_PHASES.length,
  error_codes: WORKER_CODES.length, raw_stderr_printed: false, release_authority: false }));
