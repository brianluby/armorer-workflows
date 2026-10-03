/** Decode a bounded closed diagnostic vocabulary; no stderr text becomes authorization or raw output. */
export const WORKER_PHASES = Object.freeze([
  "arguments", "native-gh-install", "native-gh-api", "source-context", "runtime-bytes",
  "selection-inputs", "provider-run", "reviewed-tool-members", "archive-pair-reader",
  "final-byte-layout", "source-recheck", "emit-record", "worker-no-coded-error"
]);
export const WORKER_CODES = Object.freeze([
  "http-forbidden", "http-not-found", "http-rate-limited", "http-server-error", "http-other",
  "network-unclassified", "timeout", "invariant-rejected", "metadata-decode", "metadata-key",
  "io-unclassified", "unclassified", "invariant-run-identity", "invariant-run-state",
  "invariant-workflow-pin", "invariant-pr-identity", "invariant-artifact-set",
  "invariant-artifact-identity", "invariant-upload-window", "invariant-zip-layout",
  "invariant-byte-identity", "invariant-staging-budget", "invariant-expectations",
  "invariant-source-tree", "invariant-provider-race", "invariant-local-race",
  "invariant-freshness", "invariant-policy-semantics", "invariant-build-semantics"
]);
const prefix = 'ARMORER_COMBINED_FAILURE_V1';

/** Drain arbitrary chunks with fixed total/line bounds and retain only a single recognized enum pair. */
export function fixedWorkerFailureDecoder() {
  let line = '';
  let discard = false;
  let total = 0;
  let found;
  let ambiguous = false;

  /** Accept only a complete exact ASCII protocol line with two supported fixed labels. */
  function finishLine() {
    if (!discard) {
      const parts = line.split(' ');
      if (parts.length === 3 && parts[0] === prefix && WORKER_PHASES.includes(parts[1]) && WORKER_CODES.includes(parts[2])) {
        if (found) ambiguous = true;
        found = Object.freeze({ phase: parts[1], code: parts[2] });
      }
    }
    line = '';
    discard = false;
  }

  /** Discard oversized, non-ASCII and unrelated lines while continuously draining the owned pipe. */
  function push(block) {
    for (const byte of block) {
      total += 1;
      if (total > 16384) { line = ''; discard = true; return; }
      if (byte === 10) { finishLine(); continue; }
      if (discard) continue;
      if (byte < 32 || byte > 126 || line.length >= 96) { line = ''; discard = true; continue; }
      line += String.fromCharCode(byte);
    }
  }

  /** An absent, truncated or ambiguous message yields fixed generic diagnostics and never raw stderr. */
  function snapshot() {
    if (total > 16384 || ambiguous || !found) {
      return Object.freeze({ phase: 'worker-no-coded-error', code: 'unclassified', coded: false });
    }
    return Object.freeze({ ...found, coded: true });
  }

  /** Remember any recognized failure even when ambiguity or overflow requires generic display labels. */
  function hasFailure() {
    return found !== undefined;
  }

  return Object.freeze({ push, snapshot, hasFailure });
}
