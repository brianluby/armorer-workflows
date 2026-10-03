"""Emit only fixed qualification failure labels; diagnostics confer no producer or release authority."""
import json
import urllib.error

from armorer_runtime.common import Failure

PREFIX = "ARMORER_COMBINED_FAILURE_V1"
PHASES = ("arguments", "native-gh-install", "native-gh-api", "source-context", "runtime-bytes",
          "selection-inputs", "provider-run", "reviewed-tool-members", "archive-pair-reader",
          "final-byte-layout", "source-recheck", "emit-record", "worker-no-coded-error")
CODES = ("http-forbidden", "http-not-found", "http-rate-limited", "http-server-error", "http-other",
         "network-unclassified", "timeout", "invariant-rejected", "metadata-decode", "metadata-key",
         "io-unclassified", "unclassified", "invariant-run-identity", "invariant-run-state",
         "invariant-workflow-pin", "invariant-pr-identity", "invariant-artifact-set",
         "invariant-artifact-identity", "invariant-upload-window", "invariant-zip-layout",
         "invariant-byte-identity", "invariant-staging-budget", "invariant-expectations",
         "invariant-source-tree", "invariant-provider-race", "invariant-local-race",
         "invariant-freshness", "invariant-policy-semantics", "invariant-build-semantics")

# Only these exact owned constant messages can select a more specific fixed label.
# Unknown text, offered values and dynamic errors retain the generic invariant code.
INVARIANTS = {
    "provider run or attempt mismatch": "invariant-run-identity",
    "provider source, trigger or caller mismatch": "invariant-run-identity",
    "provider repository or fork mismatch": "invariant-run-identity",
    "provider run is failed, pending or unsupported": "invariant-run-state",
    "combined run must be active": "invariant-run-state",
    "missing bounded reusable workflow identities": "invariant-workflow-pin",
    "executing builder pin mismatch": "invariant-workflow-pin",
    "combined policy workflow pin mismatch": "invariant-workflow-pin",
    "combined PR identity mismatch": "invariant-pr-identity",
    "combined PR head mismatch": "invariant-pr-identity",
    "incomplete or extra provider artifact set": "invariant-artifact-set",
    "unexpected or duplicate provider artifact name": "invariant-artifact-set",
    "duplicate provider artifact ID": "invariant-artifact-set",
    "missing provider artifact": "invariant-artifact-set",
    "artifact identity, name or expiry mismatch": "invariant-artifact-identity",
    "missing bounded provider archive byte identity": "invariant-artifact-identity",
    "artifact belongs to another run or source": "invariant-artifact-identity",
    "artifact is outside the exact attempt upload window": "invariant-upload-window",
    "combined observation outside exact attempt upload window": "invariant-upload-window",
    "combined ZIP too short": "invariant-zip-layout",
    "combined ZIP directory invalid": "invariant-zip-layout",
    "combined ZIP expansion invalid": "invariant-zip-layout",
    "combined provider ZIP failed closed": "invariant-zip-layout",
    "unsupported, ambiguous or unbounded provider ZIP directory": "invariant-zip-layout",
    "provider ZIP leaf set mismatch": "invariant-zip-layout",
    "unsafe provider ZIP member": "invariant-zip-layout",
    "unsupported policy provider ZIP directory": "invariant-zip-layout",
    "combined provider archive bytes mismatch": "invariant-byte-identity",
    "combined archive staging budget exceeded": "invariant-staging-budget",
    "combined archive and leaf staging budget exceeded": "invariant-staging-budget",
    "combined run contexts differ": "invariant-expectations",
    "combined duplicate or foreign build expectation": "invariant-expectations",
    "combined build and policy source inputs differ": "invariant-expectations",
    "combined build source tree differs from independent policy source": "invariant-source-tree",
    "independent policy source input mismatch": "invariant-source-tree",
    "combined artifact detail changed": "invariant-provider-race",
    "combined final artifact detail changed": "invariant-provider-race",
    "combined latest and explicit attempt differ": "invariant-provider-race",
    "combined provider state changed": "invariant-provider-race",
    "combined local leaf changed": "invariant-local-race",
    "provider attempt is stale or future": "invariant-freshness",
    "combined transport expired or clock reversed": "invariant-freshness",
    "combined final freshness expired": "invariant-freshness",
    "combined handoff or policy snapshot expired": "invariant-freshness",
    "combined policy exception expired": "invariant-freshness",
    "policy source/run/selection/policy/runtime mismatch": "invariant-policy-semantics",
    "qualified policy tool identity mismatch": "invariant-policy-semantics",
    "policy report bytes mismatch": "invariant-policy-semantics",
    "combined report semantics changed": "invariant-policy-semantics",
    "handoff inventory byte mismatch": "invariant-build-semantics",
    "v2 tool identity mismatch": "invariant-build-semantics",
}


def fixed_error_code(error):
    """Classify known types and bounded exact owned messages without rendering arbitrary content or metadata."""
    seen = set()
    fallback = "unclassified"
    for _ in range(8):
        if error is None or id(error) in seen:
            break
        seen.add(id(error))
        if isinstance(error, urllib.error.HTTPError):
            return {403: "http-forbidden", 404: "http-not-found", 429: "http-rate-limited",
                    500: "http-server-error", 502: "http-server-error", 503: "http-server-error",
                    504: "http-server-error"}.get(error.code, "http-other")
        if isinstance(error, TimeoutError):
            return "timeout"
        if isinstance(error, urllib.error.URLError):
            return "network-unclassified"
        if isinstance(error, (Failure, AssertionError)):
            fallback = "invariant-rejected"
            if type(error) is Failure and len(error.args) == 1 and type(error.args[0]) is str and len(error.args[0]) <= 160:
                fallback = INVARIANTS.get(error.args[0], fallback)
        elif isinstance(error, (json.JSONDecodeError, UnicodeError)):
            fallback = "metadata-decode"
        elif isinstance(error, KeyError):
            fallback = "metadata-key"
        elif isinstance(error, OSError):
            fallback = "io-unclassified"
        error = error.__cause__
    return fallback


def failure_line(phase, error):
    """Render one closed-vocabulary line, replacing unsupported phases rather than printing offered text."""
    phase = phase if phase in PHASES else "worker-no-coded-error"
    return PREFIX + " " + phase + " " + fixed_error_code(error) + "\n"
