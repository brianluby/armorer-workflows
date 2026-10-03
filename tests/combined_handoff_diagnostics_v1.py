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
         "io-unclassified", "unclassified")


def fixed_error_code(error):
    """Classify bounded known exception types without reading messages, URLs, headers, bodies or token values."""
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
