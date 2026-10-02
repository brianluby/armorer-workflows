# ADR 0006: Independently map current job before verifying producer OIDC

Status: proposed for review; production protection and artifact authority pending.

## Context

A verified issuer token authenticates its claims but does not independently
select the controller's intended job. Accepting a caller-offered check-run ID or
serialized observer JSON would let the offered data define its own acceptance
boundary. The existing current-job observer supplies an independent association,
but observations can change while a token is requested and verified.

## Decision

Add a versioned join that accepts only cross-bound independent source/job/OIDC
expectations. A fixed isolated Python worker uses pinned read-only native tools
to map the intended job. The parent derives the check-run expectation, verifies
the private issuer proof, then repeats the full native observation and compares
its canonical prerequisite digest. Only a fresh private in-memory join exports
whitelisted audit data. All protection, artifact, signing and publication gates
remain explicit and incomplete.

## Consequences

The fixed worker has bounded transport and cancellation-aware child reaping;
old source/transport bytes remain unchanged. This adds a fixed Python hosted
dependency and two native observations per authentication. Missing metadata,
unsupported policy/runtime, mutation, timeout or credential failure rejects
without fallback. Qualification fixtures and native PR mapping do not replace
the required authorized live producer, accepted policy/root, effective approval
and complete protected release controller.
