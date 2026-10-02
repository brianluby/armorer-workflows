# Mapped producer context v1

This experimental join binds the [current-job observer](controller-context-v1.md)
to the [fixed-issuer producer OIDC proof](producer-oidc-context-v1.md). It is an
identity prerequisite for a future fixed release controller. It does not sign
bytes, attest an artifact, create a draft, publish, or establish SLSA Build L2.

The controller supplies independently reviewed source, caller, reusable signer,
exact workflow/job display names and native runner expectations. The public
`authenticateMappedProducerContext({mapping, oidc})` interface does not accept a
check-run ID, token, keyset, offered JSON observation, executable, command, path,
predicate or provider callback. Source and OIDC expectations must agree. Release
mode admits only a stable `vMAJOR.MINOR.PATCH` tag or a dispatch at the expected
default branch; source ancestry and original/rerun permissions still require
independent native API verification. Qualification PR observations cannot enter
the producer join.

The fixed worker independently reads the complete source and attempt job graph,
maps one uniquely intended active job, and parses its separate check-run URL.
That check-run identity becomes the issuer expectation. Native RS256 then
verifies the fixed GitHub issuer, audience and source/caller/reusable signer/run/
attempt/check-run claims. A second full native observation must reproduce the
canonical snapshot digest and both job identities. Permission revocation, reruns,
caller/source changes, attempt job changes and environment control changes block
the join. The worker uses the existing exact observer intent/adapter types with
its bundled cancellation-aware GET method; older observer and transport bytes
remain unchanged.

Only a module-created private in-memory proof can reach
`mappedProducerContextRecord`. Serialized proof construction is denied; audit
JSON cannot authorize a later stage. Audit use requires a final native view no
older than 30 seconds and an unexpired issuer proof without clock rollback. IDs
cross the Python/Node boundary as canonical decimal strings, preserving values
above JavaScript's safe integer range. Errors use fixed codes and discard child
diagnostics and arbitrary issuer claims.

## Isolation and capability limits

Node 24 launches only the bundled worker using a fixed Python path:
`/usr/bin/python3` on Ubuntu 24.04 x86/ARM and `/opt/homebrew/bin/python3` on
macOS 15 ARM. Python 3.11 or newer is required. A missing or unsupported path is
an explicit qualification failure; caller `PATH` or a custom interpreter cannot
provide a fallback. Python remains a hosted-image dependency, not a fully pinned
or reproducible runtime. The worker downloads fixed gh 2.102.0 archive bytes,
checks archive and executable pins, and rehashes the executable before each GET.
These delivery pins do not authenticate an upstream signature or accept a
production catalog.

The parent reads `ARMORER_WORKFLOW_READ_TOKEN` only after validating the independent
intent. Supply the current workflow token with `contents: read` and `actions:
read`; this helper exposes no mutation routes. The Python worker receives only
that read token plus fixed path/locale and private home/temp settings. OIDC service
variables, Apple material, ambient GH credentials, proxy/debug state and Python
module inputs are excluded. The parent uses the existing platform-provided OIDC
request variables through the fixed issuer helper; no credential values are
returned or persisted. Parent and child use bounded JSON/pipes and private
temporary directories. Cancellation stops new reads, reaps separate native
process groups, waits for worker close and removes scratch. The parent has a
240-second worker deadline and a 75-second emergency termination grace. This
follows [Node 24 subprocess semantics](https://nodejs.org/download/release/v24.19.0/docs/api/child_process.html)
and [Python signal handling](https://docs.python.org/3.11/library/signal.html).
It does not claim memory zeroization or a sandbox for hostile same-process code.

`producer_job_authenticated` means that the API-mapped current job and signed
issuer identity agree. Required protection/approval, artifact writer identity,
cryptographic release verification, accepted catalogs, signing authorization and
publication authorization remain false. Even a signed environment claim joined
to an exact configuration does not prove current approval or effective
enforcement. Those unsupported gates must block the eventual release controller.

## Validation and adoption gates

The additive tests use ephemeral RSA keys and owned fixture children. They cover
unsafe intent before credential access, getter/shape attacks, exact IDs, separate
job/check-run identities, signature/source/signer/rerun substitutions, prerequisite
changes, strict JSON bounds, proof forgery/expiry, environment distinctions,
sterile child state and cancellation. Actual inert native processes exercise
SIGTERM during a read and immediately after spawn; synthetic protocol success
does not establish a live GitHub producer positive.

The native PR qualification separately uses the fixed worker/Python paths and
real pinned gh reads on all three supported hosted platforms. It observes the
intended qualification job and caller/source bytes without requesting live OIDC,
accessing signing secrets or mutating releases. Hosted receipts, source review
and accepted pins remain separate from operational acceptance. Before production
adoption, require an authorized live producer positive, independently accepted
roots/catalog, effective ref/environment/approval evidence, a complete fixed
artifact/inventory controller, protected Apple parity and publication/recovery
tests. None of those gates is satisfied by this join alone.
