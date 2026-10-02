# Provider transport observation v1

`armorer_runtime.transport_v1` collects the independently expected complete
GitHub.com artifact set through native gh 2.102.0 fixed GET routes. Exact native
byte pins exist for Linux x86, Linux ARM and macOS ARM. This adapter does not
install gh, accept arbitrary API endpoints or allow caller-selected tool pins.
The workflow must provision the exact executable through a separately approved
tool-distribution channel. A version string alone is insufficient.

A trusted controller constructs `ExpectedRun` from independent source and
platform observations and its reviewed intent. It must establish the numeric
repository/workflow IDs, source checkout and REST head, expected branch/trigger,
builder SHA, run/attempt and complete selections before calling this adapter.
Do not copy expectations from an unsigned handoff or download receipt. For PR
qualification, independently verify the actual checkout merge and its parents;
PR transport success is never authorization for signing.

In a future isolated actions-read job, construct `QualifiedGhApi` with the pinned
executable and that job's ephemeral token, then enter `collect_handoffs`. The
context yields a read-only mapping from exact selection IDs to private inert
five-leaf directories, plus an audit receipt. Use the directories while the
context is open; they are removed afterward. Revalidate `verify_handoff_v3` against
independent inputs/root/version/tool identities and independently validate whole
CycloneDX documents. No transport API result itself authorizes credentials.
The adapter is internal: no public generic arbitrary-artifact/signature interface
or caller shell/custom-provenance input is added.

Before downloading, current and explicit attempts must agree with exact provider
repository/source/caller/runtime intent. Each artifact must be nonexpired and
created in the current attempt's provider-observed window with an independently
derived name. Compare exact archive SHA-256/size before ZIP member reading.
After downloading, recheck the latest attempt and complete artifact storage set.
Missing/extra/paginated/duplicate objects, old-attempt artifacts, pin substitutions
and changed digests/IDs fail the entire collection. The one-hour default freshness
policy can be independently narrowed or explicitly chosen up to one day; it
must never be learned from the artifact.

Only a bounded provider ZIP layer is decoded. Five regular leaves get new private
0400 files; .crate archives and .bin executables remain inert. ZIP64, encryption,
unsafe/nested names, duplicate/extra leaves, links/devices and unsupported
compression fail. See [ADR 0001](adr/0001-authenticated-provider-handoff.md) for
byte/time/disk bounds and the stable-filesystem assumption.

Every receipt retains `signing_authorized: false`,
`producer_job_authenticated: false`, and
`cryptographic_release_authenticated: false`. Its JSON is an audit record;
deserializing it cannot create a trust proof. The operator qualification mode
uses existing gh authentication without reading/exporting credential values;
it is explicitly different from live workflow-token isolation.

## Validation and remaining gates

Tests reject source/repository/fork/run/attempt/workflow substitutions, malformed
provider identities, stale or old-attempt uploads, duplicate/extra/paginated
sets, ZIP tampering, unsafe members, rerun/replacement races and clock expiry.
A real owned subprocess test enforces streaming limits and a sterile token
environment. Mocks supplement actual native qualification and have no signature
or provider-authentication credit.

Native macOS qualification used the exact official gh executable against the
existing nine-selection v3 run 37015567882, attempt 1, source merge
`1fa8bc6a15ce35b54c59145c621403a0ac2c1876`, API head
`a10fa183605e92bf9ed4a074ed194d637c5db5b6`, and builder
`bd76fe10dfb54b022c1f755b300bd498fa79fe48`. All nine provider archives, 45 leaf
identities and v3 semantics matched independently established source expectations.
Three real native API negatives rejected wrong attempt, source head and builder
SHA before archive download. No built payload was executed or nested-extracted.
This is a read-only operator qualification on macOS, not live native Linux
provider qualification or proof of workflow-token/environment protection.

Tickets #8/#9/#11 remain incomplete: qualified retained platform reports,
protected source/actor/ancestry/environment gates, fresh credentialed job
integration, final-byte factory and inventory, own complete signed rehearsal,
Apple evidence and human acceptance are still required. No credentialed job is
enabled by this slice, and green development CI is not release acceptance.
