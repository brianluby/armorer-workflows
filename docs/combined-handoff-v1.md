# Combined producer handoffs v1

The standalone collectors require their artifact kind to be the run's complete
set. A producer run needs both build handoffs and independent policy reports.
`collect_producer_handoffs` validates that combined set in one active run and
attempt, retaining the existing v3 build and v1 policy semantics unchanged.

The internal controller independently supplies both run expectations, selections,
source inputs, runtime helpers, package/root/tool expectations, policy and catalog.
Their shared identities must match before credential access or network reads.
Build and policy records cannot supply those expectations. Every build source
file digest must match the separately expected complete policy source tree.

The collector requires both exact immutable reusable workflow pins, the active
latest and explicit attempt, a complete artifact listing, stable per-artifact
details, matching whole ZIP size/digest and exact inert regular member sets.
It checks the existing graph/SBOM/build handoff and policy/advisory semantics,
attempt upload windows, final run/list/detail rereads and unchanged local leaves.
It rechecks freshness and exception expiry at the final boundary. Build payloads
are never executed, and source `.crate` archives are never extracted.

Private mode 0700 directories and mode 0400 leaves exist only inside the context
manager. Total archive plus expanded staging is limited to 4 GiB, checked before
download and expansion. The current single-page collector supports **1–32
selections / 2–64 artifacts**. A larger set returns an explicit unsupported error;
it never validates a subset. Larger configurations require a qualified paginated
successor, including the corresponding artifact-writer observer. This is an
implementation limit to resolve before claiming broader v0.1 adoption support.

PR runs require explicit `qualification_only=True`. This mode and a serialized
receipt cannot authorize signing or publication. Storage reads and unsigned
semantics leave producer OIDC, artifact-producer authority, accepted production
catalog/root, effective protections and cryptographic release authentication
unproven. The production integration must use fresh original private mapped-OIDC
and writer observations; their audit JSON cannot reconstruct those proofs.

## Native integration rehearsal

The separate workflow invokes the unchanged pinned build and policy workflows
for library, CLI and service profiles on Linux x64, Linux ARM64 and macOS ARM64.
Three native readers download all eighteen real archives using the qualified
native `gh` and an isolated ephemeral read token. Their Python process receives
no OIDC, Apple or publication credentials and executes no consuming build code.

Each reader checks nine semantic pairs against committed rehearsal source and
fixed runtime bytes, then joins all eighteen measured ZIP identities to fresh
private artifact-writer observations. Expected uploader job names come from the
fixed workflow shape. A live negative join substitutes a downloaded ZIP digest
and must reject against the original private writer proof. Audit output retains
actual source/runtime/job/archive identities without credentials.

Measured ZIP sizes are positive safe integers; the writer proof preserves exact
decimal strings from ProtoJSON. Their join compares canonical decimal values
without lossy coercion and also rechecks the REST size. Twenty-one synthetic
integration groups exercise the original private proof interface, including
valid eighteen-archive joins, unsafe or substituted sizes, copied and expired
proofs, and digest/source/set mismatches. A separate Node 24 fixture action drops
unused injected runtime credentials before these tests. The native rehearsal
uses the same join helper with live provider observations.

The new workflow ID is discovered from authenticated run metadata **only in this
qualification mode**. Production controllers need an independent expected ID.
Rehearsal config/catalog inputs and the assembly runtime identity are explicitly
fixture inputs; qualification does not promote them to an accepted production
context. PR refs are unsupported by the final-release assembler; the PR rehearsal
records that gate and does not rewrite its source ref. A later non-PR execution
can check that the nine-selection full payload set blocks the two unsigned macOS
executables and separately qualify the seven Linux/library payload transforms.
That smaller qualification does not earn Apple parity or complete-release credit.

The full producer still needs accepted independent context/catalog/root, protected
credential boundaries, real final-byte signing and strict complete-release
verification. Apple finalization, immutable publication, both pilots and human
review/acceptance remain required for the full v0.1 baseline.
