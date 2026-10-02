# Independent policy observations v1

Status: implemented for review and native qualification; production catalog acceptance,
authenticated producer-job integration and protected finalization remain pending.
This is an unsigned observation contract. It does not authorize signing or establish
SLSA Build L2. Existing CI, builders, transport adapters, schemas and tool pins retain
their versioned behavior.

Call `brianluby/armorer-workflows/.github/workflows/rust-policy-v1.yml` by its reviewed
full commit SHA. The caller needs `contents: read`; no secrets, OIDC permissions,
shell inputs or provenance inputs are accepted. Keep the existing CI/build calls:
this additional workflow records policy checks and does not replace tests or builds.
Pin that same workflow repository/commit in `armorer.lock`, with runtime version
`0.1.0` and the exact current configuration hash. A moving, stale or different lock
pin fails. Catalog adoption still requires independent human review.

The supported compiler is exactly Rust 1.95.0. Linux x86-64, Linux ARM64 and macOS
ARM64 run natively; other compilers/targets fail. The independent job builds only
the fixed trusted intent validator outside caller source, then discovers selections
without consuming build scripts. It copies a clean exact caller checkout into private
inert storage, audits workflows, scans secrets and fetches/checks dependency policy.
It never invokes consuming builds, tests, helper scripts or nested executable assets.

Four qualified tools have separate archive and exact executable member identities
for all three hosts in `pins/policy-tools-v1.json`. Whole archive size/hash precedes
decoding; only the exact regular native member is installed. Every invocation
rechecks the executable. Provider release records bind the qualified source and
asset observations; upstream signatures and production catalog acceptance are
explicitly unverified. A header's architecture is not a code-safety proof.

Actionlint uses its [JSON template](https://github.com/rhysd/actionlint/blob/v1.7.12/docs/usage.md#format)
with an external empty config and no external shellcheck/pyflakes. Zizmor uses
[explicit JSON v1](https://docs.zizmor.sh/usage/#json), offline collection of all
inputs, strict parsing and disabled caller configs/ignores. Gitleaks uses
[directory scanning](https://github.com/gitleaks/gitleaks/tree/v8.30.1#dir) with a
private default-rule config, empty ignore file, disabled inline allows and full
redaction. All three require successful exit and an empty JSON findings array.
Failed diagnostics remain private and no passing report is uploaded.

Cargo-deny uses the existing exact project policy translation, a private Cargo home,
the explicit target/features and a selected member manifest. Its scope is the Cargo
workspace under those arguments, including development/build dependencies; it is
not a minimal selected SBOM graph claim. A successful fresh fetch into a new private
database precedes an offline check of advisories, licenses, sources and bans.
[JSON summary statistics](https://embarkstudios.github.io/cargo-deny/cli/check.html)
must cover all four checks with zero errors. Policy-permitted warnings remain
warnings; caller suppressions and implicit exceptions are rejected. The project
policy bytes and normalized effective policy are both bound.

Each passing artifact contains exactly seven inert regular leaves:

- `policy-v1.json`: source commit/repository, ref/event, runtime helper bytes,
  run/attempt, complete selection, tool pins, policy, timestamps and report identities.
- `source-inputs.json`: every source file's size/hash, including lock/config,
  all manifests, source/build scripts, workflows and the explicit CI policy.
- `actionlint.json`, `zizmor.json`, `gitleaks.json` and `cargo-deny.jsonl`: native reports.
- `advisory-db.json`: actual bounded advisory file bytes encoded as base64, per-file
  sizes/hashes, Git commit/tree and observed successful fetch completion time.

The database Git identifiers are observations. The reader does not infer a signed
Git tree or authenticated upstream release from them. It rehashes every retained
advisory file without extracting or executing anything. Fetch completion is observed
by trusted runtime code; fresh clones can lack `FETCH_HEAD`. Cargo-deny separately
enforces native `P1D` database staleness. Required fetch outages stop the workflow;
there is no stale-cache or weaker-policy fallback.

`policy_v1.verify` takes independent source/run/selection, complete input identities,
runtime helper identities, qualified catalog bytes and project policy expectations.
It bounds and hashes all offered bytes before parsing native reports, requires the
exact leaf set, and rejects substitutions, missing/extra files, failures, altered
tools/policy or expired observations.
The reader also rechecks advisory exception expiry against the current UTC date,
including an otherwise fresh report crossing midnight. Matching unsigned data establishes consistency
only. An attacker can forge unsigned observations; provider transport, exact producer
job/source/workflow authentication and protected trigger/ref/ancestry/actor gates
must be established separately before finalization. All three authority flags remain
false even after this reader succeeds. Existing `transport_v1` supports the frozen
five-leaf builder handoff and cannot collect this seven-leaf report contract.

Limits: 4,096 source files, 8,192 tree entries, 16 MiB per source file, 128 MiB source
total, 4 MiB per native report/envelope, 32 MiB advisory report and 16 MiB decoded
advisory files. Symlinks, special files, nested repositories, dirty source, unsafe
paths and oversized trees fail. A source checkout containing ignored build outputs
can exceed these limits; use a fresh checkout. Observation freshness is at most one
hour. Each tool pipe is capped while streaming; fixed commands have deadlines and
process-group cleanup. Source and advisory data are rechecked after checks.

Artifact names bind selection, run and attempt; upload is success-only, SHA-pinned,
non-overwriting and retained for 14 days. For expiry, outage or failure, rerun the
entire independent job and authenticate the new attempt before using its result.
Retained failed secret matches are never part of recovery evidence. Future producer
authentication must bind complete artifact bytes, job and source independently;
stored artifact hashes alone are insufficient.

Development qualification runs in three separate native policy jobs. Four synthetic
library/CLI/service/feature selections include a consuming build script that panics
if run. The actual reports are independently checked and retained with explicit
fixture source and synthetic run identities. These runs demonstrate the adapter and
no-build boundary; they are not pilot adoption, a production runtime catalog, signed
release provenance or protected finalizer acceptance.
