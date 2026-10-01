# Fixed Rust builds and Cargo SBOMs

`rust-build.yml` runs the reusable CI gates before producing unsigned build
artifacts. Call it with a reviewed full commit SHA. It accepts no caller shell,
runner, source identity, tool URL, digest or provenance inputs. Its jobs recover
their own reusable workflow repository and full SHA from GitHub's job context,
then check out the trusted runtime at that exact commit. GitHub installations
without that context fail closed. Caller checkouts do not retain credentials.

The caller's root `armorer.toml` selects packages, binaries, target triples and
feature sets. The SHA-pinned Armorer CLI validates it before the runtime
rederives the matrix. `.armorer/ci-policy.toml` is required by the preceding CI
gates; existing policies are not replaced. `armorer.lock` must bind the executing
`brianluby/armorer-workflows` commit. The dependency `Cargo.lock`, configuration
and Armorer lock must be tracked files in a clean source checkout. Hosted
builds also require Git HEAD to match GitHub's source SHA.
Preexisting non-ignored untracked files are rejected before build execution.
Ignored/generated inputs, native SDKs and tools used inside caller build scripts
are not fully bound by the tracked source inventory; fresh hosted checkouts
reduce that risk but do not establish platform isolation.

The current native runners are Ubuntu 24.04 x86-64, Ubuntu 24.04 ARM64 and macOS
15 ARM64. A selection cannot run on another native target. Each selection gets
an isolated Cargo home and target directory, fixed argument arrays, locked
dependency resolution, its exact Rust toolchain and its declared features.
Cargo configuration overrides require migration review. No shared build cache,
OIDC permission, signing credential or release write permission is used.
Runner images and native SDKs are mutable; this is not a reproducible-build or
SLSA level claim.

## Why the SBOM adapter exists

[cargo-cyclonedx 0.5.9](https://github.com/CycloneDX/cyclonedx-rust-cargo/tree/e58bd5590212f82c5b7e16dd3e2e819b0dbea5b1)
supports target filtering, feature selection, per-Cargo-target output and
CycloneDX JSON 1.5. Its CLI does not expose `--locked` or `--package`, and Cargo
metadata can unify features across unrelated workspace members. Calling the
generator directly would overstate a selected build's dependency graph.

The builder first records Cargo's fresh selected release build
[compiler-artifact messages](https://doc.rust-lang.org/cargo/reference/external-tools.html#artifact-messages),
including package IDs and enabled features. It obtains locked, target-filtered
Cargo metadata with the same requested features. It then selects the actual
root package, reconciles optional dependency activation against compiled local
features, removes unrelated workspace packages and checks every active edge
and compiled package. Missing host dependencies or ambiguous declarations fail
closed. A fixed `$CARGO` adapter returns only this reconciled metadata and
accepts exactly the invocation made by the pinned generator; it never runs
caller commands or accepts caller metadata.

The generated SBOM must match the selected Cargo target, package version, exact
compiled package inventory, every dependency component's name/version and
every graph edge. Duplicate JSON keys, duplicate component references, missing
roots, missing nodes and dangling or altered edges are rejected. The pinned
[CycloneDX CLI 0.33.1](https://github.com/CycloneDX/cyclonedx-cli/releases/tag/v0.33.1)
independently validates the JSON offline against specification 1.5. Downloads
come exclusively from the reviewed trusted tool catalog, with distribution
SHA-256 checks before extraction. The catalog's immutable workflow commit is
the tool pin authority; syntactically valid values in a caller lock are not
independent authentication of upstream tools.

## Artifact and evidence scope

CLI and service profiles produce the explicitly selected executable. Library
profiles additionally run locked `cargo package` with verification enabled and
produce its `.crate` source package, paired with the selected target's build
graph. A source `.crate` is not a compiled platform binary. Library packaging
can fail for unpublished path dependencies or projects that are not ready for
Cargo packaging; Armorer does not bypass those prerequisites. A library may
have zero dependencies and a custom Cargo library target name.

Inventory schema version 1 is documented in
[`build-inventory-v1.json`](../schemas/build-inventory-v1.json). It binds source
repository/commit, hosted run/attempt, trusted runtime commit, exact
configuration and lock digests, tracked source digests, selected target/features,
tool executable digests and three exact files: artifact, SBOM and Cargo graph
evidence. Source, runtime and installed tool preimages are checked after caller
build execution. Asset names include the selection; uploaded artifact names
also include run ID and attempt, and overwriting is disabled. Source packaging
finishes before SBOM generation so generated SBOMs cannot dirty its inputs.

`verify_inventory` compares the exact asset inventory and SHA-256 bytes. Pass
independently derived expected selection and source/runtime/run context when
checking consistency. The inventory itself is unsigned: replacing both a file
and its digest is not detected cryptographically. Nothing here authenticates a
consumer download or authorizes publication. Signing, attestations, immutable
release assembly and secure consumer verification are later gates. Those gates
must rehash their actual subjects independently in a separate trusted controller
rather than treating caller Cargo output or this inventory as provenance claims.

Cargo compiler messages are emitted in the caller build environment and are
not a platform isolation boundary. Features for host and target units of the
same package are aggregated in this inventory. Native linkage messages provide
clues, but native and system libraries are not fully inventoried. These limits
are explicit coverage gaps. macOS bytes here remain unsigned and unnotarized;
they must never be attested as final signed/notarized release bytes.

## Validation and recovery

Unit failure tests cover workspace feature over-inclusion, optional edges to
packages compiled elsewhere, missing host dependencies, wrong roots, tampered
component versions, valid-reference edge rerouting, duplicate keys/references,
unsafe adapter arguments, tampered/missing/extra assets, wrong expected source
or run context and descendant termination on command timeout.

Run `python3 -m unittest discover -s tests -p test_build.py -v` for those tests.
For schema tests and native fixtures, use a development virtual environment and
install `requirements-schema.txt` with `pip install --require-hashes
--only-binary=:all: -r requirements-schema.txt`; it is not a runtime dependency.
After building the pinned trusted Armorer validator, run
`python3 tests/build_cases.py --armorer /absolute/path/to/armorer
--tool-directory /absolute/path/to/new-tool-directory` for native fixtures.
They construct a temporary five-crate workspace and exercise minimal and
optional-feature applications, a target-gated dependency and a zero-dependency
library with a custom target name. No pilot repository is modified.

Failed commands terminate their Unix process group and clean temporary build
directories. A failed attempt publishes no release. Retry in a fresh workflow
attempt; run/attempt asset identities keep attempts distinct. Investigate a
failed graph reconciliation or schema check instead of changing the expected
inventory or disabling validation. Existing source customizations and missing
native/package prerequisites require explicit migration or future adapters.
