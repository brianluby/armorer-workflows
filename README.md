# Armorer workflows

MIT-licensed reusable Rust CI/build/release workflows for Armorer. Implementation is being prepared in reviewable branches; no release or SLSA claim is made.

Runtime and workflow upgrades require reviewed immutable pins. Never pass signing credentials, shell commands or caller provenance claims to builders.

The experimental [Rust CI workflow](.github/workflows/rust-ci.yml) validates
library, CLI and service feature cases, runs locked tests/lints, and enforces an
explicit project dependency policy with workflow and redacted secret scanning.
Read [CI onboarding and limitations](docs/ci.md) and the
[shared contracts](docs/parallel-contracts.md) before adoption. Call reusable
workflows by reviewed full commit SHA; no release/version is published yet.

Native fixtures and failure tests cover advisory outages/expiry/staleness,
denied licenses, secret-scan suppression, unsafe triggers, tampered tool bytes,
path/archive escapes, and lingering build-script descendants.

The experimental [Rust builder](.github/workflows/rust-build.yml) produces
unsigned executables or Cargo source packages with target/feature-specific
CycloneDX SBOMs and exact byte inventories. Read [builder scope and verification
limits](docs/build.md); signing, attestations and publication are later gates.

The explicit [independent policy observation workflow](.github/workflows/rust-policy-v1.yml)
retains qualified native reports and actual advisory input bytes in separate
unprivileged jobs without executing consuming builds or tests. Read
[its versioned contract and remaining authentication gates](docs/independent-policy-v1.md)
before adopting it. Existing CI/build callers remain required.

The experimental [producer OIDC context helper](docs/producer-oidc-context-v1.md)
verifies job identity against independent expectations. Its native RSA fixtures
use a synthetic issuer; live producer, protection, signing and publication
gates remain incomplete.

## Current-job controller prerequisite

The [mapped producer join](docs/mapped-producer-context-v1.md) derives the
issuer's check-run expectation from independent current-job observations and
rereads source/job prerequisites after verification. Private identity proof
does not grant protection, signing or publication authority; live producer and
complete release-controller acceptance remain pending.

The [versioned controller observer](docs/controller-context-v1.md) independently
maps one active job to its separate check-run identity and observes exact
preexisting environment controls. Candidate PR qualification uses read-only
native GitHub APIs on all three runners. Configuration and unknown or
unsupported enforcement remain distinct; these receipts grant no signing or
publication authority.

The internal [final payload assembler](docs/final-payload-v1.md) packages exact
Linux binaries and retains library archives in the strict consumer's fixed
inventory layout. Native tests compare actual Cargo outputs on all three runners;
unsigned Apple executables block before staging. A complete layout remains
unverified until the pinned signer and independent consumer authenticate it.

The internal [artifact writer reader](docs/artifact-writer-v1.md) joins the
artifact service's uploader identity to native Actions job/check records. Its
credential-free observations preserve the remaining producer, protection and
release authentication gates.

The [combined handoff collector](docs/combined-handoff-v1.md) checks build and
policy artifacts as one complete same-run set. Its native rehearsal joins actual
downloaded archive bytes to their uploader jobs across all three profiles and
platforms. Production signing, Apple finalization and release acceptance remain
separate gates.

The [Apple unsigned payload intake](docs/apple-payload-intake-v1.md) freezes the
complete v3 handoff set and checks ARM64 Mach-O structure before a later signing
stage can use its readonly bytes. Native Cargo qualification retains measured
input identities; protected signing, notarization and final attestations remain
required.

The [release controller](docs/release-controller-v1.md) binds its exact
run/attempt in a deployment before any publication write, so the consumer can
observe current-attempt environment enforcement and runner-wide serialization.
It stays inert without independently approved policy and approvals, and grants
no signing or attestation authority.

The [protected signing and attestation producers](docs/release-signing-v1.md)
complete the Apple chain: a caller-owned `release-signing` environment signs and
notarizes the exact approved executables, then a credential-free verify stage
admits only those finalized bytes before separate provenance and SBOM
attestations. Both stay inert without a digest-pinned approval and named
credentials; publication and the real signed rehearsal remain separate gates.
