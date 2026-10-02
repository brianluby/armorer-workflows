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
