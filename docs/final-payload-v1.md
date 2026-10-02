# Final payload assembly v1

This internal, credential-free stage prepares the byte layout consumed by the
strict release verifier. It snapshots and verifies the entire independently
expected v3 handoff set, retains `.crate` source archives without extracting them,
and packages Linux CLI/service binaries as a gzip USTAR archive containing one
declared regular executable. It checks the ELF64 machine header without executing
the binary. Normalized archive headers do not establish reproducible builds.

All expectations come from controller-owned validated source, reviewed catalog
and policy inputs. `ReleaseExpectation` is a structural input type, not a private
authorization proof. There is no public workflow, command, source override,
custom-provenance input, attestation token, Apple credential or release mutation
in this module. Its production integration is still in progress.

The bounded private workspace stages at most 64 selections and 4 GiB total,
including retained unsigned snapshots and later metadata/bundles. The assembler
admits complete sets, regular leaves and fixed names only. Source archives remain
opaque. Linux archives set the declared binary name, mode 0755, uid/gid 0, empty
owner names and zero timestamps. Files remain mode 0400 in a mode 0700 directory.
Insufficient space or a required missing, extra, changed or unsupported member
fails the entire assembly. The context manager deletes its workspace on success
or error. Stable filesystem ancestry and no hostile process sharing the OS account
remain required, as with the other snapshot readers.

An unsigned Apple executable blocks the entire set before staging. Libraries
associated with the macOS target remain source archives. The protected Apple
backend must produce and authenticate the required sign/notarize/package chain;
Linux success cannot substitute for that gate.

## Assembly order

1. Prepare final artifact, exact Cargo SBOM and selected Cargo graph bytes.
2. Attest those subjects and compare the signed SBOM predicate with the retained
   JSON through the qualified signer and strict consumer integration.
3. Retain actual platform reports in the fixed `.diagnostic.json` leaf. Produce
   complete `.build.json` and `.package.json` records from actual observations,
   measured input/output bytes and timestamps. Both evidence records reference
   the diagnostic's actual retained byte identity. This module checks consistency;
   it does not manufacture passing policy or attestation observations.
4. Attest the retained diagnostic and both evidence records.
5. Freeze the complete fixed inventory, including every bundle's exact bytes.
6. Attest the inventory itself last and retain its detached bundle outside the
   inventory asset list, avoiding a self-referential authentication hash.
7. Run the independent complete-release consumer before any later release gate.

The reviewable policy must independently permit the diagnostic supplemental
asset (`"diagnostic": false`, an authenticated reporting asset). The assembler
does not alter policy or add this decision implicitly. Required supplemental
semantic adapters retain the consumer's existing unsupported-capability errors.

`add_bundle` validates one exact subject/digest, the expected predicate type and
the exact SBOM document. Its checks are structural. A matching DSSE payload with
an invalid signature can reach `layout-complete-unverified`; it cannot authenticate
a release. `finish` always reports `cryptographic_release_authenticated`,
`signing_authorized` and `publication_authorized` as false. JSON, this workspace
object and a complete layout cannot reconstruct the private producer proof.

The producer must still connect qualified run-bound transport and policy reports,
effective source/protection gates, the mapped private OIDC proof, a pinned
attestation action, accepted native runtime/root/catalog inputs and the strict
consumer. Those integrations, genuine own signed positives, protected Apple
finalization and immutable publication remain required outcomes.

## Validation

Failure-oriented tests exercise complete sets, cross-run/source/input changes,
ELF machine/script substitutions, unexecuted library archives, retained reports,
actual measured byte chains, exact SBOM predicate matching, bundle substitutions,
missing/extra assets, inventory ordering, conflicting retries, mutation, cleanup
and resource bounds. Their platform records and signatures are deliberately
synthetic; they are not cryptographic qualification.

The native qualification composes the unchanged real v3 Cargo fixtures with this
stage and independently compares final archive members with actual compiler
outputs. Linux qualifies CLI feature cases, service and library bytes. macOS
qualifies the actual library archive and records each executable as blocked by
the required Apple backend. All source/run/catalog contexts in these fixtures
remain explicitly synthetic. No live OIDC, Apple or publication operation occurs.

Schema fixtures are exact copies from the merged Armorer trust-contract commit;
their source hashes and Git blob identities are in the fixture receipt. The
original schemas, handoff versions, producer proof adapters and historical
receipts remain unchanged.
