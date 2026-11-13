# Protected Apple signing and attestation producers v1

Two reusable producer workflows complete the signed-release chain that
`rust-build-v3.yml` begins. Both are **inert until the owner supplies a
digest-pinned approval and the matching credentials**; neither grants
publication, tag or release authority. The caller repository owns the
environments and their required reviewers.

## Jobs and boundaries

| Workflow | Job | Runner | Environment | Authority |
| --- | --- | --- | --- | --- |
| `rust-release-sign.yml` | `sign` | `macos-15` | `release-signing` (caller-owned) | Developer ID signing + notarization |
| `rust-release-attest.yml` | `verify` | `ubuntu-24.04` | none | read-only byte verification |
| `rust-release-attest.yml` | `attest` | `ubuntu-24.04` | none | `id-token: write`, `attestations: write` |

Every job fixes its whole-job startup environment before any earlier action
can receive credentials, per [producer startup boundary v1](producer-startup-v1.md).
All orchestration runs in isolated `python3 -I`; there is no Node-first entry.
PR events never receive signing or attestation access — both workflows require
a tag push or a `workflow_dispatch` on `refs/heads/main`.

## Signing chain

`armorer_runtime.release_signing_v1` owns the credential-free logic. The
workflow supplies only fixed shell steps around it:

1. **prepare** — verifies the complete unsigned build-v3 handoff set from this
   exact run/attempt, rejects any payload that already carries an embedded
   signature, and stages one canonical `pkg/<binary>` archive per Apple
   executable. Emits the signing plan. Runs before any credential step.
2. **credential import** — the only step that reads secrets, referenced by name:
   `APPLE_CERTIFICATE_P12_BASE64`, `APPLE_CERTIFICATE_PASSWORD`, `APPLE_ID`,
   `APPLE_APP_SPECIFIC_PASSWORD`. Creates a temporary keychain with a random
   masked password, imports the identity, stores notarytool credentials, and
   deletes the `.p12` immediately. The approved team and identity come from the
   plan, never from a caller input.
3. **sign + notarize** — `codesign --force --timestamp --options runtime`,
   team-identifier assertion, `ditto` submission, `notarytool submit --wait`
   requiring `Accepted`, `notarytool log`, then
   `codesign --check-notarization -R=notarized`. Per-key evidence lands in
   `work/<key>/submission.json` and `notarization.json`.
4. **finalize** — extracts the exact signed executable, measures public
   signature facts and the certificate digest, binds the notarization records
   in clock order, repackages the consumer-canonical single-leaf USTAR archive,
   and emits the `ArtifactEvidence` chain the armorer consumer validates.
5. **assemble** — publishes the final archives, the per-key evidence, the plan
   and the **carried-forward unsigned-build SBOMs** (unchanged bytes; `verify`
   binds their digests).

## Attestation chain

The `verify` job re-runs `release_signing_v1 verify`, which admits only the
exact finalized bytes: each archive must rehash to the plan's recorded final
identity, unpack to exactly the one declared executable, and each SBOM must
match the verified unsigned-build SBOM digest. Because the attest job executes
a *different* workflow commit than the signing job, `verify` binds the
digest-pinned approval to the signing commit the plan claims.

The `attest` job then makes **two separate** `actions/attest` invocations per
subject. This is required, not stylistic: in the pinned action manifest,
`sbom-path` is mutually exclusive with `predicate-type`/`predicate`/`predicate-path`.

- Provenance: default mode (no `sbom-path`, no predicate inputs) over the final
  signed archive and its authenticated consumer evidence.
- SBOM: `sbom-path` over the carried-forward CycloneDX JSON.

Unsigned bytes can never become an attestation subject: `verify` fails closed
before any subject path is exposed.

### Attestation subjects and the inventory boundary

The subjects here are the final signed archive, its Apple transformation
evidence (`<key>.apple.json`) and the carried-forward CycloneDX SBOM. The
release-level **authenticated inventory** (`armorer-release-inventory.json`
plus its provenance bundle) is a separate stage owned by
`armorer_runtime.final_payload_v1`, and it deliberately cannot represent Apple
executables in v0.1: that module rejects any non-library selection targeting
`aarch64-apple-darwin` because its evidence contract has no Apple assertion
slots. This workflow therefore does not invent an inventory subject for signed
Apple bytes; joining the signed set into a release inventory is the
controller's reviewed step, and the consumer validates that inventory against
its own bundle. The names here are staging names
(`<key>-signed-release-v1.tar.gz`), not the consumer's release asset names
(`<key>.tar.gz` + `<key>.apple.json`, `src/verification/apple.rs`); that join
must rename and re-inventory, never re-sign. Do not attest unsigned bytes or a
fabricated inventory to close that gap.

## Pins

| Reference | Commit |
| --- | --- |
| `actions/checkout` v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `actions/download-artifact` v8.0.1 | `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c` |
| `actions/upload-artifact` v7.0.1 | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` |
| `actions/attest` v4.2.0 | `f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6` |

The reusable runtime is checked out at the executing workflow's own immutable
commit, validated from the job context — never from an offered artifact.

## What remains owner-blocked

- Apple Developer ID certificate and notarization credentials provisioned into
  the caller's `release-signing` environment (named secrets only; values are
  never requested, logged or embedded here).
- An independently reviewed signing approval whose exact SHA-256 the owner
  pins; it binds repository, run/attempt, source commit/ref, caller identity,
  signing and build workflow commits, team, identity and the complete
  selection set.
- A real signed producer→consumer rehearsal against the armorer consumer
  (`armorer verify-release`) with independently approved production roots and
  catalog. Synthetic fixtures and these workflows alone establish no
  signature, notarization or release qualification.

Synthetic adversarial coverage lives in `tests/tests_release_signing_v1.py`
(canonical repackaging round-trip, foreign/duplicate/missing archive members,
unsafe names, size bounds, approval digest and byte guards, matrix derivation,
and verify-stage archive/SBOM/run substitution). `finalize_signing` invokes real
`codesign`/`notarytool` and is exercised only in a credentialed rehearsal.

Preserve the chain. Keep the credentials out of the record. **This is the way.**