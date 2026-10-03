# Apple unsigned payload intake v1

The credential-free intake snapshots the **complete independently expected v3
handoff set** before exposing an Apple executable to a later signing stage. It
uses the existing v3 graph, SBOM, source/run/attempt, input, package and tool
checks over the copied bytes. It retains Linux payloads and opaque library
archives as part of that same complete set. A missing, extra, conflicting,
expired or changed required member rejects the whole intake.

`prepare_apple_payloads` accepts controller-owned `PayloadExpectation` values
and the live inert directories from the preceding collector. It offers no public
workflow input, shell command, credential parameter or provenance override.
The caller must separately join authenticated provider ZIP bytes to the original
private artifact-writer and mapped OIDC proofs and approved policy/catalog/root.
The expectation records and this workspace do **not** establish those authorities.

Each file is copied through the bounded regular-file reader into a private mode
0700 directory, with leaves mode 0400. There are at most 64 selections and 4 GiB
of staged file bytes, including the temporary duplicate used by v3 semantic
verification. The load-command inspection allocates at most 16 MiB per payload.
Audit access rehashes the whole set; payload access rehashes all five leaves for
that selection. Build age, a twenty-minute stage lifetime and wall-clock rollback
are checked on every access. The context manager rechecks the complete set on
normal exit and removes it on both normal and exceptional exits. Paths become
invalid outside the context. Stable filesystem ancestry and no hostile process
sharing the OS account remain prerequisites of the existing file readers.

## Supported payload shape

Apple CLI/service selections must contain a thin, little-endian ARM64
`MH_EXECUTE` image with an unambiguous `LC_MAIN` inside file-backed executable
`__TEXT`, after the load-command table, and the fixed `/usr/lib/dyld` loader.
The intake checks command counts, alignment and sizes, segment/section file and
virtual ranges, duplicate segment/section names, overlapping file-backed
segments and any embedded signature range. Scripts, ELF, fat/universal images,
32-bit Mach-O, ARM64e, dylibs, legacy thread entry points and encrypted-command
layouts return explicit failures. Source-library archives remain opaque.

These layouts follow Apple's published [Mach-O loader definitions](https://github.com/apple-oss-distributions/cctools/blob/main/include/mach-o/loader.h)
and [ARM64 CPU definitions](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/machine.h).
Unknown load commands receive only generic command-bound checks. This is a
bounded intake format check, not complete loader validation, vulnerability
analysis, dependency resolution or a signature verifier.

Rust's native linker may place an ad-hoc signature in an unsigned ARM64 payload.
A structurally bounded `LC_CODE_SIGNATURE` range is retained as audit data;
neither its existence nor its contents establish Developer ID, expected team,
hardened runtime, secure timestamp or notarization. The signed transformation
must preserve this input's actual byte identity and independently verify those
properties after signing.

## Integration and remaining acceptance

The native final-payload rehearsal now passes its **whole actual Cargo handoff
set** through this intake on each runner. On macOS it independently rehashes the
retained unsigned CLI/service Mach-O bytes. Linux qualifies the complete-set
snapshot interface without claiming an Apple native positive. The existing
final assembler still rejects all unsigned Apple executables, so an intake
success cannot be substituted for final Apple output.

The audit always reports producer/writer authentication, accepted production
catalog, protected environment, cryptographic release authentication, signing
and publication authority as false. A copied audit or workspace object cannot
authorize credentials. Effective current-attempt environment protection,
Developer ID signing, notarization submission/acceptance, signed/final package
evidence, final-byte attestations and a complete signed consumer positive remain
required for #9. No live Apple credential, signing/notarization submission,
release, tag or repository-admin mutation is performed by this intake.

Twenty adversarial unit tests use inert fixtures and do not establish live
signing or Sigstore qualification. Native Cargo qualification complements them;
neither form substitutes for the separately approved protected rehearsal.
