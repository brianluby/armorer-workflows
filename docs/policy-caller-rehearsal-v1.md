# SHA-pinned independent policy caller rehearsal

Status: prepared for hosted validation and human review. This is a non-publishing,
unsigned rehearsal; all release and signing authority remains unavailable.

The additional `rehearsal-policy-v1.yml` caller invokes `rust-policy-v1.yml` at
`59a2e782150abff3f995682013d514e6865d8dfb`, the reviewed independent observation
implementation. The root `armorer.lock` pins that same runtime commit. All three
builder callers explicitly move to that SHA because one root lock requires the
same executing runtime for every caller. Their versioned workflow files, builder
and CI helpers, and legacy tool catalog are byte-identical to the previous pinned
runtime. This advances the shared source pin without changing the v1/v2/v3 output
contracts. Mixing the old builder pin with the new lock correctly fails.

Unlike the development qualification's temporary fixture repository and synthetic
run identities, this caller checks the actual clean GitHub source checkout and
records the actual run, attempt, event, ref and executing reusable runtime commit.
The existing root configuration selects library, CLI and service cases on Linux
x86-64, Linux ARM64 and macOS ARM64, with explicit minimal or JSON feature sets.
Each of the nine cases retains exactly the seven leaves defined in
[the observation protocol](independent-policy-v1.md).

An independent qualification must derive the source file identities and selections
from the exact reviewed caller tree, runtime helper identities and tool catalog
from the pinned runtime tree, and repository/run/artifact observations from the
provider. Compare the provider's latest and exact attempt, referenced reusable
workflow pin, source merge/tree and complete artifact set; rehash each whole
download before bounded decoding, then check all seven leaves using independent
expectations. Recheck the latest attempt, artifacts and source merge after reading.
Perform current-clock verification within the protocol's one-hour limit. An expired
observation cannot be reused as current qualification evidence. This unsigned result
does not authorize signing.

This rehearsal demonstrates the real reusable caller and retained-byte consistency.
Provider artifact storage metadata does not establish which producer job wrote
those bytes. Producer-job authentication, credentialed finalizer integration,
accepted production catalog/root, signed complete inventory verification, Apple
finalization, publication parity, pilots and human acceptance remain separate
incomplete gates. Do not run downloaded caller artifacts or treat a successful
unsigned reader result as permission to sign or publish.
