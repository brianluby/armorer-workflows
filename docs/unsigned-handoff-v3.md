# Explicit unsigned build handoff v3

`rust-build-v3.yml` is a separate, no-input reusable workflow. It uses the
unchanged selected graph v2 builder and emits exactly five regular leaves: the
selected `.bin` or `.crate`, its `.cdx.json`, its `.cargo-graph.json`, the unchanged
`inventory.json` v2, and a new `handoff-v3.json`. The v1/v2 entry points, runtime
implementations and schemas are preserved. Older readers never infer v3 or omit
its extra file.

The envelope records the exact v2 inventory byte identity, source and executing
workflow commits, run/attempt, selection, configuration/lock hashes, selected
root/version, native tool hashes and observed wall-clock start/finish around the
complete unsigned build operation. Those times include trusted setup and native
SBOM validation, rather than claiming a narrower Cargo-only measurement. The
unchanged builder verifies complete CycloneDX 1.5 with the catalog-pinned native
validator before the envelope is written. Existing valid SBOM serial numbers and
all artifact/SBOM/graph/inventory bytes are retained.

The state is always `unsigned-handoff`, signing is `unsigned`, and provenance is
`not-attested`. The upload name is the independently derived selection followed
by `-handoff-v3-run-<run>-attempt-<attempt>`. Missing or malformed hosted run IDs
fail this version; local native tests use explicitly synthetic run 17/2.
The workflow accepts no caller shell, runner, matrix, provenance, subject, digest
or tool-pin inputs and grants only contents read. There are no signing secrets,
OIDC, write permissions, release/tag operations or shared build-output caches.

## Independent reader

`verify_handoff_v3` requires independently established selection, source/runtime
commit, run/attempt, config/lock hashes, root/version and both exact native tool
digests. A consuming finalizer must derive those from approved source/runtime and
capability observations, never copy them from the downloaded envelope. The reader
snapshots the exact bounded regular leaf set privately, checks the envelope's
inventory digest and bindings, then applies the unchanged v2 inventory and
selected-graph/SBOM semantic reader to a four-leaf private view. The source
five-leaf directory and all consuming files remain unchanged.

Missing/extra/nested files, directory or leaf symlinks, FIFOs and other special
files fail before use. Each artifact is at most 1 GiB; graph/SBOM/inventory files
are at most 16 MiB each; the envelope is at most 1 MiB. The five-file layout also
bounds aggregate snapshot allocation. Copying streams 64 KiB chunks, checks the
opened regular inode, detects size changes and restricts snapshot writes. JSON
rejects duplicate keys, trailing documents and nonstandard numbers. The envelope
schema's structural checks supplement exact runtime comparisons; they do not
establish authenticity.

The reader's actual clock is checked before and after verification. Start must be
positive and no later than finish/current time; age is measured from start.
Default maximum age is one hour, with explicit independently chosen positive
limits up to one day. Boolean timestamps, future/reversed observations and
expiry during verification fail. A stable filesystem is required; a hostile
process sharing the same OS account or mutating directory ancestry is outside
snapshot isolation. Individual stalled filesystem reads are not interrupted.

## Required later gates

This slice checks unsigned consistency only. It does **not** authenticate GitHub
artifact transport, source execution, runner identity, tool approval or reported
times. A credentialed finalizer must first independently authenticate the exact
artifact/run/attempt/source transport, recheck mutable prerequisites and current
approval, and revalidate complete CycloneDX with its own approved native adapter.
The reader's reused v2 graph check alone is not a whole-document schema proof.
No unsigned envelope may substitute for verified platform evidence.

The separate [provider transport collector](provider-transport-v1.md) now checks
exact live storage/run/attempt identities and archive bytes before yielding inert
leaves. It remains a transport observation, with producer-job authentication and
signing authorization explicitly false. Qualified platform reports, whole SBOM
validation and effective protected finalizer integration remain required.

Final packaging, qualified retained platform reports, current-producer final-byte
provenance/SBOM/inventory bundles, own genuine complete signed positive,
independent consumer verification and human acceptance remain required #8 gates.
macOS executable outputs remain unsigned; protected Apple authentication,
Developer ID/team/runtime/timestamp/notarization and final-byte attestations are
separate required #9 gates. This workflow does not enable credentials or satisfy
those gates. Publication/immutable drafts and both pilots are still separate.

Development CI runs the v1/v2 controls and a four-case native v3 fixture on Linux
x86, Linux ARM and macOS ARM: minimal/optional executables, zero-dependency
library and service, including real host-build dependencies. Unit regressions
cover source/run/root/tools substitution, byte changes, clock/expiry, graph
rewrites with updated unsigned digests, file types/limits, version mixing and
absence of payload execution. Synthetic fixtures and unsigned native runs never
establish SLSA Build L2 or a production trust-root/catalog approval.
