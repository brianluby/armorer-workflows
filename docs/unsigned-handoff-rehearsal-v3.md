# Nine-selection unsigned handoff v3 rehearsal

The repository's synthetic fixture covers library, CLI and service outputs on
native Linux x86, Linux ARM and macOS ARM. `rehearsal-v3.yml` invokes the no-input
`rust-build-v3.yml` at the caller-pinned workflow commit
`59a2e782150abff3f995682013d514e6865d8dfb`. Its uploaded result for each of the
nine independently derived selections contains the exact five regular leaves
described in [unsigned handoff v3](unsigned-handoff-v3.md).

This is a second caller/configuration commit after the reusable code commit. The
shared fixture `armorer.lock` and all three v1/v2/v3 callers pin that same
caller/configuration commit. Updating only the v3 caller or only the shared lock would break the
builder's mandatory executing-workflow identity check. The older entry-point
and runtime/schema/tool-catalog bytes are unchanged; earlier immutable caller
commits and validation receipts remain available. No moving pin or self-pinning
commit is used.

All three callers grant only contents read, allow the existing pull request,
main push and explicit workflow-dispatch triggers, and inherit no secrets or
caller inputs. The builders remain unprivileged. There is no OIDC, signing,
attestation creation, tag or publication operation. The fixture intentionally
requires attestations in its project policy, so an unsigned rehearsal cannot
satisfy release readiness or SLSA Build L2.

## Independently reconcile hosted downloads

Establish the caller head, hosted run/attempt, provider source commit (including
the exact pull-request merge parents), reusable workflow SHA and nine expected
selections from approved source and provider observations. Derive root names,
versions, input hashes and both target-specific native tool hashes from those
independent inputs. Do not learn expected values from a downloaded inventory or
handoff envelope.

Require exactly nine run-bound provider artifact names, each with the selection
ID and `-handoff-v3-run-<run>-attempt-<attempt>` suffix. Bound each ZIP's transport
and decompressed sizes and require exactly the five expected regular leaves;
reject paths, symlinks, directories, duplicates, extra or missing members. Copy
only bounded inert leaves to a private directory without executing the payload
or extracting a nested `.crate` archive. Rehash every leaf.

Pass the independent selection/source/runtime/run/input/root/version/native-tool
expectations to `verify_handoff_v3`. Use a current clock and an explicit approved
maximum age; expired downloads fail. Retain the provider observations, all leaf
hashes and actual validation results. Independently revalidate the complete
CycloneDX JSON with the pinned native adapter and reconcile the selected graph.
Wrong run/attempt/source/tool values and altered graph semantics must fail.

The local reader proves unsigned byte and semantic consistency. Provider API
observations and a downloaded artifact are not a signed release or standalone
cryptographic transport proof. Report native CI, unsigned hosted reconciliation,
authenticated release and human acceptance separately. Credentialed finalization
must still authenticate the bounded exact run-bound transport before credentials
and recheck all mutable prerequisites; the full final-byte producer, platform
reports, Apple protection, complete signed inventory and publication gates remain
incomplete.
