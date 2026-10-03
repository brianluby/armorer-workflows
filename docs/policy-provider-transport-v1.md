# Policy provider transport v1

Status: implemented for review and native qualification. This explicit successor
collects the seven-leaf policy contract; the frozen five-leaf `transport_v1`
builder adapter retains its behavior. Neither adapter authorizes credentials.

`policy_transport_v1.collect_policy` requires the exact qualified native GitHub
API adapter and an independently supplied `ExpectedPolicyRun`. The controller must
derive the selections, all source file identities, runtime helper identities,
qualified catalog bytes and project policy from independently reviewed sources.
For a PR, independently verify the exact current merge parents and source tree
before constructing the intent. Provider run metadata identifies the PR head;
the report source identifies the merge checkout. Run/artifact records alone cannot
establish that Git ancestry.

The native adapter uses the existing fixed GET-only endpoints and qualified
archive/executable pins for GitHub CLI 2.102.0. Workflow-token mode isolates its
home/configuration and credentials from caller source. The separate operator
qualification mode uses the workstation's existing credential store without
reading values; it does not qualify workflow-token isolation. This collector
performs no arbitrary URL requests, writes to GitHub, builds or artifact execution.

Before downloading, require a completed successful exact latest and explicit
attempt, independent repository/head/caller/workflow identities, the exact PR
number/head or supported push/dispatch ref, and exactly one referenced reusable
workflow at the expected `rust-policy-v1.yml` SHA. This supports a standalone
policy caller; combined callers with additional reusable workflows fail.
Require a complete bounded artifact set with exact selection/run/attempt names,
unique provider IDs, current expiry and upload times within the expected attempt.
Read back each artifact's individual record before downloading it.

Whole archive size/hash checks precede ZIP decoding. Accept exactly seven regular
inert leaves, with no links, aliases, extra members, container comments, trailing
bytes, encryption or unsupported compression. Bound each streamed leaf and keep it
private and read-only. The unsigned semantic reader compares independent context,
selection, source/runtime/tool/policy identities, native passing reports and actual
advisory bytes. Report observation times must also fall between the provider's
attempt start and the artifact creation time.

After all downloads, reread the latest attempt, exact attempt and complete artifact
listing, then reverify every retained report against the current clock. The oldest
observation must still satisfy the independently supplied freshness bound, at most
one hour. The context yields private directories and a transport audit receipt only
after all cases pass; temporary files disappear when it exits. The receipt binds
the native CLI, authentication mode, source/run/caller, whole archives and every
leaf identity. A rejected case yields no passing snapshot.

The result authenticates provider storage observations and establishes retained
unsigned-byte consistency under the supplied expectations. Artifact metadata does
not identify the job that wrote those bytes. `signing_authorized`,
`producer_job_authenticated` and `cryptographic_release_authenticated` remain
false. A protected controller must separately authenticate producer jobs, source
ancestry, accepted catalog/root and current trigger/ref/actor/approval prerequisites,
then recheck mutable state immediately before any irreversible operation. An audit
receipt is a checkpoint, not a continuing authorization. No fallback, signature
downgrade, publication or signing is implemented here.
