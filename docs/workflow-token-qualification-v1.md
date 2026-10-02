# Native workflow-token qualification v1

Status: implemented for review. This development qualification exercises the
fixed GitHub GET adapter using the actual ephemeral Actions-read token on Linux
x86, Linux ARM and macOS ARM. It requests no signing, attestation, environment,
publication, repository administration or other write permission.

The new `transport-evidence` jobs wait for all three native policy qualification
jobs to finish. They independently obtain this repository, head, branch, event,
run and attempt from their GitHub job context. The independently read development
workflow ID is fixed in the reviewed helper. They require the exact latest and
explicit attempt and the complete three-artifact qualification set, then read
individual artifact records and compare downloaded whole archive sizes/hashes.
Latest/attempt/listing state and freshness are rechecked after every download has
finished. Archives remain private and inert and disappear when the check exits.
They are not decoded or executed here, and their metadata cannot authenticate the
job that wrote them.

Hosted qualification observed the provider returning `queued` to fast Linux
readers while their jobs were already running. Preflight may wait for matching
pending metadata for at most thirty seconds. Repository, source, caller, run and
attempt checks apply before waiting; unknown or failed states reject immediately.
No archive download occurs until the provider reports an active run or completed
success. A persistent pending state expires rather than earning qualification.
All later attempt/state/freshness checks remain strict. State diagnostics contain
only recognized status/conclusion enums, never arbitrary provider values or bodies.

The installer selects only the existing independently qualified GitHub CLI
2.102.0 native distributions. Archive sizes/hashes are checked before bounded
tar/ZIP decoding; paths, member types/counts and expansion are checked before
writing one exact native executable. Its size/hash is checked before it receives
executable permissions and again before every API read. URLs, archive pins and
native pins cannot come from a caller's configuration. The installer excludes
ambient HTTP proxy and authentication configuration. Pin receipts identify the
previously qualified upstream source and checksum manifest; they do not claim
upstream signature authentication or production catalog acceptance.

The existing adapter starts the CLI in a fresh private working directory with a
fresh home/configuration/cache, fixed host/API version/GET routes, bounded streams
and timeouts, closed stdin and discarded diagnostic text. The token is supplied
only in that child process's environment. Native qualification deliberately sets
unrelated ambient debug/token/proxy values; the sterile child environment excludes
them. Existing real-process boundary tests verify this exclusion. Each native job
also exercises an invalid token and altered CLI bytes: both must reject, and the
altered executable must never run.

Credential-free receipts appear in the job log and step summary. No new artifacts
are uploaded by these jobs: otherwise one qualification job could change the
complete artifact set while another is rereading it. Operator-mode local archive
or API checks remain distinct from these actual workflow-token jobs. Fork PRs do
not qualify this same-repository token contract; the qualification jobs are
explicitly skipped for them. A run with retained artifacts from an earlier attempt
fails the exact-set check; start a fresh workflow run rather than replacing or
ignoring those artifacts. Retry qualification remains a separate gate.

This checkpoint qualifies native delivery and token-mode GET transport only.
`producer_job_authenticated`, `policy_snapshot_authenticated`,
`cryptographic_release_authenticated`, `production_catalog_accepted` and
`signing_authorized` remain false. Independent source ancestry, authenticated
producer evidence, accepted catalog/root, exact release trigger/ref/actor and
approval checks, protected finalization and all publication/pilot acceptance
gates remain required.

GitHub documents token permission minimization and the Actions-read artifact API
in its [workflow token guide](https://docs.github.com/en/actions/tutorials/authenticate-with-github_token)
and [artifact REST API](https://docs.github.com/en/rest/actions/artifacts?apiVersion=2022-11-28).
