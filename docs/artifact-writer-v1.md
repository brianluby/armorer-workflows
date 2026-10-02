# Artifact writer mapping v1

The internal `artifact_writer_v1.mjs` reader joins GitHub's artifact service to
native Actions jobs. It reads existing records and never downloads or executes
artifact payloads, requests OIDC, signs, creates artifacts or publishes releases.
Its process-local observation handle is not release authority.

Independent controller intent supplies the repository, source commit, run and
attempt, workflow, reader job and complete expected artifact/writer set. The
reader obtains current and explicit-attempt run records, the complete attempt job
list and the complete artifact list through fixed GitHub.com REST GET routes.
Each named writer must be unique, hosted on the expected supported runner and
completed successfully in that exact attempt. Its native `github-actions` check
must agree on name, source commit, check suite and state. Numeric job and check
IDs are independent fields; equality is not assumed.

The native check's `external_id` is compared with the artifact service's
`workflowJobRunBackendId`. Artifact IDs, names, sizes, digests and creation times
must also agree with individual REST records. Creation times agree at REST's
whole-second precision; the service timestamp is retained separately. The current reader's runtime scope
must match its independently observed native check. Decoding the runtime token
provides routing IDs only; it does not authenticate its claims. The authenticated
service call and independent native check join supply the provider evidence.
Builder outputs, artifact JSON and job logs never establish uploader identity.

Service records follow [ProtoJSON](https://protobuf.dev/programming-guides/json/):
the decoder accepts original protobuf field names or their lower-camel JSON
names, and canonical decimal strings or exact safe integer numbers for int64
fields. Duplicate aliases, null/missing fields, fractional or lossy numbers and
noncanonical decimal strings block the observation. The actual field names and
integer forms are retained in credential-free native receipts.

The only artifact-service request is read-only `ListArtifacts` over POST to the
fixed GitHub.com results receiver. Create, finalize, delete and signed download
URL methods are absent. REST and runtime credentials are separate, consumed from
their dedicated environment variables and omitted from results and errors.
Redirects, alternate service origins, TLS/proxy overrides, pagination, duplicate
objects, failed writers and cross-run/source/attempt substitutions fail closed.
Responses are bounded to 4 MiB, each request to 30 seconds and the whole operation
to 120 seconds. Two complete normalized snapshots must agree. Audit export is
allowed only for the original handle for 30 seconds; copied JSON is inert.

The development action qualifies the three already uploaded policy fixtures on
Linux x86-64, Linux ARM64 and macOS. It receives only `contents: read`,
`actions: read` and `checks: read`, runs after all fixture writers finish and is
restricted to same-repository runs. No extra artifacts or release mutations are
introduced. This checkpoint still requires accepted production catalog/root and
controller integration, producer OIDC, effective environment protection, actual
build handoff byte validation and signing before a final producer may proceed.
It does not establish SLSA Build L2, protected Apple finalization or publication.

Protocol source qualification is pinned to official `actions/toolkit` commit
`6cb87687384f971ebb756e43c7a56f62cd80a31d`. The internal service is not a public
stable REST contract; an incompatible or missing field blocks the operation.
The relevant primary sources are the [artifact service definition](https://github.com/actions/toolkit/blob/6cb87687384f971ebb756e43c7a56f62cd80a31d/packages/artifact/src/generated/results/api/v1/artifact.ts),
[runtime routing helper](https://github.com/actions/toolkit/blob/6cb87687384f971ebb756e43c7a56f62cd80a31d/packages/artifact/src/internal/shared/util.ts),
[service client](https://github.com/actions/toolkit/blob/6cb87687384f971ebb756e43c7a56f62cd80a31d/packages/artifact/src/internal/shared/artifact-twirp-client.ts)
and [native check API](https://docs.github.com/en/rest/checks/runs).
