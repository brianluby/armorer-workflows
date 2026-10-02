# Current-job controller observations v1

`armorer_runtime.controller_context_v1` joins the versioned source preflight
with a read-only mapping of one independently intended, active job. This is a
prerequisite for matching the producer OIDC helper's `check_run_id`. It does
not mint signing, attestation or publication authority.

The controller must establish `JobIntent` from its reviewed static workflow
and independent source policy. The exact workflow name, full job display
name (including any matrix suffix) and native runner label cannot come from
an offered artifact or unverified token. A unique name is required across
the complete attempt listing. GitHub's job ID and check-run ID are separate
fields; no equality or fallback is assumed.

The observer keeps the existing `SourceIntent`, source API and original
transport routes unchanged. It requires their exact adapter types. The new
`ControllerGhApi` reuses the qualified native executable identity and has
its own fixed GET route allowlist. Each call rechecks native executable
bytes, uses a private working directory and sterile environment, closes
stdin, bounds JSON to 4 MiB and bounds an individual read to 60 seconds and
the overall native stage to 20 minutes. Ambient debug, proxy and unrelated
tokens do not enter the child. Provider stderr is discarded. Native reads
do not build consuming code, mutate files in the consuming repository,
request OIDC or call any GitHub write endpoint.

The mapping requires:

- Both the latest run and explicit attempt are active and match the complete independent
  source, caller workflow, reusable workflow set, actors and fresh start.
- All job pages agree on a positive total at most 1,000. Every page is
  complete, every job ID is unique, and every row belongs to the intended
  run, attempt, head commit, branch and workflow name. Exactly one job has
  the reviewed display name.
- The selected job's direct GET agrees with its listing. Its API URLs and
  check-run URL have the exact repository and fixed GitHub origin. IDs are
  positive canonical values within the signed 64-bit range.
- The job is active, unconcluded and fresh. Its runner label is exactly one
  of the three qualified native labels and its metadata names the GitHub
  Actions runner group. These are provider metadata observations; hosted
  producer identity still requires independently verified signed OIDC.
- Both complete source and controller snapshots agree. The job and latest
  and explicit attempt are reread after the final source preflight. A
  changed actor permission, rerun, job completion, check association or
  required environment configuration rejects the observation.

`qualification_only=True` explicitly allows the candidate PR test path.
That mode cannot collect protected release environment controls. Producer
mode only permits the source preflight's default-branch dispatch or stable
tag push rules. A serialized receipt is an audit artifact, never a permit
to request signing credentials or perform a release mutation.

## Environment observations and unavailable enforcement

An optional independent `EnvironmentIntent` binds a preexisting
`release-signing` or `release-publish` numeric ID, node ID, exact set of
1–6 user reviewer IDs, default branch and optional wait timer. Teams and
custom protection rules require a separately qualified successor. The
observer requires self-review prevention, exact required rules, and exactly
two typed custom deployment policies: the default branch and `v*` tags.
The source guard separately restricts actual push tags to stable `vM.m.p`.
No administrator mutation or implicit environment creation is performed.

The normalized receipt contains exact rule and branch-policy IDs and a
configuration SHA-256. It deliberately distinguishes:

| Observation | State | Consequence |
| --- | --- | --- |
| Explicit `can_admins_bypass: false` | `configured` | Configuration only; no enforcement credit |
| Explicit `can_admins_bypass: true` | `disabled` | Required no-bypass control fails |
| Admin bypass field absent | `unknown` | Absence does not mean bypass is disabled |
| Approval for the current attempt/job | `unsupported` | Signing/publication remain blocked |
| Effective protected environment enforcement | `unsupported` | Configuration does not prove execution enforcement |

GitHub's documented environment response does not promise an admin-bypass
field. Its run approval history includes environments and users, but lacks
an attempt/job identity suitable for authorizing a rerun. The observer
therefore does not call that endpoint or promote a run-level approval to
current-attempt approval. It also does not infer protected-ref enforcement
from environment deployment policies. Ruleset bypass actors can be hidden
unless the API caller has write access to the ruleset; missing actors must
remain unknown in the later protected-ref observer. This adapter does not
expand credentials to obtain those fields.

All receipts leave `producer_job_authenticated`,
`protected_ref_authenticated`, `protected_environment_authenticated`,
`production_catalog_accepted`, `cryptographic_release_authenticated`,
`signing_authorized` and `publication_authorized` false. They must not be
used as substitutes for the producer OIDC proof, independent accepted
roots/catalogs, effective protections or strict final-byte verification.

## Validation

Adversarial fixtures use different job/check IDs and cover ambiguous names,
pagination truncation and late duplicates, cross-run/attempt/source swaps,
unsafe API URLs, inactive and unqualified runners, source permission
revocation, final reread races, protection broadening and absent bypass
metadata. Mocked reads are supplements to the development workflow's
three native qualifications with the pinned real `gh` and actual isolated
`actions: read` job token. That qualification maps only the current PR test
job; it does not request live OIDC, create environments, sign bytes or
publish assets. Source/caller hashes come from the candidate checkout in
this explicitly marked test path, not a production accepted root.

Primary platform contracts:

- [List jobs for a workflow run attempt](https://docs.github.com/en/rest/actions/workflow-jobs#list-jobs-for-a-workflow-run-attempt)
- [Get an environment](https://docs.github.com/en/rest/deployments/environments#get-an-environment)
- [List deployment branch policies](https://docs.github.com/en/rest/deployments/branch-policies#list-deployment-branch-policies)
- [Get the review history for a workflow run](https://docs.github.com/en/rest/actions/workflow-runs#get-the-review-history-for-a-workflow-run)
- [Get a repository ruleset](https://docs.github.com/en/rest/repos/rules#get-a-repository-ruleset)
