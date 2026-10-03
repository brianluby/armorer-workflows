# Native publication prerequisites v1

`armorer_runtime/publication_capabilities_v1.py` performs fixed native GitHub GETs
for an independently expected repository, its immutable-release setting, and the
existing `release-signing` and `release-publish` environments. It runs no consuming
build code, reads no secret endpoints, and changes no repository settings.

The module adds a versioned status-preserving adapter. Existing v1 source,
controller and artifact transport behavior and historical receipts are unchanged.
The same qualified gh 2.102.0 executable bytes are rehashed before every request.
Workflow mode uses only the explicit read token in a sterile child environment;
operator qualification uses the existing native credential store without reading
credential values. Both use closed stdin, fixed GitHub origin, fixed GET routes,
bounded stdout/stderr, a 60-second request bound and a 120-second observation
bound. Native diagnostics and provider error message text never enter receipts.

## Independent intent and states

`RepositoryIntent` supplies the exact repository name, numeric database ID and
default branch. Native metadata must match those expectations before and after
each complete prerequisite snapshot. The two snapshots must agree; repository,
setting or environment changes reject the observation.

The immutable endpoint must return explicit boolean `enabled` and
`enforced_by_owner` fields. Enabled is **configured**; explicit false is
**disabled**. HTTP 401 is **denied**; 403 is **unknown**
(`access-denied-or-throttled`), since permission denial and primary/secondary
rate limits can share that status. HTTP 429 and other errors are **error**. A
404 is **unknown** (`not-visible-or-not-enabled`), because the observer cannot
independently distinguish disabled settings from a permission-hidden resource.
Every one of these blocking states remains visible; none becomes successful
verification or a fallback to mutable publication.

GitHub documents this endpoint as requiring Administration **read** access.
The ordinary workflow token may therefore produce a denied or unknown result.
A production controller must use a separately reviewed read-only credential
binding; granting such access or enabling the setting is an operator action
outside this observer. No credential is collected by this implementation.

For an environment to be **configured**, supply its independently reviewed
`EnvironmentIntent`: numeric/node identity, exact user reviewer IDs, self-review
prevention, exact default-branch and `v*` tag restrictions, expected wait timer and
an explicitly false `can_admins_bypass`. The existing exact controller validator
enforces these controls. Missing bypass metadata is **unknown**, enabled bypass
is **disabled**, and missing/unsupported controls reject the observation. Without
independent environment policy, a discovered environment is **unknown** and its
identity/configuration hash is audit-only. Discovery never creates or adopts it.

## Authority and remaining release gates

Every returned record has `run_bound`, `protected_environment_authenticated`,
`signing_authorized`, `publication_authorized`, `immutable_release_verified` and
`release_attestation_verified` set to false. A configured environment still has
unsupported current-attempt approval and effective enforcement. Configuration,
old run-level approval history and a serialized receipt do not authorize the
current signing or publication job.

This component supplies read-only prerequisites for tickets #9/#10. The protected
current-attempt credential gate, owned immutable draft state machine, final-byte
served-asset verification, final mutable rechecks, publication and post-publication
release attestation verification remain separate required components. It does
not establish SLSA Build L2 or close either ticket.

## Validation

`tests/test_build_publication_capabilities_v1.py` covers exact identity, status
denial, malformed JSON/headers, redirect and contradictory exit rejection,
configuration changes, clock rollback/expiry, independent environment policy,
fixed routes, actual inert-child isolation, bounded output and child termination.
Mocks in those fixtures do not authenticate GitHub or production capabilities.

The separate hosted `capability-rehearsal-v1.yml` workflow runs
`tests/capability_cases_v1.py` on all three supported native runners with the real
workflow read token and pinned native gh. It retains observed blocking states,
genuine bad-auth rejection and native-byte substitution rejection. This is a PR
qualification under an unprivileged token, with every operational authority
false; it does not qualify a production administrative-read credential.
Its artifacts are isolated from the existing development run's exact three-policy
artifact set. Adding capability receipts to that run would correctly make its
native transport and artifact-writer collectors reject the extra assets.

Primary API contracts:

- [Immutable release configuration GET](https://docs.github.com/en/rest/repos/repos#check-if-immutable-releases-are-enabled-for-a-repository)
- [Existing environment configuration GET](https://docs.github.com/en/rest/deployments/environments#get-an-environment)
- [Run-level approval history](https://docs.github.com/en/rest/actions/workflow-runs#get-the-review-history-for-a-workflow-run)
- [Rate-limit failures and ambiguous HTTP 403](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)
- [Environment job protection rules](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idenvironment)
