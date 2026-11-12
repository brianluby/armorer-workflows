# Release controller v1

`.github/workflows/rust-release-controller-v1.yml` is the reusable publication
controller (`workflow_call`). It is inert until a caller supplies the
digest-pinned approvals and a built armorer binary: there is no push or
pull-request trigger, and no signing or attestation secret is accepted. The
caller repository owns the `release-publish` environment and its required
reviewers; this workflow only binds and observes one attempt.

## Deployment binding contract

Before any publication write, the controller creates exactly one deployment
bound to its own run/attempt through the fixed route
`POST repos/{repo}/deployments`, then marks it active through
`POST repos/{repo}/deployments/{id}/statuses`. The create body uses
`auto_merge: false` so the frozen commit is never merged with the default
branch (a merge would change the sha and break the binding), and
`required_contexts: []` because commit-status checks are not the publication
gate — the environment's required reviewers and the native adapter's gate
observation are the authority.

The deployment payload keys are the exact contract shared with the native Rust
adapter (`armorer_runtime/controller_deployment_v1.py` mirrors
`src/verification/publication/github.rs`):

```json
{"armorer_run_id": <run id>, "armorer_run_attempt": <attempt>, "armorer_source_commit": <head sha>}
```

`armorer_run_id` and `armorer_run_attempt` are positive integers taken from the
workflow's own `github.run_id`/`github.run_attempt`, never from a provider
record; `armorer_source_commit` is the 40-character lowercase head sha. The
adapter's `source_gates` confirms exactly one deployment binds this attempt
(environment match, `sha == source.commit`, payload match, creator
`github-actions[bot]`), that it is the sole active deployment for the
environment, and that `actions/runs/{id}/approvals` shows an approved entry for
the policy environment by an allowed approver who is not the actor or
triggering actor. Both gates then report Enforced; otherwise Unknown, with the
established unavailable mapping (401 denied, 403/404 unknown, 410 unsupported,
other explicit). A completed or failed attempt marks its deployment inactive so
it does not hold serialization hostage.

## Serialization

The job sets `concurrency: { group: armorer-release-controller,
cancel-in-progress: false }`. That concurrency group is the real runner-wide
enforcement: one controller runs at a time and an in-flight publication is
never cancelled. The single active deployment is the API-observable proxy the
adapter checks; a second active deployment blocks `runner-wide-serialization`.
The environment name is `release-publish` and the concurrency group is
`armorer-release-controller` on both sides.

## Startup boundary and permissions

The job fixes the producer startup environment (producer-startup-v1) before any
step receives the job token: Node, Python, loader, crypto and proxy startup
variables are cleared at job level. The deployment write uses the job's
ephemeral `GITHUB_TOKEN` through the qualified native gh with a sterile child
environment; no credential value is embedded in code or inputs. Permissions are
scoped to the single writing job: `deployments: write` to bind the attempt,
`contents: write` for the armorer release create/publish, and `actions: read` so
the adapter can observe run approvals. The CLI binary, native gh, approvals and
every digest arrive as workflow inputs; the workflow builds nothing and accepts
no command or script input.

## Residual trust

The workflow must be the immutable pinned controller referenced by the
publication policy. A write-access actor inside the existing protected-workflow
trust boundary could forge a deployment; this binding is not an atomic
compare-and-swap. The approvals API is run-scoped, so the attempt binding comes
from the workflow-written deployment payload, not from the approval record
itself. Settings-only inspect still reports both current-attempt gates
Unsupported; genuine enforcement is observable only through this deployment.

## Owner-blocked items

- A second independent reviewer for the `release-publish` environment
  (`prevent_self_review` requires an approver who is not the triggering actor).
- Production publication policy approval: the independently approved policy
  digest, allowed actor/publisher/approver IDs, environment identity and the
  release-attestation root must be reviewed and supplied by the owner.
- A built, independently qualified armorer binary and native gh, plus the
  digest-pinned staging/publication approvals, before any caller wires this
  workflow. No live publication is authorized by this document.