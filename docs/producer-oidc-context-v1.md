# Producer OIDC context v1

This experimental helper authenticates a job's GitHub OIDC identity against
independent controller expectations. It is not yet connected to a privileged
release workflow. Native RSA protocol fixtures are synthetic issuer evidence;
they do not establish a live protected producer, artifact authentication, signing
approval, an accepted production catalog, or SLSA achievement.

`armorer_runtime/producer_oidc_v1.mjs` has two exports:

- `authenticateProducerContext(intent)` requests the current job token and
  verifies it before returning a private, frozen, in-memory proof.
- `producerContextRecord(proof)` exports a frozen noncredential observation.
  Offered JSON, deserialized records and reconstructed objects cannot become a
  proof. Direct proof serialization fails. There is no exported token, keyset,
  audience, provider URL, caller shell, predicate or signing operation.

An eventual fixed controller must obtain the intent from independently reviewed
policy/catalog expectations and current authenticated platform context. Copying
expectations from token contents or accepting arbitrary caller inputs defeats
the intended boundary. The helper does not establish actor permissions, default
branch ancestry, protection rules, catalog acceptance, or the mapping of a check
run ID to the controller's intended job. Those remain separate required gates.

## Exact intent and identity

Intent must contain exactly these data-only fields, with no accessors or extra
properties:

| Fields | Required shape |
| --- | --- |
| `repository`, `repository_id`, `repository_owner_id`, `repository_visibility` | Exact repository name and canonical positive decimal string IDs; public or private visibility |
| `source_sha`, `caller_sha`, `signer_sha` | Full lowercase 40-character commits; caller commit equals source commit |
| `caller_path`, `signer_repository`, `signer_path` | Exact `.github/workflows/*.yml` paths; signer repository is `brianluby/armorer-workflows` |
| `event`, `ref`, `default_branch`, `protected_ref` | Dispatch on the exact expected default branch, or stable `vMAJOR.MINOR.PATCH` tag push; independently expected protection is `true` |
| `actor`, `actor_id` | Exact original initiating account and canonical string ID |
| `run_id`, `run_attempt`, `check_run_id` | Exact canonical positive string IDs for this run, attempt and current job |
| `environment`, `environment_node_id` | Both null for a job without an environment, or exact independently expected `release-signing`/`release-publish` name and environment node ID |
| `subject_mode` | Explicit reviewed `legacy` or `immutable` default subject format |

PR, PR-target, workflow-run, nondefault dispatch and prerelease-tag intent is
rejected before token-service access. No normalization, numeric coercion,
unknown-property acceptance, or subject-mode fallback is allowed.

Signed claims must match the source name/IDs/visibility, source commit, exact
ref/type, protected-ref string `"true"`, event, original actor, caller path and
commit, SHA-pinned reusable signer path and commit, run/attempt/check-run IDs,
and `github-hosted` runner. Environment name and node ID must match; an
environment-free intent rejects even null environment claims. A protected-ref
claim alone does not establish the adequacy of protection rules. The supported
claim types must still be qualified in an authorized live producer rehearsal.

Repository and owner IDs are checked in both subject modes. GitHub documents
immutable default subjects for newly created repositories and explicit legacy
compatibility for older ones. Custom subject templates are unsupported and
block the helper; it never changes OIDC settings. See the
[GitHub OIDC reference](https://docs.github.com/en/actions/reference/security/oidc).

## Transport, signature and proof lifetime

The fixed audience is `armorer:producer-context:v1`. The only issuer is
`https://token.actions.githubusercontent.com`; the JWKS URL is fixed to
`https://token.actions.githubusercontent.com/.well-known/jwks`, as advertised by
the [issuer discovery document](https://token.actions.githubusercontent.com/.well-known/openid-configuration).
Discovery fields and token headers cannot select another issuer or key service.

The current platform request URL and bearer credential come only from
`ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN`. URLs must
be HTTPS hosted Actions subdomains under `actions.githubusercontent.com`, use
the bounded distributed-task build-plan/job `idtoken` route and contain only an
optional single `api-version` query. Redirects, userinfo, nondefault ports,
fragments and additional queries fail. This conservative route must be
qualified against the eventual real producer; an unrecognized platform route
is a capability limitation and never triggers an unrestricted fallback.

There is one token-service GET and one fresh fixed-JWKS GET, without retries or
redirects. The service bearer is never sent to the JWKS endpoint. Each HTTP
operation has a ten-second deadline within a twenty-second authentication
stage. Body reads and cancellation cannot extend that deadline. Response bodies
are bounded to 256 KiB; JWTs, decoded headers, payloads, signatures, JSON depth,
node count and key count have separate limits. Duplicate decoded JSON keys,
prototype keys, invalid UTF-8, BOMs, trailing input and noncanonical base64url
fail. Errors expose only fixed stage codes without provider diagnostics.

Only native RS256 verification with an unambiguous public RSA key of 2048–8192
bits and exponent 65537 is accepted. Remote-key and critical-extension headers,
algorithm substitutions, duplicate key IDs, private parameters and weak keys
fail. Claims are parsed only after verifying the signature over the exact JWT
header and payload bytes. `iat`, `nbf` and `exp` must be positive safe integers;
there is no clock-skew grace, issue age exceeds neither five minutes nor token
lifetime, and token lifetime is at most ten minutes. Clock rollback fails.
Record export requires a still-live proof and at most five minutes since its
observation. A previously exported JSON record has no continuing authority.

The private proof retains only matched public identity, times and the JWKS byte
hash/size. Raw JWTs, request credentials, subject/JTI, unknown claims and raw
provider diagnostics are never returned, logged, written to files or retained
in the proof. This does not claim memory zeroization of JavaScript strings or
protection from arbitrary code already executing in the credentialed process.
Such code must be excluded by the eventual fixed controller.

## Evidence and remaining gates

The record marks `oidc_job_identity_authenticated: true` after successful
signature and exact-claim verification, and marks an effective environment
claim authenticated only when an environment is expected. All of these remain
false: `environment_protection_authenticated`, `artifact_producer_authenticated`,
`cryptographic_release_authenticated`, `production_catalog_accepted`,
`signing_authorized`, and `publication_authorized`.

The development workflow runs the fixed fixture suite on the Actions Node 24
runtime on Linux x86_64, Linux ARM64 and macOS ARM64. Its permissions remain
unprivileged and no live OIDC token is requested. Tests use ephemeral RSA keys
in memory and restore synthetic platform state after each case. The timeout
regression exercises the real ten-second limit with a reader and cancellation
that ignore abort. Local Node 22 runs are compatibility evidence only.

Before release integration, required work includes independent accepted roots,
fresh authenticated source/actor/ancestry context, exact current job mapping,
effective protected-environment enforcement and approval, an authorized live
OIDC producer positive, authenticated artifact handoffs, final-byte evidence,
complete signed inventory verification, Apple finalization and controlled
publication/recovery. This helper alone satisfies none of those ticket-level
acceptance gates.
