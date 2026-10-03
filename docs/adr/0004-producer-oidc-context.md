# ADR 0004: Authenticate producer job identity before release integration

Status: proposed implementation for review; no production controller accepted.

Source/provider observations identify a run and its artifacts but cannot prove
that the current credentialed job is the independently expected SHA-pinned
reusable workflow. We need that identity before connecting signing or
publication operations.

Use a fixed-audience GitHub OIDC request, a fresh fixed-issuer keyset and native
RS256 signature verification. Match all source, caller, signer, run, attempt,
current-job and effective-environment claims against independent intent. Reject
unsafe intent before requesting credentials. Return a private in-memory proof
and a separately whitelisted observation; never accept an offered token or JSON
record as authority.

Keep this first version outside privileged workflows. Validate the bounded
cryptographic protocol with synthetic issuer keys on three native Node 24
Actions runners without granting OIDC permissions. A signed job/environment
claim does not establish protection rules, artifact authorship, actor
authorization, current controller roots, signing approval or publication.
Those gates remain explicit and fail closed until independently implemented
and operationally qualified. See the [exact contract and limitations](../producer-oidc-context-v1.md).

No dependency, old schema, existing reusable-builder input, credential surface,
catalog acceptance, environment setting or historical receipt is changed.
