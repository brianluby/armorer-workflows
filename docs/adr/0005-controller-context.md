# ADR 0005: Independently mapped current-job observations

Status: implemented candidate prerequisite; production acceptance pending.

The bounded producer OIDC helper authenticates an exact independently
expected `check_run_id`. Taking that expectation from the token itself
would fail to bind the independently intended job. The native source
observer already binds source, caller, actors and mutable refs but has no
current-job mapping.

Add a versioned read-only controller observer beside the frozen source and
transport adapters. Require a reviewed exact workflow/job name and native
label, complete bounded attempt pagination, one unique selected job,
canonical check-run association, direct job identity, active state and
repeated source/job/run reads. Preserve the older adapters byte for byte.

Observe optional preexisting environment controls against independent
IDs, exact user reviewers and typed deployment restrictions. Keep
configuration, unknown bypass metadata and unsupported current-attempt
approval separate from effective enforcement. Never promote run-level
approval history or hidden ruleset bypass information into authority.

The receipt is audit data. A future fixed credential-isolated controller
must join the independently mapped identity with verified producer OIDC,
accepted roots, effective protections and final-byte verification. This
observer performs no OIDC, signing, credential provisioning or release
mutation, and cannot authorize those operations.
