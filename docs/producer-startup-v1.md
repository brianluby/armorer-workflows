# Producer startup boundary v1

Credentialed producer authentication starts in isolated Python, which copies a
fixed byte-qualified native Node into private scratch and starts a fixed worker
with an exact environment. JavaScript checks cannot prevent
`NODE_OPTIONS=--require=...`: a startup hook can read the request credential,
replace fetch and erase its marker before authentication runs. The original
Node-first OIDC/mapped exports now reject explicitly. Internal worker modules
are implementation details and synthetic fixtures; importing them in a
caller-controlled Node process is unsupported.

The fixed composite action `.github/actions/producer-launcher-v1` invokes
absolute isolated Python and overrides startup variables through trusted step
configuration before the interpreter starts. A complete privileged job must
fix its startup environment before any earlier action/executable receives
credentials. No credentialed release job is wired yet. Python remains a
hosted-image dependency; this does not establish a sandbox against hostile
same-user processes or a reproducible interpreter. Accepted controller source
and independently enforced job boundaries remain required.

The request is an independently approved bounded UTF-8 JSON file:

```json
{"schema_version":1,"operation":"oidc","intent":{}}
```

That empty intent demonstrates the envelope and is rejected. Complete intent
uses the exact [OIDC fields](producer-oidc-context-v1.md), or `operation: "mapped"`
and the [independent mapping contract](mapped-producer-context-v1.md). Approve
the exact file SHA-256 before parsing or credential access. Token contents and
downloaded artifacts never choose the expected source, signer, job or environment.
There is no arbitrary command, script, token, keyset, provider callback or URL
input. The eventual fixed controller derives intent from independently accepted
policy/catalog and authenticated platform context.

Prepare Node in a credential-free stage with `prepare_node(destination)` from
`armorer_runtime/producer_launcher_v1.py`. It downloads one fixed official
24.21.0 archive without proxy inheritance, verifies compiled size/SHA-256 and
writes only the exact `bin/node` leaf after checking executable size/SHA-256.
Other archive entries are never extracted or executed. A privileged stage
accepts only this exact native executable; it does not install tools. The
launcher copies a no-follow leaf to private scratch and rehashes the copy
before credential access. File path input cannot select another digest or code.

| Platform | Node executable size | SHA-256 |
| --- | ---: | --- |
| Linux x86_64 | 126595440 | `7fde7b8afa198da66257f42ee2001d874c7355631e6d1579a5fb5ef1f246df4c` |
| Linux ARM64 | 122893672 | `0f8949d1028f6d61506b2d5bc57e7e6fe893d7b1997509b7847294fc9c616584` |
| macOS ARM64 | 122129232 | `e4b5a3af0e05c75de2eae013904145f40fe7fc2a6e6f17510128bf45cca4e79b` |

These proposed delivery pins were compared with the
[fixed official manifest](https://nodejs.org/dist/v24.21.0/SHASUMS256.txt).
Upstream release-signature authentication and production catalog acceptance
have not been established. The observation explicitly reports
`production_node_catalog_accepted: false`; separate review is required before
these become an accepted runtime/catalog or release authority.

The fresh child receives fixed PATH/locale/private HOME/TMPDIR and
`ACTIONS_ID_TOKEN_REQUEST_URL`, `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, plus
`ARMORER_WORKFLOW_READ_TOKEN` for a mapped operation. Node startup flags,
extra CAs, TLS bypass, proxies, Python/OS loader variables, Apple material and
ambient GH credentials are excluded. Credentials appear only in the child
environment, never arguments or serialized stdin. Input/output/diagnostic
streams and the entire worker have independent bounds. Cancellation gives the
mapped native worker time to reap separate groups; remaining launcher-group
descendants are killed even after the leader exits.

Only a noncredential audit is serialized. Private proofs stay in the fresh
process; JSON cannot recreate a retired Node-first proof interface. Signing and
publication authority remain false. Live protected approval, accepted roots/
catalog, an own signed producer/inventory positive, Apple parity and controlled
publication/recovery remain separate gates. No SLSA level follows from fixtures.

The native regression executes the actual entry/RSA worker with a fixed
synthetic issuer and a real preload that tries to read a fake token and erase
`NODE_OPTIONS`. The safe launch never executes it; a direct Node control does
read the fake token. Additional cases cover wrong approval/substituted bytes
before credential access, environment allowlisting, retired interfaces and an
exited leader with surviving pipe holders. Authentication tests use no network
or real credentials; public Node preparation is a separate qualification.
