# Node public release signature qualification v1

The Node 24.21.0 archive pins currently enforce byte identity. Their upstream
signature and production catalog/root approval remain incomplete. This slice
qualifies genuine public OpenPGP signature verification separately; it does not
change the producer launcher's permission or `upstream_signature_authenticated`
fields and does not grant signing/publication authority.

The fixture freezes official signing keys at `nodejs/release-keys` commit
`481637f813e912c4aa3622d7964ab426c97b8e8d` and the Node 24.21.0 source at
`955266bfdd854cd280dffd47548673914484e4c0`. That source's README lists signing key
`5BE8A3F6C8A5C01D106C0AD820B1A390B168D356`. The actual detached SHA256/EdDSA
signature covers the checksum manifest and therefore the existing Linux x64,
Linux ARM64 and macOS ARM64 archive digests. The fixture source receipt retains
all exact URLs, Git blobs and byte identities. No downloaded archive is executed
or extracted by this qualification.

The fixed qualification uses Linux `/usr/bin/gpgv`, an empty private home and
the frozen public keyring. It accepts no caller options, credentials, keyserver,
commands or upstream scripts. Input/native byte bounds, closed stdin, cleared
startup environment, output/deadline limits and complete private process-group
cleanup apply. Required signature result, exact signer/algorithm, expiration
and error/revocation status checks precede an informational receipt. The native
verifier's observed bytes are retained; they are not an approved production tool
catalog. Root/catalog acceptance and producer integration remain false.

The separate read-only workflow runs actual native verification on Linux x64 and
ARM64 and retains receipts; its macOS job must record explicit unsupported
status with `native_signature_verified: false`. macOS system GPGv qualification is unsupported;
there is no alternative or checksum fallback. Authenticating checksum entries
for a macOS archive is not qualification of an OpenPGP verifier on macOS. Native
macOS verification, production root/tool/catalog review and fixed producer
integration remain required. No Build L2 achievement follows from this fixture.

An exploratory test-only PGPy oracle verifies the detached and cleartext
signature math and rejects changed bytes. Its self-signature and revocation
checks are incomplete, so that oracle cannot satisfy production authentication.
No PGPy dependency is introduced into the product.

Primary sources: [Node release verification](https://github.com/nodejs/node/blob/955266bfdd854cd280dffd47548673914484e4c0/README.md#verifying-binaries),
[official pinned key set](https://github.com/nodejs/release-keys/tree/481637f813e912c4aa3622d7964ab426c97b8e8d),
[fixed signed manifest](https://nodejs.org/dist/v24.21.0/SHASUMS256.txt.asc).
