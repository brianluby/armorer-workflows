# Reusable Rust CI, experimental version one

`rust-ci.yml` runs unprivileged, fixed gates for library, CLI and service
deliverables. It accepts no inputs or secrets: the consuming checkout's root
`armorer.toml` supplies package, binary, target and named feature selections.
Use a reviewed full commit SHA in the caller's `uses` reference. Retain bespoke
CI alongside this job; Armorer never imports or overwrites existing workflows.

The initial native runners are `ubuntu-24.04`, `ubuntu-24.04-arm` and `macos-15`.
At most 128 validated cases and three concurrent jobs are allowed. Runner images
are mutable; this slice does not claim reproducible builds or a SLSA level.

## Caller and trust boundary

Call on ordinary `pull_request` and `push` events with `contents: read` and no
`secrets: inherit`. `workflow_dispatch` is also supported for rehearsal. Privileged
`pull_request_target`, `workflow_run`, release and unsupported events fail before
checkout or configuration processing. There are no signing environments, OIDC,
write permissions, signing credentials or shared output caches.

The workflow validates GitHub's `job.workflow_repository` and
`job.workflow_sha` before checking out its own helpers at that exact commit.
GitHub installations lacking those fields fail closed; substituting the caller's
`github.workflow_sha` would select the wrong repository. Helpers never load Python
from consuming source. The trusted Armorer CLI is built with `--locked` and Rust
1.95.0 from `brianluby/armorer@1615339b6415afa9bb9d65e2c37304e977158c4e`
outside the caller source tree, before executing caller code.

Each job rederives its selection through that CLI and checks repository identity
against GitHub's actual execution context. Matrix IDs choose cases; they do not
introduce a command, subject, source identity or provenance claim. Cargo manifests
and configuration are checked against discovery digests. Repository and ancestor
Cargo configuration, symlinks and implicit Cargo-deny exception files require
explicit migration review. Source must be stable during discovery; these guards
are not an operating-system sandbox.

The pinned consumer Rust version is syntax checked before installing it with
fixed Rustup arguments. The tool environment clears credentials, Cargo wrappers,
flags and caller PATH entries; Cargo uses isolated home and target directories.
Fixed commands run in separate process groups with bounded time/output and kill
surviving descendants after completion. Rust tests and build scripts execute
caller code only in these disposable, unprivileged jobs.

## Explicit project policy

Create and review `.armorer/ci-policy.toml`. The following is an example decision
for the synthetic fixture, **not a default allowlist for adopting projects**:

```toml
schema_version = 1

[licenses]
allow = ["MIT", "Apache-2.0"]

[advisories]
exceptions = []

[sources]
allow_git = []

[bans]
multiple_versions = "warn"
deny = []
```

Every section is required and unknown fields are errors. Licenses are a nonempty
SPDX identifier allowlist, including explicit `WITH` exceptions when needed;
Cargo-deny validates recognized identifiers. Build and development dependency
licenses are included, and private workspace packages are not exempt. Unlisted
licenses and unlicensed packages fail. Sources are crates.io plus explicitly
listed public GitHub HTTPS Git repositories; unknown registries/Git sources fail.
Wildcard dependency specifications fail. Duplicate versions must be `warn` or
`deny`; named crate bans are explicit. Custom registries, license clarifications,
license/bans exceptions and additional Cargo-deny settings need a later reviewed
policy extension. Existing `deny.toml` files remain untouched; this gate uses only
the typed policy and reports unsupported implicit exceptions instead of merging
opaque settings.

Advisory exceptions have an exact RustSec ID and a nonempty `owner`, `reason`,
and quoted ISO `expires` date. There are at most 32 exceptions, each valid through
its UTC expiry day and no more than 90 days ahead. Expired, duplicate, unowned,
and wildcard exceptions fail. Cargo-deny records unused-exception warnings because
a reviewed exception may apply to only one target/feature graph in a workspace;
these non-failing diagnostics are captured rather than printed. Replace the example's
empty `exceptions` array with tables when adding an exception:

```toml
[[advisories.exceptions]]
id = "RUSTSEC-2026-0001"
owner = "security-maintainer"
reason = "Reviewed impact and tracked remediation"
expires = "2026-10-15"
```

Generated Cargo-deny configuration is outside source. Dependency bytes are first
fetched with `cargo fetch --locked` for the selected manifest/target. All advisory,
registry and standard-replacement feeds are freshly fetched; failures stop CI.
Then offline Cargo-deny checks advisories, licenses, sources and bans with a fixed
one-day RustSec fetch-age ceiling. There is no stale-data fallback or permissive
private-repository downgrade. All vulnerability/unsound advisories, yanked crates
and unmaintained dependencies fail unless the restricted exception applies.

Cargo-deny 0.20.2 classifies non-ignored advisories as errors; explicit
`unmaintained = "all"` and `unsound = "all"` include transitive dependencies.
It removed `--disable-fetch` and accepts `fetch db/index/std-replacement/all`.
The published binary was tested; runtime uses global `--offline` after fresh fetch.
Policy graphs are rooted at each discovered member manifest with its explicit
target/default/declared features, never blanket `--workspace --all-features`.

## Gates and reviewed tools

Formatting covers the workspace. Each selected case runs locked package tests
over all targets, library/procedural-macro doctests where available, and Clippy over all targets
with warnings denied, preserving the declared feature case. Package CI tests
may cover other binaries in that package; release binary selection is separate.
Cargo does not support doctests for pure `dylib`, `cdylib` or `staticlib` targets;
such cases retain package tests/lints. Cargo's explicit `doctest = false` setting
is honored, so a passing doc command does not claim documentation coverage when
the package disables it.

Actionlint 1.7.12 checks workflow syntax using an explicit external empty
configuration; caller `.github/actionlint.yaml`/`.yml` ignore rules cannot bypass
it. Zizmor 1.30.1 runs offline with strict
collection, no configuration/ignore rules, and collection ignoring `.gitignore`.
Gitleaks 8.30.1 scans present files with trusted built-in rules, an external empty
ignore file, inline ignores disabled and full redaction. Process output is captured
and never printed on failure; only gate names and static errors appear. Secret
values and matched source lines are never emitted or uploaded. Full Git history
scanning and online-only Zizmor audits remain explicit follow-ups; passing these
scanners is not proof that no secret or workflow vulnerability exists.

Cargo-deny 0.20.2 and the scanner distributions are pinned by URL and SHA-256 in
`pins/tools.json` for all three native platforms. Downloads are bounded and checked
before extraction; traversal, links, devices, duplicate binaries and oversized
archives fail. Only the expected binary is written. Installer destinations must
be trusted empty directories outside consuming source. Zizmor requires Rust 1.97
to compile, so its reviewed native binary avoids changing the consumer toolchain.

## Verification and recovery

Run `python3 -m unittest discover -s tests -p 'tests_*.py'` for boundary tests.
Set `ARMORER_TEST_TOOLS` to a directory of verified native tools to enable real
scanner failures; `ARMORER_TEST_NETWORK=1` additionally runs live RustSec freshness,
registry license checks, denied-license and stale-feed failures, and locked native
tests/lints for all three profiles. Hosted development CI runs these on all three
runner platforms. The separate `rehearsal.yml` calls the actual no-input reusable
workflow against the repository's explicitly labeled synthetic root workspace:
three profiles on three native runners, with service JSON and minimal feature
cases. Its project-owned fixture allowlist is not an adopter default, and no
`armorer.lock` or release readiness is invented for this CI-only rehearsal.
Skip messages mean that evidence was not collected locally.

Fix the reported gate, review policy changes, and rerun. Advisory outages remain
failures; retry once the feed is reachable. Existing customization is preserved
and needs explicit import decisions. A passing run provides CI evidence for that
source/configuration; configured, release rehearsed, published and provenance
verified remain separate states. These workflows neither attest nor publish.

Primary references: [GitHub job context](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#job-context),
[Cargo-deny advisories](https://embarkstudios.github.io/cargo-deny/checks/advisories/cfg.html),
[license policy](https://embarkstudios.github.io/cargo-deny/checks/licenses/cfg.html),
[Zizmor usage](https://docs.zizmor.sh/usage/), and
[Gitleaks CLI](https://github.com/gitleaks/gitleaks#usage).
