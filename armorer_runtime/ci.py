"""Fixed CI commands and a restricted, project-owned policy translation."""

from __future__ import annotations

import argparse
from datetime import date, datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import tomllib

from . import common, tools
from .common import Failure, require

POLICY_PATH = ".armorer/ci-policy.toml"
ADVISORY = re.compile(r"RUSTSEC-[0-9]{4}-[0-9]{4}\Z")
LICENSE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]*(?: WITH [A-Za-z0-9][A-Za-z0-9.+-]*)?\Z")


def exact_fields(value: dict, required: set[str], optional: set[str] = frozenset()) -> None:
    require(isinstance(value, dict) and required <= value.keys() and value.keys() <= required | optional,
            "unsupported or incomplete CI policy; explicit policy review/import required")


def load_policy(root: Path, today: date | None = None) -> dict:
    try:
        policy = tomllib.loads(common.read_input(root, POLICY_PATH).decode())
    except (ValueError, UnicodeError) as error:
        raise Failure("invalid CI policy") from error
    exact_fields(policy, {"schema_version", "licenses", "advisories", "sources", "bans"})
    require(type(policy["schema_version"]) is int and policy["schema_version"] == 1, "unsupported CI policy version")
    exact_fields(policy["licenses"], {"allow"})
    licenses = policy["licenses"]["allow"]
    require(isinstance(licenses, list) and 0 < len(licenses) <= 128 and all(isinstance(v, str) for v in licenses) and
            len(set(licenses)) == len(licenses),
            "explicit nonempty license allowlist required")
    require(all(isinstance(value, str) and LICENSE.fullmatch(value) for value in licenses), "invalid license identifier")
    exact_fields(policy["advisories"], {"exceptions"})
    exceptions = policy["advisories"]["exceptions"]
    require(isinstance(exceptions, list) and len(exceptions) <= 32, "advisory exception count exceeds limit")
    today = today or datetime.now(timezone.utc).date()
    seen = set()
    for exception in exceptions:
        exact_fields(exception, {"id", "owner", "reason", "expires"})
        require(isinstance(exception["id"], str) and ADVISORY.fullmatch(exception["id"]), "invalid advisory exception ID")
        require(exception["id"] not in seen, "duplicate advisory exception")
        seen.add(exception["id"])
        for field in ("owner", "reason"):
            value = exception[field]
            require(isinstance(value, str) and 0 < len(value.strip()) <= 512 and
                    not any(ord(c) < 32 for c in value), "exception owner and reason are required")
        try:
            expiry = date.fromisoformat(exception["expires"])
        except (ValueError, TypeError) as error:
            raise Failure("exception expiry must be an ISO date") from error
        require(expiry.isoformat() == exception["expires"] and today <= expiry and
                (expiry - today).days <= 90, "advisory exception expired or exceeds 90-day bound")
    exact_fields(policy["sources"], {"allow_git"})
    git = policy["sources"]["allow_git"]
    require(isinstance(git, list) and len(git) <= 32 and all(isinstance(v, str) for v in git) and
            len(set(git)) == len(git), "invalid allowed source list")
    require(all(isinstance(url, str) and re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?", url)
                for url in git), "allowed Git sources must be explicit public GitHub repositories")
    exact_fields(policy["bans"], {"multiple_versions", "deny"})
    require(policy["bans"]["multiple_versions"] in ("warn", "deny"), "invalid duplicate-version policy")
    banned = policy["bans"]["deny"]
    require(isinstance(banned, list) and len(banned) <= 128 and all(isinstance(v, str) for v in banned) and
            len(set(banned)) == len(banned), "invalid crate ban list")
    require(all(isinstance(name, str) and common.IDENTIFIER.fullmatch(name) for name in banned), "invalid banned crate name")
    return policy


def deny_configuration(policy: dict, database_path: Path) -> str:
    def quote(value):
        return json.dumps(value, ensure_ascii=False)
    exceptions = ", ".join("{ id = " + quote(e["id"]) + ", reason = " +
                           quote(e["owner"] + ": " + e["reason"] + " (expires " + e["expires"] + ")") + " }"
                           for e in policy["advisories"]["exceptions"])
    banned = ", ".join("{ crate = " + quote(name) + " }" for name in policy["bans"]["deny"])
    return f'''[advisories]
db-urls = ["https://github.com/RustSec/advisory-db"]
db-path = {quote(str(database_path))}
maximum-db-staleness = "P1D"
yanked = "deny"
unmaintained = "all"
unsound = "all"
unused-ignored-advisory = "warn"
ignore = [{exceptions}]

[licenses]
allow = {quote(policy["licenses"]["allow"])}
include-dev = true
include-build = true
confidence-threshold = 0.95
unused-allowed-license = "allow"
private = {{ ignore = false }}

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
allow-git = {quote(policy["sources"]["allow_git"])}

[bans]
multiple-versions = {quote(policy["bans"]["multiple_versions"])}
multiple-versions-include-dev = true
wildcards = "deny"
deny = [{banned}]
'''


def reject_implicit_exceptions(project: common.Project) -> None:
    # cargo-deny walks every manifest ancestor even when --config is explicit.
    manifests = [common.member_manifest(project, case["package"]) for case in project.selections]
    for manifest in manifests:
        for ancestor in manifest.parent.parents:
            for name in ("deny.exceptions.toml", ".deny.exceptions.toml", ".cargo/deny.exceptions.toml"):
                require(not (ancestor / name).exists() and not (ancestor / name).is_symlink(),
                        "implicit Cargo-deny exceptions require explicit policy import")
        for name in ("deny.exceptions.toml", ".deny.exceptions.toml", ".cargo/deny.exceptions.toml"):
            require(not (manifest.parent / name).exists() and not (manifest.parent / name).is_symlink(),
                    "implicit Cargo-deny exceptions require explicit policy import")


def scan_workflows(root: Path, binaries: dict[str, Path], runner=common.run) -> None:
    workflows = root / ".github" / "workflows"
    paths = sorted(str(p) for p in workflows.glob("*.y*ml")) if workflows.exists() else []
    require(paths, "CI requires at least one workflow to audit")
    with tempfile.TemporaryDirectory(prefix="armorer-actionlint-") as directory:
        configuration = Path(directory) / "actionlint.yaml"
        require(not configuration.parent.resolve().is_relative_to(root.resolve()), "scanner configuration must be outside source")
        configuration.write_text("{}\n")
        runner([str(binaries["actionlint"]), "-config-file", str(configuration), "-shellcheck=", "-pyflakes=", *paths], cwd=root)
    runner([str(binaries["zizmor"]), "--offline", "--no-config", "--no-ignores", "--strict-collection",
            "--collect=all", str(root / ".github")], cwd=root)


def scan_secrets(root: Path, binary: Path, scratch: Path, runner=common.run) -> None:
    config = scratch / "gitleaks.toml"
    config.write_text('[extend]\nuseDefault = true\n')
    ignore = scratch / ".gitleaksignore"
    ignore.write_text("")
    # No matched data is printed, including tool errors; only the stage is reported.
    runner([str(binary), "dir", str(root), "--config", str(config), "--gitleaks-ignore-path", str(ignore),
            "--ignore-gitleaks-allow", "--redact=100", "--no-banner", "--no-color", "--timeout", "120"], cwd=scratch)


def cargo_commands(case: dict, has_library: bool) -> list[list[str]]:
    flags = ["--locked", "--package", case["package"], "--target", case["target"], *common.cargo_flags(case)]
    commands = [["cargo", "test", *flags, "--all-targets"]]
    if has_library:
        commands.append(["cargo", "test", *flags, "--doc"])
    commands.append(["cargo", "clippy", *flags, "--all-targets", "--", "-D", "warnings"])
    return commands


def has_doctest_target(package: dict) -> bool:
    # Cargo cannot run docs for pure C ABI/dylib targets; proc-macros do support docs.
    return any({"lib", "rlib", "proc-macro"}.intersection(target["kind"]) for target in package["targets"])


def run_policy(project: common.Project, case: dict, policy: dict, binary: Path, scratch: Path,
               env: dict[str, str], runner=common.run) -> None:
    generated = scratch / "deny.toml"
    generated.write_text(deny_configuration(policy, scratch / "advisory-db"))
    manifest = common.member_manifest(project, case["package"])
    arguments = [str(binary), "--locked", "--config", str(generated), "--manifest-path", str(manifest),
                 "--target", case["target"], *common.cargo_flags(case)]
    runner(["cargo", "fetch", "--locked", "--manifest-path", str(manifest), "--target", case["target"]],
           cwd=scratch, env=env)
    # A failed fresh update stops here. Offline check cannot silently reuse stale DBs.
    runner([*arguments, "fetch", "all"], cwd=scratch, env=env)
    runner([*arguments, "--offline", "check", "advisories", "licenses", "sources", "bans"], cwd=scratch, env=env)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("matrix", "run"))
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--armorer", required=True, type=Path)
    parser.add_argument("--artifact-id")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        common.check_trigger(os.environ.get("GITHUB_EVENT_NAME", "workflow_dispatch"))
        common.setup_toolchain(args.root)
        project = common.load_project(args.root, args.armorer, os.environ.get("GITHUB_REPOSITORY"))
        policy = load_policy(project.root)
        reject_implicit_exceptions(project)
        if args.operation == "matrix":
            matrix = {"include": [{"artifact_id": c["artifact_id"], "runner": c["runner"]} for c in project.selections]}
            require(args.output is not None, "matrix requires trusted output path")
            with args.output.open("a") as handle:
                handle.write("matrix=" + json.dumps(matrix, separators=(",", ":")) + "\n")
            return 0
        require(args.artifact_id is not None, "CI case requires selection ID")
        case = common.select(project, args.artifact_id)
        require(tools.platform_target() == case["target"], "selected target does not match native runner")
        with tempfile.TemporaryDirectory(prefix="armorer-ci-") as temporary:
            scratch = Path(temporary)
            require(not scratch.is_relative_to(project.root), "CI scratch must be outside source")
            cargo_home = scratch / "cargo"
            cargo_home.mkdir()
            env = common.cargo_environment(case["toolchain"], cargo_home, scratch / "target")
            binaries = tools.install_tools(scratch / "tools", ["cargo-deny", "actionlint", "zizmor", "gitleaks"])
            for stage, function in (("workflow-audit", lambda: scan_workflows(project.root, binaries)),
                                    ("secret-scan", lambda: scan_secrets(project.root, binaries["gitleaks"], scratch)),
                                    ("format", lambda: common.run(["cargo", "fmt", "--all", "--", "--check"], cwd=project.root, env=env)),
                                    ("dependency-policy", lambda: run_policy(project, case, policy, binaries["cargo-deny"], scratch, env))):
                print("Armorer CI stage: " + stage, flush=True)
                function()
            package = next(p for p in project.plan["workspace"]["packages"] if p["name"] == case["package"])
            has_library = has_doctest_target(package)
            for command in cargo_commands(case, has_library):
                print("Armorer CI stage: " + command[1], flush=True)
                common.run(command, cwd=project.root, env=env)
            print("Armorer CI case verified; no release or provenance claim.", flush=True)
        return 0
    except (Failure, OSError, ValueError, KeyError, TypeError) as error:
        print("Armorer CI failed: " + (str(error) if isinstance(error, Failure) else "invalid or unavailable input"), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
