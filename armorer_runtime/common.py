"""Fixed, unprivileged command and validated project boundaries.

This adapter is trusted only when loaded from a reviewed workflow repository
commit. It never imports Python or executes helpers from consuming repositories.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time
import tomllib

RUNNERS = {
    "x86_64-unknown-linux-gnu": "ubuntu-24.04",
    "aarch64-unknown-linux-gnu": "ubuntu-24.04-arm",
    "aarch64-apple-darwin": "macos-15",
}
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}\Z")
FEATURE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_+.-]{0,99}\Z")
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
MAX_INPUT = 1024 * 1024


class Failure(Exception):
    """A static, non-secret workflow failure message."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Failure(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_input(root: Path, relative: str) -> bytes:
    """Read a bounded regular file, rejecting all symlink path components."""
    path = Path(relative)
    require(not path.is_absolute() and path.parts and ".." not in path.parts, "unsafe input path")
    require("\\" not in relative and not any(ord(c) < 32 for c in relative), "unsafe input path")
    candidate = root
    for part in path.parts:
        candidate = candidate / part
        require(not candidate.is_symlink(), "symlink input is unsupported")
    require(candidate.is_file(), "expected regular input file")
    with candidate.open("rb") as handle:
        data = handle.read(MAX_INPUT + 1)
    require(len(data) <= MAX_INPUT, "input exceeds size limit")
    return data


def base_environment(forbidden_root: Path | None = None) -> dict[str, str]:
    """Omit credentials, Cargo wrappers and caller-controlled process variables."""
    home = Path.home().resolve()
    candidates = [home / ".cargo/bin/rustup", Path("/opt/homebrew/bin/rustup"),
                  Path("/usr/local/bin/rustup"), Path("/usr/bin/rustup")]
    rustup = next((p for p in candidates if p.is_file() and os.access(p, os.X_OK)), None)
    require(rustup is not None, "trusted rustup is unavailable")
    if forbidden_root is not None:
        require(not rustup.resolve().is_relative_to(forbidden_root), "rustup must be outside caller source")
    path = os.pathsep.join([str(rustup.parent.resolve()), "/usr/bin", "/bin", "/usr/sbin", "/sbin"])
    env = {"HOME": str(home), "PATH": path, "LANG": "C.UTF-8", "RUSTUP_HOME": str(home / ".rustup"),
           "RUSTUP_AUTO_INSTALL": "0", "CARGO_TERM_COLOR": "never", "RUSTC_WRAPPER": "",
           "RUSTC_WORKSPACE_WRAPPER": "", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_TERMINAL_PROMPT": "0"}
    # Apple's developer tools need the system's selected SDK, but no caller flags.
    if os.uname().sysname == "Darwin":
        env["LANG"] = "en_US.UTF-8"
    return env


def run(argv: list[str], *, cwd: Path, env: dict[str, str] | None = None,
        timeout: int = 1800, capture: bool = False, max_output: int = 16 * 1024 * 1024) -> bytes:
    """Run an argument array; captured output is bounded and never printed on error."""
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(argv, cwd=cwd, env=env or base_environment(), stdin=subprocess.DEVNULL,
                                   stdout=stdout, stderr=stderr, start_new_session=True)
        deadline = time.monotonic() + timeout
        try:
            while process.poll() is None:
                require(time.monotonic() < deadline, "fixed command timed out")
                require(os.fstat(stdout.fileno()).st_size <= max_output and
                        os.fstat(stderr.fileno()).st_size <= max_output, "fixed command exceeded output limit")
                time.sleep(0.05)
            require(process.returncode == 0, "fixed command failed")
            require(os.fstat(stdout.fileno()).st_size <= max_output and
                    os.fstat(stderr.fileno()).st_size <= max_output, "fixed command exceeded output limit")
            stdout.seek(0)
            return stdout.read() if capture else b""
        finally:
            # Cargo build scripts must not survive a failed gate or successful command.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


def strict_json(data: bytes) -> dict:
    def pairs(items: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    try:
        result = json.loads(data, object_pairs_hook=pairs)
    except (ValueError, UnicodeError) as error:
        raise Failure("invalid JSON input") from error
    require(isinstance(result, dict), "expected JSON object")
    return result


@dataclass(frozen=True)
class Project:
    root: Path
    config: dict
    plan: dict
    selections: list[dict]


def selections(config: dict) -> list[dict]:
    """Rederive IDs and fixed runners; never accept caller matrix claims."""
    require(VERSION.fullmatch(config["toolchain"]) is not None, "invalid exact toolchain")
    result = []
    ids = set()
    for deliverable in config["deliverables"]:
        case = config["feature_sets"][deliverable["feature_set"]]
        for name in (deliverable["id"], deliverable["package"], deliverable["feature_set"]):
            require(isinstance(name, str) and IDENTIFIER.fullmatch(name) is not None, "invalid selection identifier")
        require(deliverable["profile"] in ("library", "cli", "service"), "unsupported profile")
        binary = deliverable.get("binary")
        require((deliverable["profile"] == "library" and binary is None) or
                (deliverable["profile"] != "library" and isinstance(binary, str) and
                 IDENTIFIER.fullmatch(binary) is not None), "invalid binary selection")
        require(type(case["default_features"]) is bool, "invalid feature selection")
        require(all(isinstance(f, str) and FEATURE.fullmatch(f) for f in case["features"]), "invalid declared feature")
        for target in deliverable["targets"]:
            require(target in RUNNERS, "unsupported native target")
            artifact_id = f'{deliverable["id"]}--{target}--{deliverable["feature_set"]}'
            require(artifact_id not in ids, "duplicate artifact identity")
            ids.add(artifact_id)
            result.append({**deliverable, "binary": binary, "target": target, "default_features": case["default_features"],
                           "features": sorted(case["features"]), "runner": RUNNERS[target],
                           "artifact_id": artifact_id, "toolchain": config["toolchain"]})
    require(0 < len(result) <= 128, "selection count exceeds hosted matrix bound")
    return sorted(result, key=lambda case: case["artifact_id"])


def load_project(root: Path, armorer: Path, expected_repository: str | None = None) -> Project:
    root = root.resolve(strict=True)
    armorer = armorer.resolve(strict=True)
    require(not armorer.is_relative_to(root), "runtime must be outside caller source")
    reject_cargo_configuration(root)
    env = base_environment(root)
    # The trusted preview must not inherit a caller-local TMPDIR or Cargo config.
    temporary_parent = Path(tempfile.gettempdir()).resolve(strict=True)
    require(not temporary_parent.is_relative_to(root), "temporary storage must be outside caller source")
    reject_cargo_configuration(temporary_parent)
    env["TMPDIR"] = str(temporary_parent)
    plan = strict_json(run([str(armorer), "--repository", str(root), "plan"], cwd=armorer.parent, env=env, capture=True))
    require(plan.get("schema_version") == 1 and plan.get("mode") == "plan", "unsupported preview contract")
    config = plan["intent"]
    require(plan["config_sha256"] == sha256(read_input(root, "armorer.toml")), "configuration changed during discovery")
    if expected_repository is not None:
        require(config["repository"] == expected_repository, "configuration repository disagrees with source context")
    require(plan["workspace"]["cargo_lock_present"], "locked CI requires Cargo.lock")
    require(not plan["workspace"]["cargo_config_present"], "Cargo overrides require explicit migration review")
    for path, digest in plan["workspace"]["inputs"].items():
        if path.endswith("Cargo.toml") or path == "Cargo.lock":
            require(sha256(read_input(root, path)) == digest, "Cargo input changed during discovery")
    return Project(root, config, plan, selections(config))


def select(project: Project, artifact_id: str) -> dict:
    matches = [case for case in selections(project.config) if case["artifact_id"] == artifact_id]
    require(len(matches) == 1, "unknown artifact selection")
    return matches[0]


def member_manifest(project: Project, package: str) -> Path:
    require(any(p["name"] == package for p in project.plan["workspace"]["packages"]), "unknown workspace package")
    candidates = []
    for relative, digest in project.plan["workspace"]["inputs"].items():
        if Path(relative).name != "Cargo.toml":
            continue
        data = read_input(project.root, relative)
        require(sha256(data) == digest, "manifest changed since discovery")
        document = tomllib.loads(data.decode())
        if document.get("package", {}).get("name") == package:
            candidates.append(project.root / relative)
    require(len(candidates) == 1, "selected member manifest is ambiguous")
    return candidates[0]


def cargo_environment(toolchain: str, cargo_home: Path, target_dir: Path) -> dict[str, str]:
    require(VERSION.fullmatch(toolchain) is not None, "invalid exact toolchain")
    reject_cargo_configuration(cargo_home.parent.resolve())
    env = base_environment()
    rustc = run(["rustup", "which", "--toolchain", toolchain, "rustc"], cwd=cargo_home.parent,
                env=env, capture=True).decode().strip()
    compiler = Path(rustc).resolve(strict=True)
    env.update({"CARGO_HOME": str(cargo_home.resolve()), "CARGO_TARGET_DIR": str(target_dir.resolve()),
                "RUSTC": str(compiler), "RUSTDOC": str(compiler.with_name("rustdoc")),
                "PATH": os.pathsep.join([str(compiler.parent), env["PATH"]])})
    return env


def cargo_flags(case: dict) -> list[str]:
    return ([] if case["default_features"] else ["--no-default-features"]) + (
        ["--features", ",".join(case["features"])] if case["features"] else [])


def check_trigger(event: str) -> None:
    require(event in ("pull_request", "push", "workflow_dispatch"), "unsupported unprivileged trigger")


def setup_toolchain(root: Path) -> str:
    """Install only the syntax-checked exact version before CLI discovery."""
    root = root.resolve(strict=True)
    reject_cargo_configuration(root)
    document = tomllib.loads(read_input(root, "armorer.toml").decode())
    toolchain = document.get("toolchain")
    require(isinstance(toolchain, str) and VERSION.fullmatch(toolchain), "invalid exact toolchain")
    run(["rustup", "toolchain", "install", toolchain, "--profile", "minimal", "--component", "clippy,rustfmt"],
        cwd=Path(__file__).resolve().parent, env=base_environment(root))
    return toolchain


def reject_cargo_configuration(directory: Path) -> None:
    """Cargo consults every cwd ancestor; CARGO_HOME alone is insufficient."""
    for ancestor in (directory, *directory.parents):
        for name in (".cargo/config", ".cargo/config.toml"):
            path = ancestor / name
            require(not path.exists() and not path.is_symlink(), "Cargo ancestor overrides require migration review")
