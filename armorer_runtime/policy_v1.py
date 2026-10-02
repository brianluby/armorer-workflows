"""Independent unprivileged policy observations; no build, signing or publication operation."""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import tomllib

from . import ci, common, policy_tools_v1 as pins, tools
from .build import BuildError, parse_json
from .common import Failure, require

MAX_REPORT = 4 * 1024 * 1024
MAX_DATABASE = 32 * 1024 * 1024
MAX_SOURCE = 128 * 1024 * 1024
MAX_FILE = 16 * 1024 * 1024
MAX_FILES = 4096
REPORT_NAMES = frozenset({"actionlint.json", "zizmor.json", "gitleaks.json", "cargo-deny.jsonl",
                          "source-inputs.json", "advisory-db.json"})
RUNTIME_INPUTS = ("armorer_runtime/__init__.py", "armorer_runtime/common.py", "armorer_runtime/tools.py",
                  "armorer_runtime/build.py", "armorer_runtime/ci.py", "armorer_runtime/policy_tools_v1.py",
                  "armorer_runtime/policy_v1.py", "pins/policy-tools-v1.json")


def canonical(value: object) -> bytes:
    """Serialize retained observations deterministically without accepting nonstandard numbers."""
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def capture(arguments: list[str], cwd: Path, environment: dict[str, str], *, timeout: int = 300) -> tuple[bytes, bytes]:
    """Bound both output pipes while running a fixed argument array; never reveal failed diagnostics."""
    process = subprocess.Popen(arguments, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for name, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
                require(pipe is not None, "policy output pipe unavailable")
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            while selector.get_map() or process.poll() is None:
                require(time.monotonic() < deadline, "policy command timed out")
                for key, _ in selector.select(timeout=0.05):
                    remaining = MAX_REPORT + 1 - len(buffers[key.data])
                    block = os.read(key.fileobj.fileno(), min(65536, remaining))
                    if not block:
                        selector.unregister(key.fileobj)
                    else:
                        buffers[key.data].extend(block)
                        require(len(buffers[key.data]) <= MAX_REPORT, "policy command output limit")
            require(process.wait(timeout=5) == 0, "policy command failed")
        return bytes(buffers["stdout"]), bytes(buffers["stderr"])
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            require(process.poll() is not None, "policy process cleanup failed")
        process.wait(timeout=5)
        for pipe in (process.stdout, process.stderr):
            if pipe is not None:
                pipe.close()


def regular(path: Path, limit: int = MAX_FILE) -> bytes:
    """Read one bounded regular opened inode and reject symlink substitution or growth."""
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, "policy input type or size")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        require(stat.S_ISREG(opened.st_mode) and (opened.st_dev, opened.st_ino, opened.st_size) ==
                (before.st_dev, before.st_ino, before.st_size), "policy input changed during open")
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    require(len(data) == before.st_size and len(data) <= limit and
            (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) ==
            (after.st_size, after.st_mtime_ns, after.st_ctime_ns), "policy input changed while reading")
    return data


def snapshot(root: Path, destination: Path | None = None) -> dict:
    """Hash every bounded regular source file except root Git metadata; optionally make a private inert copy."""
    require(root.is_dir() and not root.is_symlink(), "policy source must be a regular directory")
    records = {}
    pending = [root]
    entries_seen = 0
    total = 0
    if destination is not None:
        require(not destination.exists() and not destination.is_symlink(), "policy snapshot destination exists")
        destination.mkdir(mode=0o700)
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                if directory == root and entry.name == ".git":
                    continue
                entries_seen += 1
                require(entries_seen <= MAX_FILES * 2 and entry.name != ".git", "policy source entry limit or nested repository")
                path = Path(entry.path)
                relative = path.relative_to(root).as_posix()
                require(not any(ord(c) < 32 or ord(c) == 127 for c in relative) and "\\" not in relative,
                        "unsafe policy source path")
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                    if destination is not None:
                        (destination / relative).mkdir(mode=0o700)
                else:
                    require(entry.is_file(follow_symlinks=False) and len(records) < MAX_FILES,
                            "policy source contains unsupported entry")
                    data = regular(path, MAX_FILE)
                    total += len(data)
                    require(total <= MAX_SOURCE, "policy source byte limit")
                    records[relative] = pins.identity(data)
                    if destination is not None:
                        with (destination / relative).open("xb") as stream:
                            stream.write(data)
                        (destination / relative).chmod(0o400)
    require(records, "empty policy source")
    return dict(sorted(records.items()))


def git(root: Path, arguments: list[str], environment: dict[str, str]) -> bytes:
    """Read fixed Git state with global/system configuration and hooks disabled."""
    output, _ = capture(["/usr/bin/git", "-c", "core.hooksPath=/dev/null", *arguments], root, environment)
    return output


def source_context(root: Path, expected: dict, environment: dict[str, str]) -> None:
    """Require a clean exact source checkout before and after policy checks; context is still only an observation."""
    require(git(root, ["rev-parse", "HEAD"], environment).decode().strip() == expected["commit"],
            "policy source commit mismatch")
    require(Path(git(root, ["rev-parse", "--show-toplevel"], environment).decode().strip()).resolve() == root,
            "policy source checkout root mismatch")
    require(not git(root, ["status", "--porcelain=v1", "--untracked-files=all"], environment),
            "policy source checkout is dirty")


def context(value: dict) -> None:
    """Validate explicit source/run/runtime/trigger observations without granting protected-job authority."""
    require(isinstance(value, dict) and set(value) == {"source", "runtime_commit", "run_id", "run_attempt", "event", "ref"},
            "incomplete policy context")
    require(isinstance(value["source"], dict) and set(value["source"]) == {"repository", "commit"} and
            re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value["source"]["repository"]) and
            re.fullmatch(r"[0-9a-f]{40}", value["source"]["commit"]) and
            re.fullmatch(r"[0-9a-f]{40}", value["runtime_commit"]), "invalid policy source/runtime identity")
    for key in ("run_id", "run_attempt"):
        require(isinstance(value[key], str) and re.fullmatch(r"[1-9][0-9]{0,19}", value[key]), "invalid policy run identity")
    common.check_trigger(value["event"])
    require(isinstance(value["ref"], str) and len(value["ref"]) <= 512 and
            re.fullmatch(r"refs/(?:heads|tags|pull)/[A-Za-z0-9_./-]+", value["ref"]), "invalid policy ref")


def runtime_inputs(expected_commit: str, environment: dict[str, str]) -> dict:
    """Bind committed helper bytes to the executing reusable workflow commit, rejecting local modifications."""
    root = Path(__file__).resolve().parent.parent
    require(git(root, ["rev-parse", "HEAD"], environment).decode().strip() == expected_commit,
            "policy runtime commit mismatch")
    result = {}
    for relative in RUNTIME_INPUTS:
        data = common.read_input(root, relative)
        require(git(root, ["show", "HEAD:" + relative], environment) == data, "policy runtime helper is not committed")
        result[relative] = pins.identity(data)
    return result


def database_snapshot(parent: Path, environment: dict[str, str], fetched_at: int, now: int) -> bytes:
    """Retain actual bounded advisory files and Git identities from the required successful fresh fetch."""
    candidates = list(parent.glob("*/.git"))
    require(len(candidates) == 1 and candidates[0].is_dir() and not candidates[0].is_symlink(),
            "unexpected policy advisory database")
    root = candidates[0].parent
    commit = git(root, ["rev-parse", "HEAD"], environment).decode().strip()
    tree = git(root, ["rev-parse", "HEAD^{tree}"], environment).decode().strip()
    require(re.fullmatch(r"[0-9a-f]{40}", commit) and re.fullmatch(r"[0-9a-f]{40}", tree),
            "invalid policy advisory Git identity")
    require(not git(root, ["status", "--porcelain=v1", "--untracked-files=all"], environment), "advisory database changed")
    # RustSec can create a fresh clone without FETCH_HEAD. This is the actual wall-clock
    # observation after the fixed successful fetch into a previously nonexistent private DB.
    # cargo-deny independently enforces its native P1D staleness policy during check.
    require(type(fetched_at) is int and 0 < fetched_at <= now and now - fetched_at <= 3600,
            "advisory database fetch is stale or in the future")
    tracked = git(root, ["ls-files", "-z"], environment).split(b"\0")
    files = {}
    total = 0
    for raw in tracked:
        if not raw:
            continue
        relative = raw.decode()
        require(len(files) < MAX_FILES and relative not in files, "advisory file count or duplicate path")
        data = common.read_input(root, relative)
        total += len(data)
        require(total <= MAX_FILE, "advisory database byte limit")
        files[relative] = {**pins.identity(data), "base64": base64.b64encode(data).decode("ascii")}
    require(files, "empty advisory database")
    result = canonical({"schema_version": 1, "repository": "https://github.com/RustSec/advisory-db",
                        "commit": commit, "tree": tree, "fetched_at": fetched_at,
                        "upstream_signature_verified": False, "files": files})
    require(len(result) <= MAX_DATABASE, "advisory snapshot report limit")
    return result


def passing_report(name: str, data: bytes) -> dict:
    """Require native passing report semantics, including all four explicit cargo-deny summaries."""
    require(0 < len(data) <= MAX_REPORT and name in NATIVE_REPORTS, "policy native report size or name")
    if name != "cargo-deny.jsonl":
        require(parse_json(data) == [], "policy scanner reported findings")
        return {"findings": 0}
    messages = [parse_json(line) for line in data.splitlines() if line.strip()]
    summaries = [item for item in messages if isinstance(item, dict) and item.get("type") == "summary"]
    require(len(summaries) == 1 and messages[-1] == summaries[0] and set(summaries[0]) == {"type", "fields"} and
            set(summaries[0]["fields"]) == {"advisories", "bans", "licenses", "sources"},
            "cargo-deny did not complete all four checks")
    for counts in summaries[0]["fields"].values():
        require(isinstance(counts, dict) and set(counts) == {"errors", "helps", "notes", "warnings"} and
                all(type(n) is int and 0 <= n <= 100000 for n in counts.values()) and counts["errors"] == 0,
                "cargo-deny reported failure or unsupported counts")
    for item in messages[:-1]:
        require(isinstance(item, dict) and item.get("type") == "diagnostic" and
                isinstance(item.get("fields"), dict) and item["fields"].get("severity") in ("warning", "help", "note"),
                "unsupported cargo-deny diagnostic")
    return summaries[0]["fields"]


NATIVE_REPORTS = frozenset({"actionlint.json", "zizmor.json", "gitleaks.json", "cargo-deny.jsonl"})


def tool_report(tool: pins.QualifiedTool, arguments: list[str], source: Path,
                environment: dict[str, str], *, stderr_report: bool = False, timeout: int = 300) -> bytes:
    """Recheck qualified bytes around one fixed scanner call and return only the chosen successful report pipe."""
    tool.verify()
    stdout, stderr = capture([str(tool.path), *arguments], source, environment, timeout=timeout)
    tool.verify()
    return stderr if stderr_report else stdout


def checks(project: common.Project, case: dict, qualified: dict[str, pins.QualifiedTool], scratch: Path,
           environment: dict[str, str]) -> tuple[dict[str, bytes], dict]:
    """Run fixed static/scanner/dependency checks only; never invoke consuming builds, tests or helpers."""
    require(set(qualified) == pins.NAMES and case["target"] == tools.platform_target() and
            case["toolchain"] == "1.95.0", "unsupported native policy selection")
    ci.reject_implicit_exceptions(project)
    policy = ci.load_policy(project.root)
    configuration = scratch / "actionlint.yaml"
    configuration.write_text("{}\n")
    workflows = sorted(str(project.root / relative) for relative in snapshot(project.root)
                       if Path(relative).parent.as_posix() == ".github/workflows" and Path(relative).suffix in (".yml", ".yaml"))
    require(workflows, "policy requires workflows to audit")
    reports = {}
    reports["actionlint.json"] = tool_report(qualified["actionlint"], ["-config-file", str(configuration),
        "-shellcheck=", "-pyflakes=", "-format", "{{json .}}", *workflows], scratch, environment)
    reports["zizmor.json"] = tool_report(qualified["zizmor"], ["--offline", "--no-config", "--no-ignores",
        "--strict-collection", "--collect=all", "--format=json-v1", "--no-progress", "--color=never",
        str(project.root / ".github")], scratch, environment)
    leaks_config = scratch / "gitleaks.toml"
    leaks_config.write_text('[extend]\nuseDefault = true\n')
    ignore = scratch / "gitleaksignore"
    ignore.write_text("")
    reports["gitleaks.json"] = tool_report(qualified["gitleaks"], ["dir", str(project.root), "--config", str(leaks_config),
        "--gitleaks-ignore-path", str(ignore), "--ignore-gitleaks-allow", "--redact=100", "--no-banner",
        "--no-color", "--timeout", "120", "--report-format", "json", "--report-path", "-"], scratch, environment)
    for name, data in reports.items():
        passing_report(name, data)
    generated = scratch / "deny.toml"
    generated.write_text(ci.deny_configuration(policy, scratch / "advisory-db"))
    manifest = common.member_manifest(project, case["package"])
    arguments = ["--locked", "--config", str(generated), "--manifest-path", str(manifest),
                 "--target", case["target"], *common.cargo_flags(case)]
    capture(["cargo", "fetch", "--locked", "--manifest-path", str(manifest), "--target", case["target"]],
            scratch, environment, timeout=900)
    # A failed fetch never reaches the offline check or creates a report artifact.
    require(not (scratch / "advisory-db").exists(), "policy requires a fresh private advisory database")
    tool_report(qualified["cargo-deny"], [*arguments, "fetch", "all"], scratch, environment, timeout=900)
    fetched_at = int(time.time())
    database_before = database_snapshot(scratch / "advisory-db", environment, fetched_at, int(time.time()))
    reports["cargo-deny.jsonl"] = tool_report(qualified["cargo-deny"], [*arguments, "--offline", "--format", "json",
        "check", "--show-stats", "advisories", "licenses", "sources", "bans"], scratch, environment,
        stderr_report=True, timeout=900)
    passing_report("cargo-deny.jsonl", reports["cargo-deny.jsonl"])
    require(database_before == database_snapshot(scratch / "advisory-db", environment, fetched_at, int(time.time())),
            "advisory data changed during check")
    reports["advisory-db.json"] = database_before
    return reports, policy


def produce(root: Path, armorer: Path, artifact_id: str, output: Path, expected_context: dict) -> dict:
    """Retain a complete run-bound unsigned observation only after every independent policy gate passes."""
    started = int(time.time())
    context(expected_context)
    common.setup_toolchain(root)
    project = common.load_project(root, armorer, expected_context["source"]["repository"])
    case = common.select(project, artifact_id)
    require(case["target"] == tools.platform_target() and case["toolchain"] == "1.95.0", "unsupported native policy compiler/target")
    root = project.root
    require(not output.exists() and not output.is_symlink() and not output.resolve().is_relative_to(root),
            "policy report output must be new and outside source")
    with tempfile.TemporaryDirectory(prefix="armorer-policy-v1-") as temporary:
        scratch = Path(temporary).resolve()
        require(not scratch.is_relative_to(root), "policy scratch must be outside source")
        cargo_home = scratch / "cargo-home"
        cargo_home.mkdir()
        environment = common.cargo_environment("1.95.0", cargo_home, scratch / "cargo-target")
        home = scratch / "home"
        home.mkdir()
        environment["HOME"] = str(home)
        helpers = runtime_inputs(expected_context["runtime_commit"], environment)
        source_context(root, expected_context["source"], environment)
        inputs = snapshot(root, scratch / "source")
        require({"armorer.toml", "armorer.lock", "Cargo.lock", ci.POLICY_PATH} <= inputs.keys(),
                "policy source lacks independently bindable configuration/lock/policy")
        lock = tomllib.loads(common.read_input(root, "armorer.lock").decode())
        require(lock.get("schema_version") == 1 and lock.get("runtime_version") == "0.1.0" and
                lock.get("config_sha256") == inputs["armorer.toml"]["sha256"] and
                lock.get("workflows") == {"repository": "brianluby/armorer-workflows", "commit": expected_context["runtime_commit"]},
                "policy lock requires the exact reviewed runtime workflow pin")
        # The consuming source copy contains only inert regular files; all executables come from trusted runtime/toolchain.
        copied = common.Project(scratch / "source", project.config, project.plan, project.selections)
        qualified, catalog_id = pins.install(scratch / "tools")
        reports, policy = checks(copied, case, qualified, scratch, environment)
        require(snapshot(copied.root) == inputs and snapshot(root) == inputs, "policy source changed during checks")
        source_context(root, expected_context["source"], environment)
        reports["source-inputs.json"] = canonical(inputs)
        finished = int(time.time())
        require(0 < started <= finished and finished - started <= 3600, "policy observation exceeded age bound")
        envelope = {"schema_version": 1, "state": "passing-unsigned-policy-observation", **expected_context,
                    "selection": case, "scope": "cargo-workspace-with-explicit-target-and-features",
                    "observed": {"started_at": started, "finished_at": finished}, "effective_policy": policy,
                    "runtime_inputs": helpers, "tool_catalog": catalog_id,
                    "tools": {name: {"version": tool.version, "target": tool.target, **tool.pin} for name, tool in qualified.items()},
                    "reports": {name: pins.identity(data) for name, data in reports.items()},
                    "checks": {name: passing_report(name, reports[name]) for name in sorted(NATIVE_REPORTS)},
                    "signing_authorized": False, "producer_job_authenticated": False,
                    "cryptographic_release_authenticated": False}
        require(set(reports) == REPORT_NAMES and len(canonical(envelope)) <= MAX_REPORT, "incomplete policy report set")
        output.mkdir(mode=0o700, parents=True)
        try:
            for name, data in {**reports, "policy-v1.json": canonical(envelope)}.items():
                with (output / name).open("xb") as stream:
                    stream.write(data)
                (output / name).chmod(0o400)
        except BaseException:
            # Never leave a partial directory that could be mistaken for a successful observation.
            for leaf in output.iterdir():
                leaf.unlink()
            output.rmdir()
            raise
        return envelope


def verify(directory: Path, expected_context: dict, expected_selection: dict, expected_inputs: dict,
           expected_runtime_inputs: dict, expected_catalog: dict, expected_policy: dict, *, now: int | None = None) -> dict:
    """Compare complete inert reports with independent expectations; this never authenticates a producer or authorizes signing."""
    context(expected_context)
    observed_now = int(time.time()) if now is None else now
    require(type(observed_now) is int and observed_now > 0, "invalid policy verification clock")
    require(stat.S_ISDIR(directory.lstat().st_mode), "policy report directory must be regular")
    names = set(REPORT_NAMES) | {"policy-v1.json"}
    actual = set()
    with os.scandir(directory) as entries:
        for entry in entries:
            require(len(actual) < 7 and entry.name in names and entry.is_file(follow_symlinks=False),
                    "unexpected policy report entry")
            actual.add(entry.name)
    require(actual == names, "incomplete policy report directory")
    # All offered bytes are bounded and hashed before parsing any native report or advisory snapshot.
    data = {name: regular(directory / name, MAX_DATABASE if name == "advisory-db.json" else MAX_REPORT) for name in names}
    envelope = parse_json(data["policy-v1.json"])
    fields = {"schema_version", "state", "source", "runtime_commit", "run_id", "run_attempt", "event", "ref",
              "selection", "scope", "observed", "effective_policy", "runtime_inputs", "tool_catalog", "tools",
              "reports", "checks", "signing_authorized", "producer_job_authenticated", "cryptographic_release_authenticated"}
    require(isinstance(envelope, dict) and set(envelope) == fields and type(envelope["schema_version"]) is int and
            envelope["schema_version"] == 1 and envelope["state"] == "passing-unsigned-policy-observation" and
            envelope["scope"] == "cargo-workspace-with-explicit-target-and-features" and
            all(envelope[name] is False for name in ("signing_authorized", "producer_job_authenticated", "cryptographic_release_authenticated")),
            "unsupported policy observation or unauthorized authority claim")
    require(all(envelope[key] == expected_context[key] for key in expected_context) and
            envelope["selection"] == expected_selection and envelope["effective_policy"] == expected_policy and
            envelope["runtime_inputs"] == expected_runtime_inputs and set(expected_runtime_inputs) == set(RUNTIME_INPUTS) and
            all(pins.byte_identity(value, common.MAX_INPUT) for value in expected_runtime_inputs.values()) and
            expected_selection["toolchain"] == "1.95.0", "policy source/run/selection/policy/runtime mismatch")
    require(isinstance(expected_catalog, dict) and set(expected_catalog) == {"catalog", "identity"} and
            envelope["tool_catalog"] == expected_catalog["identity"] and
            set(expected_catalog["catalog"]["tools"]) == pins.NAMES, "independent policy catalog mismatch")
    target = expected_selection["target"]
    require(target in common.RUNNERS and envelope["tools"] == {
        name: {"version": tool["version"], "target": target, **tool["platforms"][target]}
        for name, tool in expected_catalog["catalog"]["tools"].items()}, "qualified policy tool identity mismatch")
    require(envelope["reports"] == {name: pins.identity(data[name]) for name in REPORT_NAMES}, "policy report bytes mismatch")
    require(parse_json(data["source-inputs.json"]) == expected_inputs and
            {"armorer.toml", "armorer.lock", "Cargo.lock", ci.POLICY_PATH} <= expected_inputs.keys(),
            "independent policy source input mismatch")
    observation = envelope["observed"]
    require(isinstance(observation, dict) and set(observation) == {"started_at", "finished_at"} and
            type(observation["started_at"]) is int and type(observation["finished_at"]) is int and
            0 < observation["started_at"] <= observation["finished_at"] <= observed_now and
            observed_now - observation["started_at"] <= 3600, "policy observation expired or in the future")
    require(envelope["checks"] == {name: passing_report(name, data[name]) for name in NATIVE_REPORTS},
            "native report result mismatch")
    database = parse_json(data["advisory-db.json"])
    require(isinstance(database, dict) and set(database) == {"schema_version", "repository", "commit", "tree", "fetched_at",
                                                           "upstream_signature_verified", "files"} and
            type(database["schema_version"]) is int and database["schema_version"] == 1 and
            database["repository"] == "https://github.com/RustSec/advisory-db" and
            database["upstream_signature_verified"] is False and
            re.fullmatch(r"[0-9a-f]{40}", database["commit"]) and re.fullmatch(r"[0-9a-f]{40}", database["tree"]) and
            type(database["fetched_at"]) is int and observation["started_at"] <= database["fetched_at"] <= observation["finished_at"] and
            isinstance(database["files"], dict) and 0 < len(database["files"]) <= MAX_FILES,
            "invalid actual advisory snapshot")
    total = 0
    for name, record in database["files"].items():
        path = Path(name)
        require(not path.is_absolute() and path.parts and ".." not in path.parts and ".git" not in path.parts and
                "\\" not in name and not any(ord(c) < 32 or ord(c) == 127 for c in name) and
                isinstance(record, dict) and set(record) == {"sha256", "size", "base64"} and
                isinstance(record["base64"], str), "unsafe advisory snapshot file")
        raw = base64.b64decode(record["base64"], validate=True)
        total += len(raw)
        require(len(raw) <= common.MAX_INPUT and total <= MAX_FILE and
                pins.identity(raw) == {key: record[key] for key in ("sha256", "size")}, "advisory snapshot bytes mismatch")
    final_now = int(time.time()) if now is None else now
    require(observation["finished_at"] <= final_now and final_now - observation["started_at"] <= 3600,
            "policy observation expired during verification")
    return envelope


def main() -> int:
    """Expose only fixed report production from explicit GitHub observation fields, never signing operations."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--armorer", required=True, type=Path)
    parser.add_argument("--artifact-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        expected = {"source": {"repository": os.environ["GITHUB_REPOSITORY"], "commit": os.environ["GITHUB_SHA"]},
                    "runtime_commit": os.environ["ARMORER_RUNTIME_COMMIT"], "run_id": os.environ["GITHUB_RUN_ID"],
                    "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"], "event": os.environ["GITHUB_EVENT_NAME"],
                    "ref": os.environ["GITHUB_REF"]}
        produce(args.root, args.armorer, args.artifact_id, args.output, expected)
        print("Armorer policy observation retained; protected finalization is not authorized.")
        return 0
    except (Failure, BuildError, OSError, ValueError, KeyError, TypeError, RecursionError):
        print("Armorer policy observation failed; no retained passing report.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
