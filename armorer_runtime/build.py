"""Fixed Rust builders and run-bound, unsigned Cargo SBOM inventories.

This module deliberately has no signing, attestation or publication operation.
The Cargo graph is reconciled with one fresh, explicitly selected build before
it is handed to the pinned cargo-cyclonedx generator.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import tomllib


class BuildError(ValueError):
    """A build or inventory did not satisfy the fixed builder contract."""


LIBRARY_KINDS = {"lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro"}


def _unique_object(pairs):
    """Retain one JSON object while rejecting duplicate keys before semantic checks."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise BuildError("duplicate JSON key")
        result[key] = value
    return result


def parse_json(data: bytes | str):
    """Reject duplicate keys and nonstandard numeric values in evidence JSON."""
    try:
        return json.loads(data, object_pairs_hook=_unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(
                              BuildError("nonstandard JSON number")))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise BuildError("invalid evidence JSON") from error


def sha256(data: bytes) -> str:
    """Return the lowercase SHA-256 digest of exact supplied bytes."""
    return hashlib.sha256(data).hexdigest()


def _regular_bytes(path: Path, limit: int = 64 * 1024 * 1024) -> bytes:
    """Read one bounded regular evidence leaf without accepting a symlink."""
    if not stat.S_ISREG(path.lstat().st_mode) or path.is_symlink():
        raise BuildError("expected a regular evidence file")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise BuildError("evidence file exceeds its limit")
    return data


def _run(arguments: list[str], cwd: Path, environment: dict[str, str],
         timeout: int = 1800) -> bytes:
    """Run a fixed argument array with bounded output and no shell."""
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(arguments, cwd=cwd, env=environment,
                                   stdin=subprocess.DEVNULL, stdout=output,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
        deadline = time.monotonic() + timeout
        try:
            while process.poll() is None:
                if time.monotonic() > deadline or os.fstat(output.fileno()).st_size > 64 * 1024 * 1024:
                    raise BuildError("builder command exceeded its limit")
                time.sleep(0.05)
            if process.returncode != 0:
                raise BuildError("fixed builder command failed")
            if os.fstat(output.fileno()).st_size > 64 * 1024 * 1024:
                raise BuildError("builder output exceeds its limit")
            output.seek(0)
            return output.read()
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)


def feature_arguments(selection: dict) -> list[str]:
    """Derive only fixed Cargo feature flags from the validated selection."""
    arguments = [] if selection["default_features"] else ["--no-default-features"]
    if selection["features"]:
        arguments += ["--features", ",".join(selection["features"])]
    return arguments


def build_arguments(selection: dict, manifest: Path, target_dir: Path) -> list[str]:
    """Every build names a package, Cargo target and feature selection."""
    arguments = ["cargo", "build", "--locked", "--release", "--manifest-path", str(manifest),
                 "--package", selection["package"], "--target", selection["target"],
                 "--target-dir", str(target_dir), "--message-format", "json"]
    arguments += ["--lib"] if selection["profile"] == "library" else ["--bin", selection["binary"]]
    return arguments + feature_arguments(selection)


def compiler_evidence(data: bytes, selection: dict, manifest: Path | None = None) -> dict:
    """Extract the selected artifact and actual Cargo compilation graph."""
    packages: dict[str, set[str]] = {}
    roots = []
    native = []
    finished = False
    for line in data.splitlines():
        if not line.startswith(b"{"):
            continue  # Cargo does not control all subprocess output.
        message = parse_json(line)
        if not isinstance(message, dict):
            raise BuildError("invalid compiler message object")
        reason = message.get("reason")
        if reason == "build-finished":
            if finished or message.get("success") is not True:
                raise BuildError("invalid build completion evidence")
            finished = True
        elif reason == "compiler-artifact":
            package_id = message.get("package_id")
            features = message.get("features")
            target = message.get("target", {})
            if not isinstance(package_id, str) or not isinstance(features, list) or not all(isinstance(f, str) for f in features):
                raise BuildError("malformed compiler artifact")
            packages.setdefault(package_id, set()).update(features)
            kind = target.get("kind", [])
            if selection["profile"] == "library":
                candidate = bool(LIBRARY_KINDS.intersection(kind))
            else:
                candidate = kind == ["bin"] and target.get("name") == selection["binary"]
            # Manifest/package identity is checked against locked Cargo metadata.
            identity_matches = (Path(message.get("manifest_path", "")).resolve() == manifest.resolve()
                                if manifest is not None else
                                target.get("name") == (selection["package"].replace("-", "_")
                                                       if selection["profile"] == "library" else selection["binary"]))
            if candidate and identity_matches:
                roots.append(message)
        elif reason == "build-script-executed":
            libraries = message.get("linked_libs", [])
            if not isinstance(libraries, list) or not all(isinstance(x, str) for x in libraries):
                raise BuildError("malformed native linkage evidence")
            if libraries:
                native.append({"package_id": message.get("package_id"), "linked_libraries": sorted(libraries)})
    if not finished or not packages or len(roots) != 1:
        raise BuildError("missing or ambiguous selected build artifact")
    root = roots[0]
    if selection["profile"] != "library" and not isinstance(root.get("executable"), str):
        raise BuildError("selected binary has no executable")
    return {"root": root, "features": {p: sorted(f) for p, f in sorted(packages.items())},
            "native_linkage": sorted(native, key=lambda x: x["package_id"])}


def _optional_dependencies(package: dict, features: set[str]) -> set[str]:
    """Resolve optional dependency activation from actual local Cargo features."""
    active = set()
    definitions = package.get("features", {})
    for feature in features:
        for edge in definitions.get(feature, []):
            if edge.startswith("dep:"):
                active.add(edge[4:])
            elif "/" in edge and not edge.split("/", 1)[0].endswith("?"):
                active.add(edge.split("/", 1)[0])
            elif edge == feature and any(d.get("optional") and (d.get("rename") or d["name"]) == edge
                                          for d in package.get("dependencies", [])):
                active.add(edge)  # Compatibility with legacy implicit feature maps.
    return active  # Feature edges use declaration keys, not library target names.


def reconcile_metadata(metadata: dict, evidence: dict, selection: dict) -> dict:
    """Prune workspace unification using actual build IDs and optional edges.

    Cargo's metadata describes all workspace members. Removing only unused
    package IDs would retain optional edges enabled by unrelated members. We
    therefore derive edge activation from the features compiled for each
    package. Missing target/host information and unreachable compiled packages
    are errors, rather than assumptions about completeness.
    """
    result = copy.deepcopy(metadata)
    packages = {p["id"]: p for p in result.get("packages", [])}
    nodes = {n["id"]: n for n in result.get("resolve", {}).get("nodes", [])}
    if len(packages) != len(result.get("packages", [])) or len(nodes) != len(result.get("resolve", {}).get("nodes", [])):
        raise BuildError("duplicate Cargo package or node identity")
    root_id = evidence["root"]["package_id"]
    compiled = set(evidence["features"])
    if root_id not in result.get("workspace_members", []) or root_id not in packages:
        raise BuildError("selected artifact is not a workspace member")
    root = packages[root_id]
    if root.get("name") != selection["package"]:
        raise BuildError("wrong selected package identity")
    if not compiled <= packages.keys() or not compiled <= nodes.keys():
        raise BuildError("metadata omits a compiled target or host dependency")
    kept = {}
    for package_id in compiled:
        package = packages[package_id]
        node = nodes[package_id]
        active_optional = _optional_dependencies(package, set(evidence["features"][package_id]))
        dependencies = []
        for dependency in node.get("deps", []):
            name = dependency["name"].replace("-", "_")
            dependency_package = packages.get(dependency["pkg"], {})
            kinds = []
            for kind in dependency.get("dep_kinds", []):
                if kind.get("kind") == "dev":
                    continue
                declarations = [d for d in package.get("dependencies", [])
                                if d["name"] == dependency_package.get("name")
                                and (not d.get("rename") or d["rename"].replace("-", "_") == name)
                                and d.get("kind") == kind.get("kind")
                                and d.get("target") == kind.get("target")]
                if not declarations:
                    raise BuildError("dependency edge has no unambiguous declaration")
                enabled = [not d.get("optional", False) or (d.get("rename") or d["name"]) in active_optional
                           for d in declarations]
                if len(set(enabled)) != 1:
                    raise BuildError("ambiguous dependency activation")
                if enabled[0]:
                    kinds.append(kind)
            if kinds:
                if dependency["pkg"] not in compiled:
                    raise BuildError("active dependency was not accounted for by the build")
                dependencies.append({**dependency, "dep_kinds": kinds})
        kept[package_id] = {**node, "features": evidence["features"][package_id], "deps": dependencies,
                            "dependencies": sorted({d["pkg"] for d in dependencies})}
    reachable = set()
    pending = [root_id]
    while pending:
        current = pending.pop()
        if current not in reachable:
            reachable.add(current)
            pending.extend(kept[current]["dependencies"])
    if reachable != compiled:
        raise BuildError("compiled graph cannot be reconciled with selected Cargo dependencies")
    result["packages"] = [packages[p] for p in sorted(compiled)]
    result["workspace_members"] = [root_id]
    result["workspace_default_members"] = [root_id]
    result["resolve"] = {**result["resolve"], "root": root_id,
                         "nodes": [kept[p] for p in sorted(compiled)]}
    return result


def validate_sbom(data: bytes, expected_name: str, expected_version: str, expected_ids: set[str],
                  expected_metadata: dict | None = None) -> dict:
    """Check semantic identities before the independent offline schema validator."""
    bom = parse_json(data)
    if not isinstance(bom, dict) or bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.5":
        raise BuildError("unexpected SBOM format or specification version")
    metadata = bom.get("metadata")
    if not isinstance(metadata, dict) or not isinstance(metadata.get("component"), dict):
        raise BuildError("missing SBOM root component")
    root = metadata["component"]
    if root.get("name") != expected_name or root.get("version") != expected_version:
        raise BuildError("wrong SBOM root identity")
    components = bom.get("components", [])
    if not isinstance(components, list) or not all(isinstance(c, dict) for c in components):
        raise BuildError("invalid SBOM component inventory")
    refs = [root.get("bom-ref")] + [c.get("bom-ref") for c in components]
    if not all(isinstance(r, str) and r for r in refs) or len(set(refs)) != len(refs):
        raise BuildError("missing or duplicate SBOM component reference")
    if set(refs) != expected_ids:
        raise BuildError("SBOM does not describe the compiled Cargo package inventory")
    dependency_refs = set()
    dependencies = bom.get("dependencies")
    if not isinstance(dependencies, list) or not all(isinstance(n, dict) for n in dependencies):
        raise BuildError("missing SBOM dependency inventory")
    for node in dependencies:
        reference = node.get("ref")
        edges = node.get("dependsOn", [])
        if not isinstance(reference, str) or reference not in expected_ids or reference in dependency_refs or not isinstance(edges, list) or not all(isinstance(e, str) for e in edges):
            raise BuildError("invalid SBOM dependency identity")
        dependency_refs.add(reference)
        if len(set(edges)) != len(edges) or not set(edges) <= expected_ids:
            raise BuildError("dangling or duplicate SBOM dependency edge")
    if dependency_refs != expected_ids:
        raise BuildError("SBOM dependency graph is incomplete")
    if expected_metadata is not None:
        expected_packages = {p["id"]: p for p in expected_metadata["packages"]}
        expected_root_id = expected_metadata["resolve"].get("root")
        if not isinstance(expected_root_id, str) or expected_root_id not in expected_packages or root.get("bom-ref") != expected_root_id:
            raise BuildError("SBOM root reference disagrees with the selected Cargo package")
        expected_root = expected_packages[expected_root_id]
        if expected_root.get("version") != expected_version or not any(
                target.get("name") == expected_name for target in expected_root.get("targets", [])):
            raise BuildError("SBOM root identity disagrees with the selected Cargo target")
        for component in components:
            package = expected_packages[component["bom-ref"]]
            if component.get("name") != package["name"] or component.get("version") != package["version"]:
                raise BuildError("SBOM component disagrees with locked package identity")
        expected_edges = {n["id"]: set(n["dependencies"]) for n in expected_metadata["resolve"]["nodes"]}
        actual_edges = {n["ref"]: set(n.get("dependsOn", [])) for n in bom["dependencies"]}
        if actual_edges != expected_edges:
            raise BuildError("SBOM dependency edges disagree with the compiled Cargo graph")
    return bom


def metadata_adapter(directory: Path, metadata: dict, expected_arguments: list[str]) -> Path:
    """Create a fixed executable returning previously locked, reconciled metadata.

    It accepts only the exact metadata invocation the pinned generator makes.
    It does not execute Cargo and accepts no caller claims or shell commands.
    """
    executable = directory / "cargo-metadata-adapter"
    payload = json.dumps(metadata, separators=(",", ":"), sort_keys=True)
    executable.write_text(f"#!{sys.executable}\nimport sys\n"
                          f"if sys.argv[1:] != {expected_arguments!r}:\n    sys.exit(64)\n"
                          f"sys.stdout.write({payload!r})\n", encoding="utf-8")
    executable.chmod(0o700)
    return executable


def _file_record(path: Path, role: str) -> dict:
    """Hash a bounded regular output leaf and retain its exact name, role and size."""
    if not stat.S_ISREG(path.lstat().st_mode) or path.is_symlink():
        raise BuildError("expected a regular inventory file")
    size = path.stat().st_size
    if size > 1024 * 1024 * 1024:
        raise BuildError("inventory file exceeds its limit")
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return {"name": path.name, "role": role, "size": size, "sha256": hasher.hexdigest()}


def _verify_inventory(directory: Path, inventory: dict, expected_selection: dict | None,
                      expected_context: dict | None, *, expected_version: int) -> None:
    """Verify the exact unsigned file inventory; it is not signature verification."""
    required = {"schema_version", "state", "signing_status", "provenance_status", "source", "runtime_commit",
                "run_id", "run_attempt", "selection", "input_sha256", "source_input_sha256", "tool_sha256",
                "tool_pin_authority", "graph_scope", "coverage_gaps", "artifact_kind", "files"}
    if expected_version == 2:
        required.add("cargo_graph_version")
    if not isinstance(inventory, dict) or set(inventory) != required:
        raise BuildError("unexpected inventory fields")
    published_inventory = parse_json(_regular_bytes(directory / "inventory.json", 16 * 1024 * 1024))
    if not isinstance(published_inventory, dict) or json.dumps(published_inventory, sort_keys=True, separators=(",", ":")) != json.dumps(inventory, sort_keys=True, separators=(",", ":")):
        raise BuildError("published inventory manifest disagrees with expected inventory")
    if type(inventory.get("schema_version")) is not int or inventory["schema_version"] != expected_version or inventory.get("signing_status") != "unsigned":
        raise BuildError("unsupported build inventory")
    if expected_version == 2 and (type(inventory["cargo_graph_version"]) is not int or inventory["cargo_graph_version"] != 2):
        raise BuildError("version-two build requires graph version two")
    if inventory["state"] != "build-produced" or inventory["provenance_status"] != "not-attested":
        raise BuildError("unsupported build state or attestation claim")
    source = inventory["source"]
    if not isinstance(source, dict) or set(source) != {"repository", "commit"} or not isinstance(source["repository"], str):
        raise BuildError("malformed source identity")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", source["repository"]) or any(
            not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value)
            for value in (source["commit"], inventory["runtime_commit"])):
        raise BuildError("invalid source or runtime identity")
    for key in ("run_id", "run_attempt"):
        if inventory[key] is not None and (not isinstance(inventory[key], str) or not re.fullmatch(r"[1-9][0-9]*", inventory[key])):
            raise BuildError("invalid run identity")
    if (inventory["run_id"] is None) != (inventory["run_attempt"] is None):
        raise BuildError("incomplete hosted run identity")
    for key in ("input_sha256", "source_input_sha256", "tool_sha256"):
        values = inventory[key]
        if not isinstance(values, dict) or not values or any(
                not isinstance(k, str) or not isinstance(v, str) or not re.fullmatch(r"[0-9a-f]{64}", v)
                for k, v in values.items()):
            raise BuildError("invalid inventory input digest")
    if set(inventory["input_sha256"]) != {"armorer.toml", "armorer.lock", "Cargo.lock"}:
        raise BuildError("missing required input digest")
    if inventory["tool_pin_authority"] != "immutable-trusted-workflow-catalog" or inventory["graph_scope"] != "compiled-cargo-target-and-host-build-dependencies":
        raise BuildError("unsupported tool authority or graph scope")
    if inventory["artifact_kind"] not in ("source-package", "executable") or not isinstance(inventory["coverage_gaps"], list) or not inventory["coverage_gaps"] or not all(
            isinstance(gap, str) for gap in inventory["coverage_gaps"]):
        raise BuildError("missing or invalid coverage declaration")
    if expected_selection is not None and inventory.get("selection") != expected_selection:
        raise BuildError("wrong build selection")
    selection = inventory["selection"]
    keys = {"id", "profile", "package", "binary", "targets", "target", "feature_set", "default_features",
            "features", "runner", "artifact_id", "toolchain"}
    if not isinstance(selection, dict) or set(selection) != keys:
        raise BuildError("invalid inventory selection fields")
    for key in ("id", "package", "feature_set"):
        if not isinstance(selection[key], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}", selection[key]):
            raise BuildError("invalid inventory selection identifier")
    native_runners = {"x86_64-unknown-linux-gnu": "ubuntu-24.04", "aarch64-unknown-linux-gnu": "ubuntu-24.04-arm", "aarch64-apple-darwin": "macos-15"}
    if not isinstance(selection["target"], str) or selection["target"] not in native_runners or selection["runner"] != native_runners[selection["target"]]:
        raise BuildError("invalid inventory target or runner")
    if not isinstance(selection["targets"], list) or not selection["targets"] or not all(isinstance(t, str) and t in native_runners for t in selection["targets"]) or selection["target"] not in selection["targets"] or len(set(selection["targets"])) != len(selection["targets"]):
        raise BuildError("invalid inventory configured targets")
    if type(selection["default_features"]) is not bool or not isinstance(selection["features"], list) or not all(isinstance(f, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_+.-]{0,99}", f) for f in selection["features"]) or len(set(selection["features"])) != len(selection["features"]):
        raise BuildError("invalid inventory features")
    if selection["profile"] not in ("library", "cli", "service") or not isinstance(selection["toolchain"], str) or not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", selection["toolchain"]):
        raise BuildError("invalid inventory profile or toolchain")
    if (selection["profile"] == "library" and selection["binary"] is not None) or (selection["profile"] != "library" and (not isinstance(selection["binary"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}", selection["binary"]))):
        raise BuildError("invalid inventory binary")
    if selection["artifact_id"] != f'{selection["id"]}--{selection["target"]}--{selection["feature_set"]}':
        raise BuildError("invalid inventory artifact identity")
    expected_kind = "source-package" if selection["profile"] == "library" else "executable"
    if inventory["artifact_kind"] != expected_kind:
        raise BuildError("artifact kind disagrees with selected profile")
    if expected_context is not None and any(inventory.get(key) != value for key, value in expected_context.items()):
        raise BuildError("wrong build source, runtime or run identity")
    files = inventory.get("files")
    if not isinstance(files, list) or not files:
        raise BuildError("missing build file inventory")
    names = []
    expected_names = {"artifact": selection["artifact_id"] + (".crate" if selection["profile"] == "library" else ".bin"),
                      "sbom": selection["artifact_id"] + ".cdx.json", "cargo-graph": selection["artifact_id"] + ".cargo-graph.json"}
    for record in files:
        if not isinstance(record, dict):
            raise BuildError("invalid inventory file record")
        name = record.get("name")
        if not isinstance(record, dict) or set(record) != {"name", "role", "size", "sha256"} or not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}", name):
            raise BuildError("unsafe inventory filename")
        if record["role"] not in ("artifact", "sbom", "cargo-graph") or type(record["size"]) is not int or record["size"] < 0:
            raise BuildError("invalid inventory file record")
        if name != expected_names[record["role"]]:
            raise BuildError("asset filename disagrees with selected build identity")
        names.append(name)
        if _file_record(directory / name, record.get("role")) != record:
            raise BuildError("build inventory bytes changed")
    if len(set(names)) != len(names):
        raise BuildError("duplicate inventory asset")
    actual = {p.name for p in directory.iterdir()}
    if actual != set(names) | {"inventory.json"}:
        raise BuildError("missing or unexpected build asset")
    if any(sum(r.get("role") == role for r in files) != 1 for role in ("sbom", "artifact", "cargo-graph")):
        raise BuildError("missing or ambiguous artifact/SBOM pair")


def verify_inventory(directory: Path, inventory: dict, expected_selection: dict | None = None,
                     expected_context: dict | None = None) -> None:
    """Check the unchanged explicit version-one inventory; never accept a successor by inference."""
    _verify_inventory(directory, inventory, expected_selection, expected_context, expected_version=1)


def verify_inventory_v2(directory: Path, inventory: dict, expected_selection: dict, expected_context: dict,
                        expected_inputs: dict, expected_root_name: str, expected_package_version: str) -> None:
    """Check explicit v2 inventory, all retained graph identities/edges and its exact paired SBOM."""
    from .graph import validate_graph_v2
    _verify_inventory(directory, inventory, expected_selection, {**expected_context, "input_sha256": expected_inputs}, expected_version=2)
    key = expected_selection["artifact_id"]
    graph = parse_json(_regular_bytes(directory / (key + ".cargo-graph.json")))
    validate_graph_v2(graph, _regular_bytes(directory / (key + ".cdx.json")), expected_selection,
                      expected_context, expected_inputs, expected_root_name, expected_package_version)


def _tracked_inputs(root: Path, environment: dict) -> dict[str, str]:
    """Hash every tracked regular source file, rejecting unsafe relative paths."""
    paths = _run(["/usr/bin/git", "ls-files", "-z"], root, environment).split(b"\0")
    result = {}
    for raw in paths:
        if raw:
            path = Path(os.fsdecode(raw))
            if path.is_absolute() or ".." in path.parts:
                raise BuildError("unsafe tracked source path")
            result[path.as_posix()] = sha256(_regular_bytes(root / path))
    return result


def require_clean_source(root: Path, environment: dict) -> None:
    """Require committed tracked inputs and no preexisting untracked source."""
    _run(["/usr/bin/git", "diff-index", "--quiet", "HEAD", "--"], root, environment)
    if _run(["/usr/bin/git", "ls-files", "--others", "--exclude-standard", "-z"], root, environment):
        raise BuildError("untracked source inputs require a clean checkout")


def _build(root: Path, armorer: Path, artifact_id: str, output: Path, *, selected_graph_v2: bool) -> dict:
    """Build one rederived selection, validate its SBOM, and inventory bytes."""
    from armorer_runtime.common import load_project, select, member_manifest, cargo_environment, setup_toolchain
    from armorer_runtime.tools import install_tools, platform_target

    setup_toolchain(root)
    project = load_project(root, armorer, os.environ.get("GITHUB_REPOSITORY"))
    selection = select(project, artifact_id)
    if platform_target() != selection["target"]:
        raise BuildError("selected target does not match the native builder platform")
    root = project.root.resolve()
    output = output.absolute()
    output = output.parent.resolve(strict=True) / output.name
    if output.exists() or output.is_symlink() or output.is_relative_to(root) or root.is_relative_to(output):
        raise BuildError("output must be a new directory outside the consuming source")
    manifest = member_manifest(project, selection["package"])
    temporary_parent = Path(tempfile.gettempdir()).resolve()
    if temporary_parent.is_relative_to(root):
        raise BuildError("builder temporary directory must be outside the consuming source")
    with tempfile.TemporaryDirectory(prefix="armorer-build-", dir=temporary_parent) as temporary:
        scratch = Path(temporary)
        tools = install_tools(scratch / "tools", ["cargo-cyclonedx", "cyclonedx"])
        tool_hashes = {name: _file_record(path, "tool")["sha256"] for name, path in sorted(tools.items())}
        target_dir = scratch / "target"
        environment = cargo_environment(selection["toolchain"], scratch / "cargo-home", target_dir)
        runtime_root = Path(__file__).resolve().parent.parent
        runtime_commit = _run(["/usr/bin/git", "rev-parse", "HEAD"], runtime_root, environment).decode().strip()
        if not re.fullmatch(r"[0-9a-f]{40}", runtime_commit):
            raise BuildError("unsupported trusted runtime commit identity")
        runtime_inputs = _tracked_inputs(runtime_root, environment)
        required_runtime = {"armorer_runtime/__init__.py", "armorer_runtime/build.py", "armorer_runtime/common.py", "armorer_runtime/tools.py", "pins/tools.json"}
        if selected_graph_v2:
            required_runtime.update({"armorer_runtime/graph.py", "armorer_runtime/build_v2.py"})
        if not required_runtime <= runtime_inputs.keys():
            raise BuildError("trusted runtime helpers must be committed inputs")
        _run(["/usr/bin/git", "diff-index", "--quiet", "HEAD", "--"], runtime_root, environment)
        # The runtime tool paths were established before caller code executes.
        source_commit = _run(["/usr/bin/git", "rev-parse", "HEAD"], root, environment).decode().strip()
        if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
            raise BuildError("unsupported source commit identity")
        actual_root = _run(["/usr/bin/git", "rev-parse", "--show-toplevel"], root, environment).decode().strip()
        if Path(actual_root).resolve() != root:
            raise BuildError("source checkout does not match project root")
        require_clean_source(root, environment)
        if os.environ.get("GITHUB_SHA") is not None and os.environ["GITHUB_SHA"] != source_commit:
            raise BuildError("source checkout disagrees with the GitHub source context")
        for context_name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
            if context_name in os.environ and not re.fullmatch(r"[1-9][0-9]*", os.environ[context_name]):
                raise BuildError("invalid hosted run identity")
        expected_context = {"source": {"repository": project.config["repository"], "commit": source_commit},
                            "runtime_commit": runtime_commit, "run_id": os.environ.get("GITHUB_RUN_ID"),
                            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT")}
        inputs = _tracked_inputs(root, environment)
        required = ["armorer.toml", "armorer.lock", "Cargo.lock"]
        if not set(required) <= inputs.keys():
            raise BuildError("configuration and locks must be tracked source inputs")
        digests = {name: sha256(_regular_bytes(root / name, 1024 * 1024)) for name in required}
        reviewed_lock = tomllib.loads(_regular_bytes(root / "armorer.lock", 1024 * 1024).decode())
        if reviewed_lock.get("workflows") != {"repository": "brianluby/armorer-workflows", "commit": runtime_commit}:
            raise BuildError("reviewed workflow lock does not match the executing trusted runtime")
        build_output = _run(build_arguments(selection, manifest, target_dir), root, environment)
        evidence = compiler_evidence(build_output, selection, manifest)
        if selection["profile"] == "library":
            _run(["cargo", "package", "--locked", "--manifest-path", str(manifest),
                  "--package", selection["package"], "--target", selection["target"],
                  "--target-dir", str(target_dir)] + feature_arguments(selection), root, environment)
        metadata_command = ["cargo", "metadata", "--locked", "--format-version", "1",
                            "--manifest-path", str(manifest), "--filter-platform", selection["target"]]
        metadata = parse_json(_run(metadata_command + feature_arguments(selection), root, environment))
        metadata = reconcile_metadata(metadata, evidence, selection)
        package = next(p for p in metadata["packages"] if p["id"] == evidence["root"]["package_id"])
        # Mirror the exact argv construction of cargo_metadata 0.18.1 used by
        # the pinned cargo-cyclonedx 0.5.9; a future tool change must be reviewed.
        adapter_args = ["metadata", "--format-version", "1"]
        if selection["features"]:
            adapter_args += ["--features", ",".join(selection["features"])]
        if not selection["default_features"]:
            adapter_args += ["--no-default-features"]
        adapter_args += ["--manifest-path", str(manifest), "--filter-platform", selection["target"]]
        adapter = metadata_adapter(scratch, metadata, adapter_args)
        generator_environment = {**environment, "CARGO": str(adapter)}
        command = [str(tools["cargo-cyclonedx"]), "cyclonedx", "--manifest-path", str(manifest),
                   "--target", selection["target"], "--target-in-filename", "--all",
                   "--format", "json", "--spec-version", "1.5", "--describe", "all-cargo-targets"]
        _run(command + feature_arguments(selection), root, generator_environment)
        if selection["profile"] == "library":
            candidates = [t for t in package["targets"] if LIBRARY_KINDS.intersection(t["kind"])]
        else:
            candidates = [t for t in package["targets"] if t["kind"] == ["bin"] and t["name"] == selection["binary"]]
        if len(candidates) != 1:
            raise BuildError("ambiguous selected Cargo target")
        selected_target = candidates[0]
        sbom_path = manifest.parent / (selected_target["name"] + "_" + "-".join(selected_target["kind"]) +
                                       "_" + selection["target"] + ".cdx.json")
        sbom_bytes = _regular_bytes(sbom_path)
        validate_sbom(sbom_bytes, selected_target["name"], package["version"], set(evidence["features"]), metadata)
        _run([str(tools["cyclonedx"]), "validate", "--input-file", str(sbom_path), "--input-format", "json",
              "--input-version", "v1_5", "--fail-on-errors"], scratch, environment)
        if _tracked_inputs(root, environment) != inputs:
            raise BuildError("build changed tracked source inputs")
        if any(sha256(_regular_bytes(root / name, 1024 * 1024)) != digest for name, digest in digests.items()):
            raise BuildError("build changed configuration or dependency locks")
        if _run(["/usr/bin/git", "rev-parse", "HEAD"], root, environment).decode().strip() != source_commit:
            raise BuildError("build changed source checkout identity")
        if _tracked_inputs(runtime_root, environment) != runtime_inputs or any(
                _file_record(path, "tool")["sha256"] != tool_hashes[name] for name, path in tools.items()):
            raise BuildError("build changed trusted runtime or tool bytes")
        if _run(["/usr/bin/git", "rev-parse", "HEAD"], runtime_root, environment).decode().strip() != runtime_commit:
            raise BuildError("build changed trusted runtime checkout identity")
        output.mkdir(parents=True)
        artifact_suffix = ".crate" if selection["profile"] == "library" else ".bin"
        artifact = output / (artifact_id + artifact_suffix)
        source = (target_dir / "package" / (package["name"] + "-" + package["version"] + ".crate")
                  if selection["profile"] == "library" else Path(evidence["root"]["executable"]))
        if not source.resolve().is_relative_to(target_dir.resolve()):
            raise BuildError("selected artifact escaped the build output directory")
        artifact.write_bytes(_regular_bytes(source, 1024 * 1024 * 1024))
        sbom = output / (artifact_id + ".cdx.json")
        sbom.write_bytes(sbom_bytes)
        native_file = output / (artifact_id + ".cargo-graph.json")
        graph_evidence = {"compiled_packages": evidence["features"], "native_linkage": evidence["native_linkage"],
                          "graph_scope": "compiled-cargo-target-and-host-build-dependencies"}
        if selected_graph_v2:
            from .graph import selected_graph_v2 as retained_graph
            graph_evidence = retained_graph(metadata, evidence, selection, selected_target, expected_context, digests)
        native_file.write_text(json.dumps(graph_evidence, sort_keys=True, indent=2) + "\n")
        inventory = {"schema_version": 1, "state": "build-produced", "signing_status": "unsigned",
                     "provenance_status": "not-attested", **expected_context, "selection": selection,
                     "input_sha256": digests, "source_input_sha256": inputs,
                     "tool_sha256": tool_hashes,
                     "tool_pin_authority": "immutable-trusted-workflow-catalog",
                     "graph_scope": graph_evidence["graph_scope"],
                     "coverage_gaps": ["native and system libraries are not fully inventoried",
                                       "Cargo host/target graphs are aggregated by package ID",
                                       "macOS bytes are unsigned and have not been notarized"] if selection["target"].endswith("apple-darwin") else
                                      ["native and system libraries are not fully inventoried", "Cargo host/target graphs are aggregated by package ID"],
                     "artifact_kind": "source-package" if selection["profile"] == "library" else "executable",
                     "files": [_file_record(artifact, "artifact"), _file_record(sbom, "sbom"), _file_record(native_file, "cargo-graph")]}
        if selected_graph_v2:
            inventory["schema_version"] = 2
            inventory["cargo_graph_version"] = 2
        (output / "inventory.json").write_text(json.dumps(inventory, sort_keys=True, indent=2) + "\n")
        if selected_graph_v2:
            verify_inventory_v2(output, inventory, selection, expected_context, digests, selected_target["name"], package["version"])
        else:
            verify_inventory(output, inventory, selection, expected_context)
        return inventory


def build(root: Path, armorer: Path, artifact_id: str, output: Path) -> dict:
    """Run the unchanged v1 unsigned builder with its feature-only graph contract."""
    return _build(root, armorer, artifact_id, output, selected_graph_v2=False)


def build_v2(root: Path, armorer: Path, artifact_id: str, output: Path) -> dict:
    """Run the explicit successor builder retaining source/run-bound selected graph version two."""
    return _build(root, armorer, artifact_id, output, selected_graph_v2=True)


def main() -> None:
    """Run the fixed v1 builder CLI and report static failure messages."""
    from armorer_runtime.common import Failure
    parser = argparse.ArgumentParser(description="Fixed unsigned Rust builder")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--armorer", type=Path, required=True)
    parser.add_argument("--artifact-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        inventory = build(arguments.root, arguments.armorer, arguments.artifact_id, arguments.output)
        print(json.dumps({"artifact_id": inventory["selection"]["artifact_id"], "state": inventory["state"]}, sort_keys=True))
    except (BuildError, Failure, ValueError, OSError, KeyError, TypeError, AttributeError, subprocess.SubprocessError):
        parser.exit(1, "Armorer builder failed closed; review configuration, tool capabilities and build prerequisites.\n")


if __name__ == "__main__":
    main()
