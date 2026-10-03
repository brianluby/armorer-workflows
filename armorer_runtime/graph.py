"""Explicit selected Cargo graph v2; unsigned consistency data until authenticated.

The old feature-only graph is never upgraded by inference. This module retains
already reconciled compiler/metadata identities and checks them against fixed
context. It never runs Cargo, extracts artifacts, or performs attestation.
"""
from __future__ import annotations

import copy
import re
import unicodedata

from .build import BuildError, reconcile_metadata, validate_sbom

SCOPE = "compiled-cargo-target-and-host-build-dependencies"
GAPS = ["native-and-system-libraries-not-fully-inventoried", "cargo-host-target-aggregated-by-package-id"]
MAX_PACKAGES = 4096
MAX_EDGES = 65536


def version(value, stable=False):
    """Check canonical bounded Cargo SemVer, including legitimate prerelease dependency versions."""
    if not isinstance(value, str) or len(value) > 100:
        return False
    match = re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*))?(?:\+([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*))?", value)
    if match is None or any(int(match.group(i)) > (1 << 64) - 1 for i in (1, 2, 3)):
        return False
    prerelease, build = match.group(4), match.group(5)
    if stable and (prerelease is not None or build is not None):
        return False
    return prerelease is None or all(not (part.isdigit() and len(part) > 1 and part.startswith("0")) for part in prerelease.split("."))


def normalized_selection(selection, package_version):
    """Retain the validated case plus its source-resolved version, without workflow-only keys."""
    if not version(package_version, stable=True):
        raise BuildError("version-two root package requires a canonical stable version")
    return {"deliverable_id": selection["id"], "profile": selection["profile"], "package": selection["package"],
            "package_version": package_version, "binary": selection["binary"], "target": selection["target"],
            "feature_set": selection["feature_set"], "default_features": selection["default_features"],
            "features": selection["features"], "toolchain": selection["toolchain"]}


def selected_graph_v2(metadata, evidence, selection, selected_target, context, inputs):
    """Retain actual selected package identities, features and all normal/build dependency contexts."""
    metadata = reconcile_metadata(metadata, evidence, selection)
    root_id = metadata["resolve"]["root"]
    root = next(p for p in metadata["packages"] if p["id"] == root_id)
    nodes = []
    for node in metadata["resolve"]["nodes"]:
        dependencies = []
        for edge in node["deps"]:
            contexts = []
            for kind in edge["dep_kinds"]:
                if kind["kind"] not in (None, "build"):
                    raise BuildError("unsupported retained dependency kind")
                contexts.append({"kind": "normal" if kind["kind"] is None else "build", "target": kind["target"]})
            dependencies.append({"package": edge["pkg"], "name": edge["name"],
                                 "contexts": sorted(contexts, key=lambda c: (c["kind"], c["target"] or ""))})
        nodes.append({"id": node["id"], "features": node["features"],
                      "dependencies": sorted(dependencies, key=lambda d: (d["package"], d["name"]))})
    record = {"schema_version": 2, "source": context["source"], "runtime_commit": context["runtime_commit"],
              "run_id": None if context["run_id"] is None else int(context["run_id"]),
              "run_attempt": None if context["run_attempt"] is None else int(context["run_attempt"]),
              "input_sha256": inputs, "selection": normalized_selection(selection, root["version"]),
              "root_component_name": selected_target["name"], "root": root_id,
              "packages": [{"id": p["id"], "name": p["name"], "version": p["version"]} for p in metadata["packages"]],
              "nodes": nodes, "native_linkage": evidence.get("native_linkage", []),
              "graph_scope": SCOPE, "coverage_gaps": GAPS.copy()}
    return copy.deepcopy(record)


def fields(value, expected):
    """Reject missing or additional fields before using a retained graph object."""
    if not isinstance(value, dict) or set(value) != set(expected):
        raise BuildError("invalid retained graph fields")


def bounded_text(value, limit):
    """Treat metadata strings as bounded data, never paths, commands or credential input."""
    if not isinstance(value, str):
        return False
    try:
        size = len(value.encode())
    except UnicodeError:
        return False
    return 0 < size <= limit and not any(unicodedata.category(c) == "Cc" for c in value)


def runtime_packages(root, nodes):
    """Match the pinned generator's normal-path classification; retain every build-only package."""
    by_id = {node["id"]: node for node in nodes}
    required = set()
    pending = [root]
    while pending:
        current = pending.pop()
        if current not in required:
            required.add(current)
            pending.extend(edge["package"] for edge in by_id[current]["dependencies"]
                           if any(context["kind"] == "normal" for context in edge["contexts"]))
    return required


def validate_graph_v2(record, sbom_bytes, expected_selection, expected_context, expected_inputs, expected_root_name, expected_package_version):
    """Check the full retained graph/SBOM against separate known context; establish no authenticity."""
    fields(record, {"schema_version", "source", "runtime_commit", "run_id", "run_attempt", "input_sha256",
                    "selection", "root_component_name", "root", "packages", "nodes", "native_linkage", "graph_scope", "coverage_gaps"})
    fields(record["source"], {"repository", "commit"})
    fields(record["input_sha256"], {"armorer.toml", "armorer.lock", "Cargo.lock"})
    fields(record["selection"], {"deliverable_id", "profile", "package", "package_version", "binary", "target",
                                 "feature_set", "default_features", "features", "toolchain"})
    package_version = record["selection"]["package_version"]
    if package_version != expected_package_version or not version(expected_package_version, stable=True):
        raise BuildError("retained graph source-resolved package version mismatch")
    if type(record["schema_version"]) is not int or record["schema_version"] != 2 or record["graph_scope"] != SCOPE or record["coverage_gaps"] != GAPS:
        raise BuildError("unsupported retained graph version or coverage")
    if record["source"] != expected_context["source"] or record["runtime_commit"] != expected_context["runtime_commit"] or record["input_sha256"] != expected_inputs:
        raise BuildError("retained graph input context mismatch")
    for key in ("run_id", "run_attempt"):
        observed = record[key]
        required = None if expected_context[key] is None else int(expected_context[key])
        if observed != required or (observed is not None and (type(observed) is not int or not 0 < observed <= (1 << 64) - 1)):
            raise BuildError("retained graph run context mismatch")
    if type(record["selection"]["default_features"]) is not bool or record["selection"] != normalized_selection(expected_selection, expected_package_version) or record["root_component_name"] != expected_root_name:
        raise BuildError("retained graph selection mismatch")
    packages = record["packages"]
    nodes = record["nodes"]
    if not isinstance(packages, list) or not 0 < len(packages) <= MAX_PACKAGES or not isinstance(nodes, list) or len(nodes) != len(packages):
        raise BuildError("retained graph package budget exceeded")
    by_id = {}
    for package in packages:
        fields(package, {"id", "name", "version"})
        if not bounded_text(package["id"], 4096) or package["id"] in by_id or not bounded_text(package["name"], 100) or not version(package["version"]):
            raise BuildError("invalid or duplicate retained package")
        by_id[package["id"]] = package
    if not bounded_text(record["root"], 4096) or not bounded_text(expected_root_name, 1024):
        raise BuildError("invalid retained graph root")
    root = by_id.get(record["root"])
    if root is None or root["name"] != expected_selection["package"] or root["version"] != expected_package_version:
        raise BuildError("retained graph root identity mismatch")
    expected_nodes = {}
    edge_count = 0
    for node in nodes:
        fields(node, {"id", "features", "dependencies"})
        if not isinstance(node["id"], str) or node["id"] not in by_id or node["id"] in expected_nodes or not isinstance(node["features"], list) or len(node["features"]) > 1024 or not all(bounded_text(f, 100) for f in node["features"]) or len(set(node["features"])) != len(node["features"]) or not isinstance(node["dependencies"], list):
            raise BuildError("invalid or duplicate retained node")
        edges = set()
        identities = set()
        for edge in node["dependencies"]:
            edge_count += 1
            fields(edge, {"package", "name", "contexts"})
            if edge_count > MAX_EDGES or not isinstance(edge["package"], str) or edge["package"] not in by_id or edge["package"] == node["id"] or not bounded_text(edge["name"], 256) or (edge["package"], edge["name"]) in identities:
                raise BuildError("invalid retained edge")
            identities.add((edge["package"], edge["name"]))
            edges.add(edge["package"])
            contexts = edge["contexts"]
            if not isinstance(contexts, list) or not 0 < len(contexts) <= 128:
                raise BuildError("invalid retained edge contexts")
            seen = set()
            for context in contexts:
                fields(context, {"kind", "target"})
                if context["kind"] not in ("normal", "build") or (context["target"] is not None and not bounded_text(context["target"], 4096)) or (context["kind"], context["target"]) in seen:
                    raise BuildError("invalid retained edge context")
                seen.add((context["kind"], context["target"]))
        expected_nodes[node["id"]] = {"id": node["id"], "dependencies": sorted(edges)}
    if not set(expected_selection["features"]) <= set(next(n for n in nodes if n["id"] == record["root"])["features"]):
        raise BuildError("retained graph requested feature missing")
    reachable = set()
    pending = [record["root"]]
    while pending:
        current = pending.pop()
        if current not in reachable:
            reachable.add(current)
            pending.extend(expected_nodes[current]["dependencies"])
    if reachable != set(by_id):
        raise BuildError("unreachable retained package")
    if not isinstance(record["native_linkage"], list) or len(record["native_linkage"]) > MAX_PACKAGES:
        raise BuildError("retained native inventory exceeds budget")
    for native in record["native_linkage"]:
        fields(native, {"package_id", "linked_libraries"})
        libraries = native["linked_libraries"]
        if not isinstance(native["package_id"], str) or native["package_id"] not in by_id or not isinstance(libraries, list) or not 0 < len(libraries) <= 1024 or not all(bounded_text(lib, 4096) for lib in libraries):
            raise BuildError("invalid retained native linkage")
    metadata = {"packages": [{**package, "targets": [{"name": expected_root_name}]} for package in packages],
                "resolve": {"root": record["root"], "nodes": list(expected_nodes.values())}}
    bom = validate_sbom(sbom_bytes, expected_root_name, expected_package_version, set(by_id), metadata)
    if type(bom.get("version")) is not int or not 0 < bom["version"] <= (1 << 64) - 1:
        raise BuildError("invalid retained Cargo SBOM version")
    root_component = bom["metadata"]["component"]
    expected_type = "library" if expected_selection["profile"] == "library" else "application"
    if root_component.get("type") != expected_type:
        raise BuildError("invalid retained Cargo root component type")
    required_packages = runtime_packages(record["root"], nodes)
    for component in [root_component, *bom.get("components", [])]:
        if "components" in component and component["components"] != []:
            raise BuildError("nested Cargo SBOM components are unsupported")
        expected_scope = "required" if component["bom-ref"] in required_packages else "excluded"
        if component.get("scope", "required") != expected_scope:
            raise BuildError("Cargo SBOM scope disagrees with retained dependency paths")
    if any(component.get("type") != "library" for component in bom.get("components", [])):
        raise BuildError("invalid retained Cargo dependency component type")
    if any(set(node) - {"ref", "dependsOn"} for node in bom["dependencies"]):
        raise BuildError("ambiguous retained Cargo dependency fields")
