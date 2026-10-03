"""Collect one complete build/policy artifact set without granting credential authority."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
from pathlib import Path
import struct
import tempfile
import time
from types import MappingProxyType
import zipfile
import zlib

from . import build_v3, policy_v1 as policy, transport_v1 as transport
from .build import parse_json
from .common import Failure, require
from .final_payload_v1 import PayloadExpectation
from .policy_transport_v1 import ExpectedPolicyRun, POLICY_WORKFLOW, _names as policy_names, _unpack as unpack_policy

# Two fixed artifacts per selection; the writer observer and REST reader both
# require a single complete page. Larger sets fail explicitly, never truncate.
MAX_SELECTIONS = 32
MAX_TOTAL = 4 * 1024 * 1024 * 1024


@dataclass(frozen=True)
class CombinedRun:
    """Independent same-run controller intent, with an explicit nonproduction PR qualification mode."""
    build: transport.ExpectedRun
    policy: ExpectedPolicyRun
    qualification_only: bool = False

    def validate(self):
        """Cross-bind every shared identity before credentials, provider reads or payload decoding."""
        require(type(self.build) is transport.ExpectedRun and type(self.policy) is ExpectedPolicyRun and
                type(self.qualification_only) is bool, "combined run intent type invalid")
        self.build.validate()
        self.policy.validate()
        for name in ("repository", "repository_id", "head_commit", "source_commit", "head_branch", "event",
                     "caller_path", "caller_workflow_id", "run_id", "run_attempt", "runtime_commit", "max_age_seconds"):
            require(getattr(self.build, name) == getattr(self.policy, name), "combined run contexts differ")
        require(self.qualification_only or self.build.event in ("push", "workflow_dispatch"),
                "combined PR collection requires explicit qualification")


def _run(value, expected, now):
    """Require an active exact attempt with both unique reusable workflow pins and exact PR head metadata."""
    start = transport._run(value, expected.build, now)
    require(value.get("status") == "in_progress" and value.get("conclusion") is None,
            "combined run must be active")
    wanted = "brianluby/armorer-workflows/" + POLICY_WORKFLOW + "@" + expected.policy.runtime_commit
    prefix = "brianluby/armorer-workflows/" + POLICY_WORKFLOW + "@"
    references = value["referenced_workflows"]
    matches = [row for row in references if type(row) is dict and type(row.get("path")) is str and
               row["path"].startswith(prefix)]
    require(len(matches) == 1 and matches[0].get("path") == wanted and
            matches[0].get("sha") == expected.policy.runtime_commit, "combined policy workflow pin mismatch")
    if expected.build.event == "pull_request":
        rows = value.get("pull_requests")
        require(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict and
                type(rows[0].get("number")) is int and rows[0]["number"] == int(expected.policy.ref.split("/")[2]),
                "combined PR identity mismatch")
        head = rows[0].get("head")
        require(type(head) is dict and head.get("sha") == expected.build.head_commit and
                head.get("ref") == expected.build.head_branch and type(head.get("repo")) is dict and
                type(head["repo"].get("id")) is int and head["repo"]["id"] == expected.build.repository_id,
                "combined PR head mismatch")
    return start


def _copy_inputs(items, source_inputs, runtime_inputs, catalog, project_policy, expected):
    """Freeze independent data and cross-bind build input hashes to the independently expected policy source set."""
    require(type(items) is tuple and 0 < len(items) <= MAX_SELECTIONS and
            all(type(item) is PayloadExpectation for item in items), "combined selection count or type unsupported")
    require(all(type(value) is dict for value in (source_inputs, runtime_inputs, catalog, project_policy)),
            "combined independent expectations must be records")
    raw = policy.canonical({"items": [asdict(item) for item in items], "source": source_inputs,
                            "runtime": runtime_inputs, "catalog": catalog, "policy": project_policy})
    require(len(raw) <= 1024 * 1024, "combined independent expectations exceed bound")
    copied = parse_json(raw)
    frozen_items = tuple(PayloadExpectation(**item) for item in copied["items"])
    keys = set()
    context = {key: value for key, value in expected.policy.context().items() if key not in ("event", "ref")}
    for item in frozen_items:
        selection = item.selection
        build_v3._names(selection)
        policy_names(selection)
        key = selection["artifact_id"]
        require(key not in keys and item.context == context, "combined duplicate or foreign build expectation")
        require(type(item.input_sha256) is dict and set(item.input_sha256) == {"armorer.toml", "armorer.lock", "Cargo.lock"},
                "combined build input set mismatch")
        for name, digest in item.input_sha256.items():
            require(type(copied["source"].get(name)) is dict and copied["source"][name].get("sha256") == digest,
                    "combined build and policy source inputs differ")
        keys.add(key)
    return frozen_items, copied["source"], copied["runtime"], copied["catalog"], copied["policy"]


def _expansion_size(path, kind, selection):
    """Bound the central directory and total advertised expansion before writing any extracted bytes."""
    size = path.stat().st_size
    require(size >= 22, "combined ZIP too short")
    with path.open("rb") as stream:
        stream.seek(-22, 2)
        magic, disk, central_disk, disk_count, count, central_size, offset, comment = struct.unpack(
            "<4s4H2LH", stream.read(22))
    expected_count = 5 if kind == "build" else 7
    require(magic == b"PK\x05\x06" and disk == central_disk == comment == 0 and
            disk_count == count == expected_count and 0 < central_size <= 65536 and
            offset + central_size == size - 22, "combined ZIP directory invalid")
    names = build_v3._names(selection) if kind == "build" else policy_names(selection)
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        require(len(entries) == expected_count and {entry.filename for entry in entries} == set(names) and
                all(0 < entry.file_size <= names[entry.filename] for entry in entries),
                "combined ZIP expansion invalid")
        return sum(entry.file_size for entry in entries)


def _semantics(build_directories, policy_directories, items, expected, inputs, now):
    """Check both report semantics and unchanged downloaded leaves, without executing build artifacts."""
    source_inputs, runtime_inputs, catalog, project_policy = inputs
    result = {}
    oldest = now
    for item in items:
        key = item.selection["artifact_id"]
        handoff = build_v3.verify_handoff_v3(build_directories[key], item.selection, item.context, item.input_sha256,
                                            item.root_component_name, item.package_version, item.tool_sha256,
                                            max_age_seconds=expected.build.max_age_seconds, now=now)
        envelope = policy.verify(policy_directories[key], expected.policy.context(), item.selection,
                                 source_inputs, runtime_inputs, catalog, project_policy, now=now)
        inventory = parse_json(policy.regular(build_directories[key] / "inventory.json", build_v3.MAX_METADATA))
        require(inventory["source_input_sha256"] == {name: identity["sha256"] for name, identity in source_inputs.items()},
                "combined build source tree differs from independent policy source")
        oldest = min(oldest, handoff["observed_build"]["started_at"], envelope["observed"]["started_at"])
        result[key] = {"build": handoff["observed_build"], "policy": envelope["observed"], "checks": envelope["checks"]}
    require(now - oldest <= expected.build.max_age_seconds, "combined handoff or policy snapshot expired")
    today = datetime.fromtimestamp(now, timezone.utc).date()
    require(all(today <= date.fromisoformat(exception["expires"])
                for exception in project_policy["advisories"]["exceptions"]), "combined policy exception expired")
    return result


@contextmanager
def collect_producer_handoffs(api, expected, items, source_inputs, runtime_inputs, catalog, project_policy):
    """Yield the entire inert build/policy set after native transport, exact-byte and final semantic rereads.

    The paths are live only within this context. This result is storage and
    unsigned report evidence; writer/OIDC identity and independent accepted
    catalog/root/protection gates remain separate requirements.
    """
    require(type(api) is transport.QualifiedGhApi and type(expected) is CombinedRun,
            "combined transport adapter or intent invalid")
    expected.validate()
    items, source_inputs, runtime_inputs, catalog, project_policy = _copy_inputs(
        items, source_inputs, runtime_inputs, catalog, project_policy, expected)
    inputs = (source_inputs, runtime_inputs, catalog, project_policy)
    by_name = {}
    for item in items:
        key = item.selection["artifact_id"]
        for kind, name in (("build", f"{key}-handoff-v3-run-{expected.build.run_id}-attempt-{expected.build.run_attempt}"),
                           ("policy", f"policy-v1-{key}-{expected.build.run_id}-{expected.build.run_attempt}")):
            require(len(name) <= 255 and name not in by_name, "combined artifact name invalid")
            by_name[name] = (kind, item)
    route = f"repos/{expected.build.repository}/actions/runs/{expected.build.run_id}"
    now = int(time.time())
    start = _run(api.json(route), expected, now)
    require(_run(api.json(route + f"/attempts/{expected.build.run_attempt}"), expected, now) == start,
            "combined latest and explicit attempt differ")
    records = transport._listing(api.json(route + "/artifacts?per_page=100"), expected.build, set(by_name), start, now)
    require(sum(record["size_in_bytes"] for record in records.values()) <= MAX_TOTAL,
            "combined archive staging budget exceeded")
    with tempfile.TemporaryDirectory(prefix="armorer-combined-handoff-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        builds, policies, observed = {}, {}, {}
        total = 0
        for name, (kind, item) in sorted(by_name.items()):
            record = records[name]
            require(transport._artifact(api.json(f"repos/{expected.build.repository}/actions/artifacts/{record['id']}"),
                                        expected.build, name, start, int(time.time())) == record,
                    "combined artifact detail changed")
            archive = root / (str(record["id"]) + ".zip")
            require(total + record["size_in_bytes"] <= MAX_TOTAL, "combined archive staging budget exceeded")
            api.archive(expected.build.repository, record["id"], archive)
            identity = transport._identity(archive, transport.MAX_ZIP)
            require(identity == {"sha256": record["digest"][7:], "size": record["size_in_bytes"]},
                    "combined provider archive bytes mismatch")
            folder = root / (kind + "-" + item.selection["artifact_id"])
            try:
                expansion = _expansion_size(archive, kind, item.selection)
                require(total + identity["size"] + expansion <= MAX_TOTAL,
                        "combined archive and leaf staging budget exceeded")
                unpack = transport._unpack_provider_zip if kind == "build" else unpack_policy
                leaves = unpack(archive, folder, item.selection)
            except (zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError, NotImplementedError,
                    OSError, EOFError, zlib.error) as error:
                raise Failure("combined provider ZIP failed closed") from error
            total += identity["size"] + sum(leaf["size"] for leaf in leaves.values())
            require(total <= MAX_TOTAL, "combined archive and leaf staging budget exceeded")
            (builds if kind == "build" else policies)[item.selection["artifact_id"]] = folder
            observed[name] = {"kind": kind, "selection": item.selection["artifact_id"], "provider": record,
                              "archive": identity, "leaves": leaves}
        semantic = _semantics(builds, policies, items, expected, inputs, int(time.time()))
        for name, record in records.items():
            times = semantic[by_name[name][1].selection["artifact_id"]][by_name[name][0]]
            require(start <= times["started_at"] <= times["finished_at"] <= transport._timestamp(record["created_at"]),
                    "combined observation outside exact attempt upload window")
        final_now = int(time.time())
        require(final_now >= now and time.monotonic() < api._deadline, "combined transport expired or clock reversed")
        require(_run(api.json(route), expected, final_now) == start and
                _run(api.json(route + f"/attempts/{expected.build.run_attempt}"), expected, final_now) == start and
                transport._listing(api.json(route + "/artifacts?per_page=100"), expected.build,
                                   set(by_name), start, final_now) == records, "combined provider state changed")
        for name, record in records.items():
            require(transport._artifact(api.json(f"repos/{expected.build.repository}/actions/artifacts/{record['id']}"),
                                        expected.build, name, start, int(time.time())) == record,
                    "combined final artifact detail changed")
            kind, item = by_name[name]
            folder = (builds if kind == "build" else policies)[item.selection["artifact_id"]]
            for leaf, identity in observed[name]["leaves"].items():
                require(transport._identity(folder / leaf, identity["size"]) == identity, "combined local leaf changed")
        end_now = int(time.time())
        require(end_now >= final_now and time.monotonic() < api._deadline, "combined final freshness expired")
        require(_semantics(builds, policies, items, expected, inputs, end_now) == semantic,
                "combined report semantics changed")
        receipt = {"schema_version": 1, "state": "combined-build-policy-transport-observed",
                   "qualification_only": expected.qualification_only, "authentication_mode":
                   "operator-readonly-qualification" if api._operator else "isolated-workflow-token",
                   "repository": expected.build.repository, "repository_id": str(expected.build.repository_id),
                   "head_commit": expected.build.head_commit, "source_commit": expected.build.source_commit,
                   "run_id": str(expected.build.run_id), "run_attempt": str(expected.build.run_attempt),
                   "runtime_commit": expected.build.runtime_commit, "observed_at": end_now,
                   "gh_version": transport.GH_VERSION, "gh_source_commit": transport.GH_SOURCE,
                   "artifacts": observed, "semantics": semantic, "archive_bytes_verified": True,
                   "producer_job_authenticated": False, "artifact_producer_authenticated": False,
                   "production_catalog_accepted": False, "cryptographic_release_authenticated": False,
                   "signing_authorized": False, "publication_authorized": False}
        yield MappingProxyType(builds), MappingProxyType(policies), receipt
