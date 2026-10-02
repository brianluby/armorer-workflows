"""Compile native owned fixtures and qualify actual final payload transforms, without signatures or release authority."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import tomllib

from armorer_runtime import common, final_payload_v1 as final, tools
from build_cases_v3 import main as build_native_v3


def byte_identity(data):
    """Identify actual test-owned bytes, without claiming an approved production distribution."""
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def fixture_distribution(root):
    """Create an actual bounded fixture archive instead of treating a hash string or helper as runtime distribution bytes."""
    note = root / "qualification-runtime.txt"
    note.write_text("Fixture distribution for byte-layout conformance only; not a production runtime.\n")
    archive = root / "qualification-runtime.tar"
    with tarfile.open(archive, "w", format=tarfile.USTAR_FORMAT) as output:
        output.add(note, arcname=note.name, recursive=False)
    return byte_identity(archive.read_bytes())


def main():
    """Compose the unchanged native v3 builder with final payload staging and independent archive-byte comparisons."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--armorer", type=Path, required=True)
    parser.add_argument("--tool-directory", type=Path, required=True)
    parser.add_argument("--receipt-directory", type=Path, required=True)
    args = parser.parse_args()
    args.receipt_directory.mkdir(exist_ok=False, parents=True)
    target = tools.platform_target()
    with tempfile.TemporaryDirectory(prefix="armorer-native-final-payload-") as temporary:
        root = Path(temporary)
        raw = root / "handoffs"
        saved = sys.argv
        try:
            sys.argv = ["native-v3", "--armorer", str(args.armorer), "--tool-directory", str(args.tool_directory),
                        "--receipt-directory", str(raw)]
            build_native_v3()
        finally:
            sys.argv = saved
        receipt = json.loads((raw / "receipt.json").read_bytes())
        config = tomllib.loads((raw / "armorer.toml").read_text())
        selections = common.selections(config)
        installed = tools.install_tools(args.tool_directory / "final-native-tools", ["cargo-cyclonedx", "cyclonedx"])
        tool_hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in installed.items()}
        runtime = fixture_distribution(root)
        build = {"repository": "brianluby/armorer-workflows", "path": ".github/workflows/rust-build-v3.yml", "commit": receipt["runtime_commit"]}
        package = {"repository": "brianluby/armorer-workflows", "path": ".github/workflows/release-cli.yml", "commit": receipt["runtime_commit"]}
        # The unchanged fixture builder deliberately uses fixture-only source/run
        # context. This qualification never presents it as a hosted release run.
        inputs = {"source": {"repository": "fixture/build", "commit": receipt["source_commit"], "git_ref": "refs/heads/fixture"},
                  "config_sha256": receipt["input_sha256"]["armorer.toml"], "lock_sha256": receipt["input_sha256"]["armorer.lock"],
                  "cargo_lock_sha256": receipt["input_sha256"]["Cargo.lock"], "runtime": runtime, "runtime_version": "0.1.0",
                  "run": {"id": 17, "attempt": 2, "workflow": package}}
        context = {"source": {"repository": "fixture/build", "commit": receipt["source_commit"]},
                   "runtime_commit": receipt["runtime_commit"], "run_id": "17", "run_attempt": "2"}
        catalog_bytes = json.dumps({"scope": "synthetic byte-layout qualification", "tools": tool_hashes}, sort_keys=True).encode()
        items, handoffs, unsupported = [], {}, []
        for case in selections:
            key = case["artifact_id"]
            root_name = "custom_zero" if case["id"] == "zero" else "fixture-app"
            item = final.PayloadExpectation(case, context, receipt["input_sha256"], root_name, "0.1.0", tool_hashes)
            if target == "aarch64-apple-darwin" and case["profile"] != "library":
                plan = final.ReleaseExpectation(inputs, byte_identity(catalog_bytes), build, package, (item,), (runtime,))
                try:
                    with final.prepare_final_payloads({key: raw / case["id"]}, plan):
                        raise AssertionError("unsigned Apple final bytes accepted")
                except common.Failure as error:
                    assert str(error) == "protected Apple finalization required before final payload assembly"
                unsupported.append({"id": case["id"], "profile": case["profile"], "status": "blocked-before-staging",
                                    "reason": "protected Apple finalization remains required"})
                continue
            items.append(item)
            handoffs[key] = raw / case["id"]
        plan = final.ReleaseExpectation(inputs, byte_identity(catalog_bytes), build, package, tuple(items), (runtime,))
        results = []
        with final.prepare_final_payloads(handoffs, plan) as assembly:
            for item in items:
                case = item.selection
                key = case["artifact_id"]
                suffix = ".crate" if case["profile"] == "library" else ".tar.gz"
                path = assembly.subject_path(key + suffix)
                source_suffix = ".crate" if case["profile"] == "library" else ".bin"
                original = (handoffs[key] / (key + source_suffix)).read_bytes()
                if case["profile"] == "library":
                    assert path.read_bytes() == original
                else:
                    with tarfile.open(path, "r:gz") as archive:
                        member, = archive.getmembers()
                        assert member.name == case["binary"] and member.mode == 0o755 and member.uid == member.gid == member.mtime == 0
                        assert member.type == tarfile.REGTYPE and archive.extractfile(member).read() == original
                assert path.stat().st_mode & 0o777 == 0o400
                assert assembly.packaging(key)["input"] == byte_identity(original)
                assert assembly.packaging(key)["output"] == byte_identity(path.read_bytes())
                destination = args.receipt_directory / key
                destination.mkdir()
                retained = {}
                for name in (key + suffix, key + ".cdx.json", key + ".cargo-graph.json"):
                    data = assembly.subject_path(name).read_bytes()
                    (destination / name).write_bytes(data)
                    retained[name] = byte_identity(data)
                results.append({"id": case["id"], "profile": case["profile"], "target": target,
                                "packaging": assembly.packaging(key), "final_name": key + suffix,
                                "retained_assets": retained})
        report = {"native_target": target, "runtime_commit": receipt["runtime_commit"], "source_commit": receipt["source_commit"],
                  "assembler_source": byte_identity(Path(final.__file__).read_bytes()),
                  "qualification_source": byte_identity(Path(__file__).read_bytes()),
                  "native_handoff_receipt": receipt,
                  "scope": "actual native Cargo bytes with synthetic fixture-only source/run/catalog intent",
                  "cases": results, "unsupported": unsupported, "archive_bytes_independently_compared": True,
                  "live_oidc_requested": False, "cryptographic_release_authenticated": False,
                  "protected_apple_finalization_operational": False, "production_catalog_accepted": False,
                  "signing_authorized": False, "publication_authorized": False, "full_release_factory_operational": False}
        (args.receipt_directory / "receipt.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"native_target": target, "final_payload_cases": [r["id"] for r in results],
                          "blocked_apple_cases": [r["id"] for r in unsupported], "state": "native-bytes-qualified-not-attested"}))


if __name__ == "__main__":
    main()
