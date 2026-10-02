"""Native explicit-v3 handoff fixtures; synthetic context, no attestation or pilot edits."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from armorer_runtime import build, build_v3 as handoff, common, tools
from armorer_runtime.graph import validate_graph_v2
from build_cases import create_fixture
from jsonschema import Draft202012Validator


def extend_fixture(root, target):
    """Add a real host build dependency and service case to the existing feature/target/library fixtures."""
    manifest = root / "Cargo.toml"
    manifest.write_text(manifest.read_text().replace('"platform"]', '"platform", "host"]'))
    host = root / "host/src"; host.mkdir(parents=True)
    (host.parent / "Cargo.toml").write_text('[package]\nname="fixture-host"\nversion="0.2.0-alpha.1"\nedition="2024"\nlicense="MIT"\n')
    (host / "lib.rs").write_text('pub fn value() -> u8 { 3 }\n')
    app = root / "app/Cargo.toml";app.write_text(app.read_text()+'\n[build-dependencies]\nfixture-host={path="../host"}\n')
    (root / "app/build.rs").write_text('fn main() { let _ = fixture_host::value(); println!("cargo:rerun-if-changed=build.rs"); }\n')
    config = root / "armorer.toml"
    configuration = config.read_text().replace(
        "[feature_sets.extra]",
        "[feature_sets.service]\ndefault_features = false\nfeatures = []\n[feature_sets.extra]",
    )
    config.write_text(configuration+f'\n[[deliverables]]\nid="service"\nprofile="service"\npackage="fixture-app"\nbinary="fixture-app"\ntargets=["{target}"]\nfeature_set="service"\n')
    digest = hashlib.sha256(config.read_bytes()).hexdigest()
    lock = root / "armorer.lock";old = lock.read_text();start = old.index('config_sha256 = "')+len('config_sha256 = "');old = old[:start]+digest+old[start+64:];lock.write_text(old)


def main():
    """Build four real native cases and reject schema-valid graph/SBOM mutations without execution."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--armorer", type=Path, required=True)
    parser.add_argument("--tool-directory", type=Path, required=True)
    parser.add_argument("--receipt-directory", type=Path)
    args = parser.parse_args(); target = tools.platform_target()
    installed = tools.install_tools(args.tool_directory, ["cargo-cyclonedx", "cyclonedx"])
    original = tools.install_tools
    def test_install(destination, names):
        """Reuse only the actually catalog-authenticated native fixture tools."""
        assert names == ["cargo-cyclonedx", "cyclonedx"]
        return installed
    tools.install_tools = test_install
    try:
        with tempfile.TemporaryDirectory(prefix="armorer-native-v3-") as temp:
            parent = Path(temp);root = parent / "source";root.mkdir();create_fixture(root, target);extend_fixture(root, target)
            environment = common.cargo_environment("1.95.0", parent / "cargo-home", parent / "target")
            for command in [["/usr/bin/git", "init", "-q"], ["cargo", "generate-lockfile", "--manifest-path", str(root / "Cargo.toml")],
                            ["/usr/bin/git", "add", "."], ["/usr/bin/git", "-c", "user.name=Armorer Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "fixture"]]:
                common.run(command, cwd=root, env=environment)
            source_commit = subprocess.check_output(["/usr/bin/git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
            runtime_commit = subprocess.check_output(["/usr/bin/git", "-C", str(Path(build.__file__).resolve().parent.parent), "rev-parse", "HEAD"], text=True).strip()
            saved = {k: os.environ.pop(k) for k in ("GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT") if k in os.environ}
            # These are explicit fixture-only expected run values, not GitHub evidence.
            os.environ.update(GITHUB_RUN_ID="17", GITHUB_RUN_ATTEMPT="2")
            context = {"source": {"repository": "fixture/build", "commit": source_commit}, "runtime_commit": runtime_commit, "run_id": "17", "run_attempt": "2"}
            inputs = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in ("armorer.toml", "armorer.lock", "Cargo.lock")}
            try:
                cases = []
                project = common.load_project(root, args.armorer, "fixture/build")
                schema = json.loads((Path(build.__file__).resolve().parent.parent / "schemas/build-inventory-v2.json").read_bytes());Draft202012Validator.check_schema(schema)
                graph_schema = json.loads((Path(build.__file__).resolve().parent.parent / "schemas/cargo-graph-v2.json").read_bytes());Draft202012Validator.check_schema(graph_schema)
                for identifier, feature in (("minimal", "minimal"), ("extra", "extra"), ("zero", "minimal"), ("service", "service")):
                    key = f"{identifier}--{target}--{feature}";output = parent / identifier
                    expected_selection = common.select(project, key)
                    observed = handoff.build_v3(root, args.armorer, key, output)
                    inventory = json.loads((output / "inventory.json").read_bytes());Draft202012Validator(schema).validate(inventory)
                    handoff_schema = json.loads((Path(build.__file__).resolve().parent.parent / "schemas/unsigned-handoff-v3.json").read_bytes())
                    Draft202012Validator.check_schema(handoff_schema);Draft202012Validator(handoff_schema).validate(observed)
                    graph = json.loads((output / (key+".cargo-graph.json")).read_bytes());Draft202012Validator(graph_schema).validate(graph)
                    root_name = "custom_zero" if identifier == "zero" else "fixture-app"
                    bom_bytes = (output / (key+".cdx.json")).read_bytes()
                    validate_graph_v2(graph, bom_bytes, expected_selection, context, inputs, root_name, "0.1.0")
                    expected_tools = {name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in installed.items()}
                    handoff.verify_handoff_v3(output, expected_selection, context, inputs, root_name, "0.1.0", expected_tools)
                    wrong_context = copy.deepcopy(context);wrong_context["run_attempt"] = "3"
                    try:
                        handoff.verify_handoff_v3(output, expected_selection, wrong_context, inputs, root_name, "0.1.0", expected_tools)
                    except build.BuildError:
                        pass
                    else:
                        raise AssertionError("cross-run handoff accepted")
                    names = {p["name"] for p in graph["packages"]}
                    assert ("fixture-extra" in names) == (identifier == "extra")
                    assert ("fixture-platform" in names) == (identifier != "zero" and target.endswith("apple-darwin"))
                    assert ("fixture-host" in names) == (identifier != "zero")
                    if identifier == "zero":
                        assert len(names) == 1 and graph["nodes"][0]["dependencies"] == []
                    else:
                        root_node = next(n for n in graph["nodes"] if n["id"] == graph["root"])
                        host_id = next(p["id"] for p in graph["packages"] if p["name"] == "fixture-host")
                        host_edge = next(e for e in root_node["dependencies"] if e["package"] == host_id)
                        assert host_edge["contexts"] == [{"kind":"build", "target":None}]
                        mutant = copy.deepcopy(graph);next(n for n in mutant["nodes"] if n["id"] == mutant["root"])["dependencies"] = []
                        try:
                            validate_graph_v2(mutant, bom_bytes, expected_selection, context, inputs, root_name, "0.1.0")
                        except build.BuildError:
                            pass
                        else:
                            raise AssertionError("retained graph edge mutation accepted")
                    cases.append({"id":identifier,"profile":inventory["selection"]["profile"],"packages":sorted(names),"files":inventory["files"],"observed_build":observed["observed_build"]})
                    if args.receipt_directory:
                        destination = args.receipt_directory / identifier;destination.mkdir(parents=True,exist_ok=False)
                        for path in output.iterdir():
                            (destination/path.name).write_bytes(path.read_bytes())
                receipt = {"native_target":target,"runtime_commit":runtime_commit,"source_commit":source_commit,"input_sha256":inputs,"cases":cases,"state":"unsigned-handoff","attested":False,"run_identity":"synthetic fixture-only 17/2"}
                if args.receipt_directory:
                    for name in ("armorer.toml", "armorer.lock", "Cargo.lock"):
                        (args.receipt_directory / name).write_bytes((root / name).read_bytes())
                    (args.receipt_directory / "receipt.json").write_text(json.dumps(receipt,indent=2)+'\n')
                print(json.dumps({"native_target":target,"cases":[c["id"] for c in cases],"state":"unsigned-handoff","attested":False}))
            finally:
                for key in ("GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
                    os.environ.pop(key,None)
                os.environ.update(saved)
    finally:
        tools.install_tools = original


if __name__ == "__main__":
    main()
