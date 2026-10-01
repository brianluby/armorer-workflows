"""Native end-to-end builder fixtures, independent of pilot repositories.

Run explicitly after trusted tool setup. The fixture is a temporary clean Git
checkout; an unrelated workspace member enables an optional feature that must
not leak into the selected application's minimal build or SBOM.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import subprocess


def create_fixture(root: Path, target: str) -> None:
    from armorer_runtime import build, tools

    runtime_root = Path(build.__file__).resolve().parent.parent
    runtime_commit = subprocess.check_output(["/usr/bin/git", "-C", str(runtime_root), "rev-parse", "HEAD"], text=True).strip()
    catalog = json.loads(tools.CATALOG.read_text())
    tool = catalog["tools"]["cargo-cyclonedx"]
    files = {
        "Cargo.toml": '[workspace]\nmembers = ["app", "extra", "other", "zero", "platform"]\nresolver = "2"\n',
        "LICENSE": "MIT fixture license\n",
        ".gitignore": "*.cdx.json\n",
        "app/Cargo.toml": '''[package]
name = "fixture-app"
version = "0.1.0"
edition = "2024"
license = "MIT"
[features]
extra = ["dep:fixture-extra"]
[dependencies]
fixture-extra = { path = "../extra", optional = true }
[target.'cfg(target_os = "macos")'.dependencies]
platform = { package = "fixture-platform", path = "../platform" }
[[bin]]
name = "fixture-app"
path = "src/main.rs"
''',
        "app/src/main.rs": '''fn main() {
    #[cfg(feature = "extra")]
    println!("{}", custom_extra::value());
    #[cfg(target_os = "macos")]
    println!("{}", platform::value());
    println!("Armorer fixture");
}
''',
        "extra/Cargo.toml": '[package]\nname="fixture-extra"\nversion="0.1.0"\nedition="2024"\nlicense="MIT"\n[lib]\nname="custom_extra"\n',
        "extra/src/lib.rs": "pub fn value() -> u8 { 7 }\n",
        "platform/Cargo.toml": '[package]\nname="fixture-platform"\nversion="0.1.0"\nedition="2024"\nlicense="MIT"\n',
        "platform/src/lib.rs": "pub fn value() -> u8 { 9 }\n",
        "other/Cargo.toml": '[package]\nname="fixture-other"\nversion="0.1.0"\nedition="2024"\nlicense="MIT"\n[dependencies]\nfixture-app={path="../app",features=["extra"]}\n',
        "other/src/lib.rs": "pub fn other() {}\n",
        "zero/Cargo.toml": '[package]\nname="fixture-zero"\nversion="0.1.0"\nedition="2024"\nlicense="MIT"\ndescription="Zero dependency fixture"\n[lib]\nname="custom_zero"\n',
        "zero/src/lib.rs": "pub fn zero() -> u8 { 0 }\n",
    }
    config = f'''schema_version = 1
repository = "fixture/build"
toolchain = "1.95.0"
manifest = "Cargo.toml"

[feature_sets.minimal]
default_features = false
features = []
[feature_sets.extra]
default_features = false
features = ["extra"]

[[deliverables]]
id = "minimal"
profile = "cli"
package = "fixture-app"
binary = "fixture-app"
targets = ["{target}"]
feature_set = "minimal"
[[deliverables]]
id = "extra"
profile = "cli"
package = "fixture-app"
binary = "fixture-app"
targets = ["{target}"]
feature_set = "extra"
[[deliverables]]
id = "zero"
profile = "library"
package = "fixture-zero"
targets = ["{target}"]
feature_set = "minimal"

[policy]
license_file = "LICENSE"
attestations = "required"
'''
    files["armorer.toml"] = config
    digest = hashlib.sha256(config.encode()).hexdigest()
    files["armorer.lock"] = f'''schema_version = 1
config_sha256 = "{digest}"
runtime_version = "0.1.0"
[workflows]
repository = "brianluby/armorer-workflows"
commit = "{runtime_commit}"
[tools.cargo-cyclonedx]
version = "{tool['version']}"
sha256 = "{tool['platforms'][target]['sha256']}"
'''
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def main() -> None:
    from armorer_runtime import build, common, tools
    from jsonschema import Draft202012Validator

    parser = argparse.ArgumentParser()
    parser.add_argument("--armorer", type=Path, required=True)
    parser.add_argument("--tool-directory", type=Path, required=True)
    arguments = parser.parse_args()
    target = tools.platform_target()
    installed = tools.install_tools(arguments.tool_directory, ["cargo-cyclonedx", "cyclonedx"])
    original_install = tools.install_tools

    # Explicit test substitution avoids repeated downloads; production has no
    # environment option for replacing reviewed tool installation.
    def test_install(destination, names):
        assert names == ["cargo-cyclonedx", "cyclonedx"]
        return installed

    tools.install_tools = test_install
    try:
        with tempfile.TemporaryDirectory(prefix="armorer-native-fixture-") as temporary:
            parent = Path(temporary)
            root = parent / "source"
            root.mkdir()
            create_fixture(root, target)
            environment = common.cargo_environment("1.95.0", parent / "cargo-home", parent / "target")
            for command in [["/usr/bin/git", "init", "-q"],
                            ["cargo", "generate-lockfile", "--manifest-path", str(root / "Cargo.toml")],
                            ["/usr/bin/git", "add", "."],
                            ["/usr/bin/git", "-c", "user.name=Armorer Fixture", "-c", "user.email=fixture@example.invalid",
                             "-c", "commit.gpgsign=false", "commit", "-qm", "fixture"]]:
                common.run(command, cwd=root, env=environment)
            # Tests are not a caller source workflow: avoid borrowing the host
            # repository and commit identity as claims for the fixture checkout.
            saved = {k: os.environ.pop(k) for k in ("GITHUB_REPOSITORY", "GITHUB_SHA") if k in os.environ}
            try:
                results = {}
                for identifier, feature in [("minimal", "minimal"), ("extra", "extra"), ("zero", "minimal")]:
                    artifact_id = f"{identifier}--{target}--{feature}"
                    results[identifier] = build.build(root, arguments.armorer, artifact_id, parent / identifier)
                    schema = json.loads((Path(build.__file__).resolve().parent.parent / "schemas/build-inventory-v1.json").read_text())
                    Draft202012Validator(schema).validate(results[identifier])
                minimal = json.loads((parent / "minimal" / f"minimal--{target}--minimal.cdx.json").read_text())
                extra = json.loads((parent / "extra" / f"extra--{target}--extra.cdx.json").read_text())
                assert "fixture-extra" not in {c["name"] for c in minimal["components"]}
                assert "fixture-extra" in {c["name"] for c in extra["components"]}
                expected_platform = target.endswith("apple-darwin")
                assert ("fixture-platform" in {c["name"] for c in minimal["components"]}) == expected_platform
                zero = json.loads((parent / "zero" / f"zero--{target}--minimal.cdx.json").read_text())
                assert zero["components"] == [] and zero["metadata"]["component"]["name"] == "custom_zero"
                assert results["zero"]["artifact_kind"] == "source-package"
                # These mutations remain CycloneDX-schema-valid. Independent
                # identity and graph checks must still reject them.
                components = [extra["metadata"]["component"], *extra["components"]]
                expected_ids = {c["bom-ref"] for c in components}
                root_reference = extra["metadata"]["component"]["bom-ref"]
                expected_metadata = {"packages": [{"id": c["bom-ref"], "name": c["name"], "version": c["version"],
                                                     "targets": [{"name": c["name"]}] if c["bom-ref"] == root_reference else []} for c in components],
                                     "resolve": {"root": root_reference, "nodes": [{"id": n["ref"], "dependencies": n.get("dependsOn", [])} for n in extra["dependencies"]]}}
                build.validate_sbom(json.dumps(extra).encode(), "fixture-app", "0.1.0", expected_ids, expected_metadata)
                for mutation in ("root", "version", "edge", "root-reference"):
                    changed = copy.deepcopy(extra)
                    if mutation == "root":
                        changed["metadata"]["component"]["name"] = "wrong-source-component"
                    elif mutation == "version":
                        changed["components"][0]["version"] = "9.9.9"
                    elif mutation == "edge":
                        root_ref = changed["metadata"]["component"]["bom-ref"]
                        next(n for n in changed["dependencies"] if n["ref"] == root_ref)["dependsOn"] = [root_ref]
                    else:
                        root_component = changed["metadata"]["component"]
                        dependency_component = changed["components"][0]
                        root_component["bom-ref"], dependency_component["bom-ref"] = dependency_component["bom-ref"], root_component["bom-ref"]
                        dependency_component["name"] = root_component["name"]
                        dependency_component["version"] = root_component["version"]
                    mutant = parent / (mutation + ".cdx.json")
                    mutant.write_text(json.dumps(changed))
                    common.run([str(installed["cyclonedx"]), "validate", "--input-file", str(mutant), "--input-format", "json",
                                "--input-version", "v1_5", "--fail-on-errors"], cwd=parent, env=environment)
                    try:
                        build.validate_sbom(mutant.read_bytes(), "fixture-app", "0.1.0", expected_ids, expected_metadata)
                    except build.BuildError:
                        pass
                    else:
                        raise AssertionError("schema-valid SBOM mutation was accepted")
                print(json.dumps({"native_target": target, "cases": list(results), "state": "build-produced", "attested": False}))
            finally:
                os.environ.update(saved)
    finally:
        tools.install_tools = original_install


if __name__ == "__main__":
    main()
