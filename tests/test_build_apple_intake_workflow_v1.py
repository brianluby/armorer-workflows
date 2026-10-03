"""Run the actual validator build step against inert Cargo override attacks without credentials."""
import os
from pathlib import Path
import shutil
import sys
import tempfile
import textwrap
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def build_step():
    """Extract the real isolated Python build body without interpreting other workflow commands."""
    workflow = (ROOT / ".github/workflows/apple-intake-rehearsal-v1.yml").read_text()
    step = workflow.split("      - name: Build fixed credential-free fixture validator\n", 1)[1]
    block = step.split("        run: |\n", 1)[1].split("      - name:", 1)[0]
    script = textwrap.dedent(block)
    assert script.startswith("python3 -I - <<'PY'\n") and script.rstrip().endswith("\nPY")
    return script.split("\n", 1)[1].rsplit("\nPY", 1)[0]


def fixture(root):
    """Stage a tiny fixed compiler fixture separately from a candidate-controlled repository."""
    candidate, scratch = root / "candidate", root / "scratch"
    candidate.mkdir()
    scratch.mkdir()
    controls = candidate / "fixture-runtime-controls/armorer_runtime"
    controls.mkdir(parents=True)
    shutil.copyfile(ROOT / "armorer_runtime/common.py", controls / "common.py")
    source = candidate / "fixture-validator"
    (source / "src").mkdir(parents=True)
    (source / "Cargo.toml").write_text('[package]\nname="fixed-intake-probe"\nversion="0.1.0"\nedition="2021"\n')
    (source / "Cargo.lock").write_text('version = 3\n[[package]]\nname="fixed-intake-probe"\nversion="0.1.0"\n')
    (source / "src/main.rs").write_text('fn main() {}\n')
    marker = root / "wrapper-executed"
    wrapper = root / "rustc-wrapper"
    wrapper.write_text('#!' + sys.executable + '\nfrom pathlib import Path\nPath(' + repr(str(marker)) + ').write_text("executed")\nraise SystemExit(1)\n')
    wrapper.chmod(0o700)
    return candidate, scratch, marker, wrapper


def run_step(candidate, scratch, extra_environment=None):
    """Execute the workflow's exact build body with test-owned cwd and explicitly injected overrides."""
    original = Path.cwd()
    try:
        os.chdir(candidate)
        with mock.patch.dict(os.environ, {"RUNNER_SCRATCH": str(scratch), **(extra_environment or {})}):
            exec(compile(build_step(), "apple-intake-build-step", "exec"), {})
    finally:
        os.chdir(original)


class AppleIntakeWorkflowTests(unittest.TestCase):
    """Prove candidate configuration cannot reach the real fixed compiler invocation."""

    def test_candidate_config_and_inherited_wrappers_do_not_execute(self):
        """Compile from sterile scratch while candidate Cargo config, flags and wrapper variables are hostile."""
        with tempfile.TemporaryDirectory() as temporary:
            candidate, scratch, marker, wrapper = fixture(Path(temporary))
            (candidate / ".cargo").mkdir()
            (candidate / ".cargo/config.toml").write_text('[build]\nrustc-wrapper=' + repr(str(wrapper)) + '\n')
            run_step(candidate, scratch, {"RUSTC_WRAPPER": str(wrapper), "RUSTC_WORKSPACE_WRAPPER": str(wrapper),
                "CARGO_BUILD_RUSTC_WRAPPER": str(wrapper), "RUSTFLAGS": "--invalid-inherited-flag",
                "CARGO_ENCODED_RUSTFLAGS": "--invalid-inherited-flag", "CARGO_HOME": str(candidate / ".cargo")})
            self.assertFalse(marker.exists())
            self.assertTrue((scratch / "apple-intake-validator-target/debug/fixed-intake-probe").is_file())
            self.assertFalse((candidate / "fixture-runtime-controls").exists())
            self.assertFalse((candidate / "fixture-validator").exists())

    def test_scratch_ancestor_configuration_blocks_before_execution(self):
        """Reject both ancestor config spellings before moving source or executing a compiler wrapper."""
        for spelling in ("config", "config.toml"):
            with self.subTest(spelling=spelling), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                candidate, scratch, marker, wrapper = fixture(root)
                (scratch / ".cargo").mkdir()
                (scratch / ".cargo" / spelling).write_text('[build]\nrustc-wrapper=' + repr(str(wrapper)) + '\n')
                with self.assertRaisesRegex(Exception, "Cargo ancestor overrides"):
                    run_step(candidate, scratch)
                self.assertFalse(marker.exists())
                self.assertTrue((candidate / "fixture-validator").is_dir())
                self.assertFalse((scratch / "apple-intake-validator-target").exists())

    def test_altered_fixed_controls_fail_before_source_or_build_execution(self):
        """Reject a replaced control module without importing it or allowing its side effects."""
        with tempfile.TemporaryDirectory() as temporary:
            candidate, scratch, marker, _ = fixture(Path(temporary))
            controls = candidate / "fixture-runtime-controls/armorer_runtime/common.py"
            controls.write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').write_text("executed")\n')
            with self.assertRaises(AssertionError):
                run_step(candidate, scratch)
            self.assertFalse(marker.exists())
            self.assertTrue((candidate / "fixture-validator").is_dir())


if __name__ == "__main__":
    unittest.main()
