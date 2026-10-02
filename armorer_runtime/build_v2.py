"""Fixed unsigned v2 builder entry point; no caller graph version or provenance input."""
import argparse
import json
from pathlib import Path
import subprocess

from .build import BuildError, build_v2
from .common import Failure


def main():
    """Build exactly the independently rederived selection with retained graph version two."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--armorer", type=Path, required=True)
    parser.add_argument("--artifact-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        inventory = build_v2(args.root, args.armorer, args.artifact_id, args.output)
        print(json.dumps({"artifact_id": inventory["selection"]["artifact_id"], "state": inventory["state"]}, sort_keys=True))
    except (BuildError, Failure, ValueError, OSError, KeyError, TypeError, AttributeError, subprocess.SubprocessError):
        parser.exit(1, "Armorer v2 builder failed closed; review selected graph, source context and build prerequisites.\n")


if __name__ == "__main__":
    main()
