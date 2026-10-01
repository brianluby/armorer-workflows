"""Install only reviewed catalog distributions, checking bytes before extraction."""

from __future__ import annotations

import io
import json
from pathlib import Path, PurePosixPath
import platform
import tarfile
import urllib.request

from .common import Failure, require, sha256

MAX_ARCHIVE = 128 * 1024 * 1024
MAX_EXPANDED = 512 * 1024 * 1024
MAX_MEMBERS = 512
CATALOG = Path(__file__).resolve().parent.parent / "pins" / "tools.json"


def platform_target() -> str:
    systems = {"Linux": "unknown-linux-gnu", "Darwin": "apple-darwin"}
    machines = {"x86_64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64"}
    require(platform.system() in systems and platform.machine() in machines, "unsupported tool platform")
    return f'{machines[platform.machine()]}-{systems[platform.system()]}'


def extract_binary(data: bytes, binary: str, archive_format: str) -> bytes:
    """Never extract links, devices, paths or unrelated archive files to disk."""
    if archive_format == "binary":
        require(len(data) <= MAX_EXPANDED, "tool binary exceeds limit")
        return data
    require(archive_format in ("tar.gz", "tar.xz"), "unsupported catalog archive format")
    found = []
    expanded = 0
    count = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        for member in archive:
            count += 1
            require(count <= MAX_MEMBERS, "tool archive member limit exceeded")
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and ".." not in path.parts and "\\" not in member.name,
                    "unsafe tool archive path")
            require(member.isfile() or member.isdir(), "tool archive contains unsafe member type")
            expanded += member.size
            require(expanded <= MAX_EXPANDED, "tool archive expansion limit exceeded")
            if member.isfile() and path.name == binary:
                handle = archive.extractfile(member)
                require(handle is not None, "tool binary is missing")
                found.append(handle.read(MAX_EXPANDED + 1))
    require(len(found) == 1 and found[0], "tool archive must contain one expected binary")
    return found[0]


def install_tools(destination: Path, names: list[str]) -> dict[str, Path]:
    """No environment or consumer configuration can supply URLs or digests."""
    require(not destination.is_symlink(), "tool destination may not be a symlink")
    destination.mkdir(parents=True, exist_ok=True)
    require(not any(destination.iterdir()), "tool destination must be empty")
    catalog = json.loads(CATALOG.read_text())
    require(catalog["schema_version"] == 1, "unsupported tool catalog")
    target = platform_target()
    result = {}
    for name in names:
        require(name in catalog["tools"] and name not in result, "unknown or duplicate catalog tool")
        tool = catalog["tools"][name]
        require(target in tool["platforms"], "catalog tool unavailable for platform")
        distribution = tool["platforms"][target]
        require(distribution["url"].startswith("https://github.com/"), "untrusted catalog origin")
        try:
            with urllib.request.urlopen(distribution["url"], timeout=60) as response:
                data = response.read(MAX_ARCHIVE + 1)
        except (OSError, ValueError) as error:
            raise Failure("reviewed tool download failed") from error
        require(len(data) <= MAX_ARCHIVE, "tool archive size limit exceeded")
        require(sha256(data) == distribution["sha256"], "tool distribution digest mismatch")
        output = extract_binary(data, tool["binary"], distribution["format"])
        path = destination / tool["binary"]
        require(path.parent == destination and not path.exists(), "unsafe catalog binary path")
        with path.open("xb") as handle:
            handle.write(output)
        path.chmod(0o700)
        result[name] = path.resolve()
    return result
