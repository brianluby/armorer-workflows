"""Install the three independently qualified native GitHub CLI distributions.

These fixed delivery pins do not constitute production catalog acceptance or
authenticate upstream release signatures. Whole archive and executable bytes
must match before the existing GET-only adapter can execute the native CLI.
"""
from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import urllib.request
import zipfile
import zlib

from .common import Failure, require
from .tools import platform_target
from .transport_v1 import GH_PINS, GH_SOURCE, GH_VERSION, _identity

MANIFEST_SHA256 = "afe49e9affa232faa8212aed035417166f6ade9b9470acb53d4dbd28c0504e8d"
DISTRIBUTIONS = {
    "x86_64-unknown-linux-gnu": {
        "name": "gh_2.102.0_linux_amd64.tar.gz", "format": "tar.gz", "size": 15319960,
        "sha256": "bb766f710eef8ede859c18578c72c327597cd4c8a85b06001b1f3843c6019386",
        "leaf": "gh_2.102.0_linux_amd64/bin/gh"},
    "aarch64-unknown-linux-gnu": {
        "name": "gh_2.102.0_linux_arm64.tar.gz", "format": "tar.gz", "size": 13917794,
        "sha256": "7862c86c72f43df3a2d93ddde6f473285b4e2af61b494849846827e513ef6484",
        "leaf": "gh_2.102.0_linux_arm64/bin/gh"},
    "aarch64-apple-darwin": {
        "name": "gh_2.102.0_macOS_arm64.zip", "format": "zip", "size": 14359983,
        "sha256": "da922c20d1792e5b2cbf375593d7a658acf034c12c84e007e71c76ef959c337e",
        "leaf": "gh_2.102.0_macOS_arm64/bin/gh"},
}
MAX_ARCHIVE = 32 * 1024 * 1024
MAX_EXPANDED = 256 * 1024 * 1024
MAX_MEMBERS = 1024


def _member(name: str, directory: bool, root: str, seen: set[str]) -> None:
    """Reject ambiguous paths, traversal, duplicate members and foreign roots."""
    clean = name[:-1] if directory and name.endswith("/") else name
    path = PurePosixPath(clean)
    require(clean and not path.is_absolute() and str(path) == clean and
            ".." not in path.parts and "\\" not in clean and "\x00" not in clean and
            path.parts[0] == root and clean not in seen, "unsafe native GitHub distribution member")
    seen.add(clean)


def _binary(data: bytes, distribution: dict, native_size: int) -> bytes:
    """Decode only a bounded exact native leaf after the whole archive was qualified."""
    require(len(data) == distribution["size"] and len(data) <= MAX_ARCHIVE and
            hashlib.sha256(data).hexdigest() == distribution["sha256"], "native GitHub archive bytes mismatch")
    seen = set()
    found = []
    expanded = 0
    root = distribution["leaf"].split("/", 1)[0]
    if distribution["format"] == "tar.gz":
        with tarfile.open(fileobj=io.BytesIO(data), mode="r|gz") as archive:
            for member in archive:
                require(len(seen) < MAX_MEMBERS and (member.isfile() or member.isdir()), "unsafe native GitHub archive type or count")
                _member(member.name, member.isdir(), root, seen)
                require(0 <= member.size <= MAX_EXPANDED, "native GitHub member size exceeds limit")
                expanded += member.size
                require(expanded <= MAX_EXPANDED, "native GitHub archive expansion exceeds limit")
                if member.name == distribution["leaf"]:
                    require(member.isfile() and member.size == native_size, "native GitHub executable type or size mismatch")
                    stream = archive.extractfile(member)
                    require(stream is not None, "native GitHub executable missing")
                    with stream:
                        found.append(stream.read(native_size + 1))
    elif distribution["format"] == "zip":
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            require(0 < len(entries) <= MAX_MEMBERS, "native GitHub archive member count exceeds limit")
            for member in entries:
                mode = stat.S_IFMT(member.external_attr >> 16)
                directory = member.is_dir()
                require(member.orig_filename == member.filename and not member.flag_bits & 1 and
                        mode in ((0, stat.S_IFDIR) if directory else (0, stat.S_IFREG)) and
                        (directory or not member.external_attr & 0x10) and
                        member.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), "unsafe native GitHub ZIP member")
                _member(member.filename, directory, root, seen)
                require(0 <= member.file_size <= MAX_EXPANDED, "native GitHub member size exceeds limit")
                expanded += member.file_size
                require(expanded <= MAX_EXPANDED, "native GitHub archive expansion exceeds limit")
                if member.filename == distribution["leaf"]:
                    require(not directory and member.file_size == native_size, "native GitHub executable type or size mismatch")
                    with archive.open(member) as stream:
                        found.append(stream.read(native_size + 1))
    else:
        raise Failure("unsupported native GitHub archive format")
    require(len(found) == 1 and len(found[0]) == native_size, "native GitHub distribution must contain one exact executable")
    return found[0]


def _download(distribution: dict) -> bytes:
    """Fetch a fixed public distribution without ambient proxy or authentication inputs."""
    url = f"https://github.com/cli/cli/releases/download/v{GH_VERSION}/" + distribution["name"]
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=60) as response:
        require(response.geturl().startswith("https://"), "native GitHub delivery requires HTTPS")
        return response.read(MAX_ARCHIVE + 1)


def install_gh(destination: Path) -> tuple[Path, dict]:
    """Install one fixed native CLI in a new private directory and return an unsigned pin receipt."""
    target = platform_target()
    require(target in DISTRIBUTIONS and target in GH_PINS, "unsupported native GitHub distribution platform")
    require(not destination.exists() and not destination.is_symlink(), "native GitHub destination must be new")
    destination.mkdir(mode=0o700)
    distribution = DISTRIBUTIONS[target]
    native_size, native_digest = GH_PINS[target]
    output = destination / "gh"
    try:
        binary = _binary(_download(distribution), distribution, native_size)
        require(hashlib.sha256(binary).hexdigest() == native_digest, "native GitHub executable bytes mismatch")
        with output.open("xb") as stream:
            stream.write(binary)
            stream.flush()
            os.fsync(stream.fileno())
        output.chmod(0o500)
        require(_identity(output, native_size) == {"size": native_size, "sha256": native_digest}, "installed native GitHub bytes changed")
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError, zlib.error) as error:
        output.unlink(missing_ok=True)
        raise Failure("native GitHub installation failed closed") from error
    except Failure:
        output.unlink(missing_ok=True)
        raise
    return output, {"schema_version": 1, "state": "native-distribution-byte-qualified", "target": target,
                    "version": GH_VERSION, "source_commit": GH_SOURCE, "manifest_sha256": MANIFEST_SHA256,
                    "archive": {key: distribution[key] for key in ("name", "size", "sha256", "leaf")},
                    "executable": {"sha256": native_digest, "size": native_size},
                    "production_catalog_accepted": False, "upstream_signature_authenticated": False,
                    "signing_authorized": False}
