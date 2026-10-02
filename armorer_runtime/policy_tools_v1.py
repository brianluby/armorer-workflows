"""Qualified policy archives and exact native executable leaves, independent of legacy pins."""

from __future__ import annotations

from dataclasses import dataclass
import io
from pathlib import Path, PurePosixPath
import re
import tarfile
import time
import urllib.request

from . import common, tools
from .build import parse_json
from .common import require

CATALOG = Path(__file__).resolve().parent.parent / "pins/policy-tools-v1.json"
NAMES = frozenset({"actionlint", "cargo-deny", "gitleaks", "zizmor"})
MAX_ARCHIVE = 128 * 1024 * 1024
MAX_EXECUTABLE = MAX_ARCHIVE


def identity(data: bytes) -> dict:
    """Bind exact bytes with a size and SHA-256, without making an authentication claim."""
    return {"sha256": common.sha256(data), "size": len(data)}


def byte_identity(value: object, limit: int) -> bool:
    """Recognize a bounded nonempty identity without treating booleans as byte sizes."""
    return (isinstance(value, dict) and set(value) == {"sha256", "size"} and
            isinstance(value["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is not None and
            type(value["size"]) is int and 0 < value["size"] <= limit)


def native_header(data: bytes, target: str) -> None:
    """Check the qualified architecture before allowing a fixed native tool invocation."""
    if target == "aarch64-apple-darwin":
        require(len(data) >= 32 and data[:4] == b"\xcf\xfa\xed\xfe" and
                int.from_bytes(data[4:8], "little") == 0x100000c and
                int.from_bytes(data[12:16], "little") == 2, "policy executable architecture mismatch")
    else:
        require(target in common.RUNNERS and len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01" and
                int.from_bytes(data[18:20], "little") == (62 if target.startswith("x86_64") else 183) and
                int.from_bytes(data[16:18], "little") in (2, 3), "policy executable architecture mismatch")


def load_catalog() -> tuple[dict, dict]:
    """Load only the reviewed runtime-owned successor pins; no caller or environment override exists."""
    data = common.read_input(CATALOG.parent, CATALOG.name)
    catalog = parse_json(data)
    require(isinstance(catalog, dict) and set(catalog) == {"schema_version", "tools"} and
            type(catalog["schema_version"]) is int and catalog["schema_version"] == 1 and
            isinstance(catalog["tools"], dict) and set(catalog["tools"]) == NAMES,
            "unsupported qualified policy catalog")
    for name, tool in catalog["tools"].items():
        require(isinstance(tool, dict) and set(tool) == {"binary", "version", "platforms"} and
                tool["binary"] == name and common.VERSION.fullmatch(tool["version"]) is not None and
                isinstance(tool["platforms"], dict) and set(tool["platforms"]) == set(common.RUNNERS),
                "incomplete qualified policy tool")
        for pin in tool["platforms"].values():
            require(isinstance(pin, dict) and set(pin) == {"url", "format", "distribution", "member",
                                                         "executable", "authentication_record"} and
                    pin["format"] == "tar.gz" and isinstance(pin["url"], str) and
                    re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/releases/download/[^/\s]+/[^/\s]+", pin["url"]) and
                    byte_identity(pin["distribution"], MAX_ARCHIVE) and
                    byte_identity(pin["executable"], MAX_EXECUTABLE), "invalid qualified policy distribution")
            member = PurePosixPath(pin["member"])
            require(not member.is_absolute() and ".." not in member.parts and "\\" not in pin["member"] and
                    member.name == name, "invalid qualified policy member")
            record = pin["authentication_record"]
            require(isinstance(record, dict) and record.get("kind") == "github-release-provider-record-v1" and
                    record.get("upstream_signature_verified") is False and
                    isinstance(record.get("source_commit"), str) and
                    re.fullmatch(r"[0-9a-f]{40}", record["source_commit"]) is not None,
                    "unsupported policy tool authentication record")
    return catalog, identity(data)


def extract(data: bytes, pin: dict, target: str) -> bytes:
    """Authenticate the whole pinned archive first, then read only its one exact regular member."""
    require(identity(data) == pin["distribution"], "policy archive identity mismatch")
    found = None
    expanded = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for index, member in enumerate(archive):
            path = PurePosixPath(member.name)
            require(index < 512 and not path.is_absolute() and ".." not in path.parts and
                    "\\" not in member.name and (member.isfile() or member.isdir()), "unsafe policy tool archive")
            expanded += member.size
            require(expanded <= 512 * 1024 * 1024, "policy tool expansion limit")
            if member.name == pin["member"]:
                require(found is None and member.isfile() and member.size == pin["executable"]["size"],
                        "ambiguous policy executable member")
                stream = archive.extractfile(member)
                require(stream is not None, "missing policy executable")
                found = stream.read(MAX_EXECUTABLE + 1)
    require(found is not None and identity(found) == pin["executable"], "policy executable identity mismatch")
    native_header(found, target)
    return found


@dataclass(frozen=True)
class QualifiedTool:
    """A private installed native tool with its separately bound archive and executable identities."""

    path: Path
    target: str
    version: str
    pin: dict

    def verify(self) -> None:
        """Rehash the regular installed executable immediately around every tool call."""
        data = regular_executable(self.path)
        require(identity(data) == self.pin["executable"], "installed policy executable changed")
        native_header(data, self.target)


def regular_executable(path: Path) -> bytes:
    """Read a bounded regular native executable without accepting a symlink."""
    require(not path.is_symlink() and path.is_file(), "policy executable must be regular")
    with path.open("rb") as stream:
        data = stream.read(MAX_EXECUTABLE + 1)
    require(0 < len(data) <= MAX_EXECUTABLE, "policy executable size limit")
    return data


def install(destination: Path) -> tuple[dict[str, QualifiedTool], dict]:
    """Download fixed native distributions with hard size/time limits and no ambient proxy configuration."""
    catalog, catalog_id = load_catalog()
    target = tools.platform_target()
    require(target in common.RUNNERS and not destination.exists() and not destination.is_symlink(),
            "policy tools require a new private native destination")
    destination.mkdir(mode=0o700)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    result = {}
    for name, tool in sorted(catalog["tools"].items()):
        pin = tool["platforms"][target]
        deadline = time.monotonic() + 300
        data = bytearray()
        with opener.open(pin["url"], timeout=30) as response:
            while True:
                require(time.monotonic() <= deadline, "policy tool download timed out")
                block = response.read(min(65536, pin["distribution"]["size"] + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
                require(len(data) <= pin["distribution"]["size"], "policy tool download size mismatch")
        executable = extract(bytes(data), pin, target)
        path = destination / name
        with path.open("xb") as stream:
            stream.write(executable)
        path.chmod(0o500)
        result[name] = QualifiedTool(path.resolve(), target, tool["version"], pin)
        result[name].verify()
    return result, catalog_id
