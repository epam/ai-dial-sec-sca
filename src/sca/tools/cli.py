"""Install the tools of the scan: ``sca tools install --dir DIR``."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import shutil
import tarfile
import tempfile
import time
import urllib.request
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from sca.lib.context import CommandError, UsageError
from sca.lib.outputs import Annotations, execute

from . import pins

ATTEMPTS = 3
CHUNK = 1 << 20
TAG = re.compile(r"v\d+\.\d+\.\d+")
SHA256 = re.compile(r"[0-9a-f]{64}")
ARCHITECTURES = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}


def current_platform() -> str:
    """``linux-amd64`` or ``linux-arm64``; anything else is an error."""
    name = f"{platform.system().lower()}-{ARCHITECTURES.get(platform.machine().lower())}"
    if name not in pins.PLATFORMS:
        raise CommandError(
            f"unsupported platform {platform.system()} {platform.machine()}: "
            f"the tools exist for {', '.join(pins.PLATFORMS)}"
        )
    return name


def fetch(url: str, target: Path) -> None:
    """Download ``url`` to ``target``, a few attempts."""
    for attempt in range(1, ATTEMPTS + 1):
        try:
            with urllib.request.urlopen(url, timeout=60) as response, target.open("wb") as f:
                shutil.copyfileobj(response, f, CHUNK)
            return
        except OSError as error:
            if attempt == ATTEMPTS:
                raise CommandError(f"cannot download {url}: {error}") from error
            time.sleep(2 * attempt)


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def verified_download(url: str, sha256: str, directory: Path) -> Path:
    """The artifact of ``url`` in ``directory``, verified: a file found there is
    checked again and downloaded again if it does not match; a download that does
    not match is an error and leaves no file.
    """
    path = directory / url.rsplit("/", 1)[1]
    if path.is_file() and sha256_of(path) == sha256:
        return path
    path.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(dir=directory) as scratch:
        part = Path(scratch) / path.name
        fetch(url, part)
        if (found := sha256_of(part)) != sha256:
            raise CommandError(f"sha256 of {path.name} is {found}, the pinned value is {sha256}")
        part.replace(path)
    return path


def place(tool: str, member: str | None, artifact: Path, directory: Path) -> None:
    """The binary of ``tool`` in ``directory``, executable: the one ``member`` of the
    tar.gz, or the artifact itself.
    """
    binary = directory / tool
    if member is None:
        shutil.copyfile(artifact, binary)
    else:
        with tarfile.open(artifact) as archive:
            try:
                entry = archive.getmember(member)
            except KeyError:
                raise CommandError(f"{artifact.name} has no {member}") from None
            source = archive.extractfile(entry) if entry.isfile() else None
            if source is None:
                raise CommandError(f"{member} in {artifact.name} is not a file")
            with source, binary.open("wb") as f:
                shutil.copyfileobj(source, f, CHUNK)
    binary.chmod(0o755)


def resolve(
    tools: Sequence[str], trivy_version: str | None, trivy_sha256: str | None, system: str
) -> dict[str, tuple[str, str, str]]:
    """Per tool the ``(tag, sha256, url)`` to install. The pinned sha256 of a Trivy
    version wins over ``trivy_sha256``, which is for a version not pinned.
    """
    resolved = {}
    for name in tools:
        tool = pins.TOOLS[name]
        tag = (trivy_version if name == "trivy" else None) or tool.default
        sha256 = tool.sha256.get(tag, {}).get(system) or (
            trivy_sha256 if name == "trivy" else None
        )
        if sha256 is None:
            raise UsageError(
                f"no pinned sha256 for Trivy {tag}: pass the sha256 of its release archive "
                "as --trivy-sha256"
            )
        url = tool.url.format(tag=tag, version=tag[1:], arch=tool.arch[system])
        resolved[name] = (tag, sha256, url)
    return resolved


def install(resolved: dict[str, tuple[str, str, str]], directory: Path) -> dict[str, str]:
    """Install the resolved tools into ``directory``; the version of each."""
    directory.mkdir(parents=True, exist_ok=True)
    for name, (_, sha256, url) in resolved.items():
        (directory / name).unlink(missing_ok=True)  # no binary of an earlier run stays on a failure
        place(name, pins.TOOLS[name].member, verified_download(url, sha256, directory), directory)
    return {name: tag for name, (tag, _, _) in resolved.items()}


def cache_key(resolved: dict[str, tuple[str, str, str]], system: str) -> str:
    """The cache key of an install directory: the platform and the tools with their
    versions and checksums, so a change of the table is a new key.
    """
    digest = hashlib.sha256(json.dumps(resolved, sort_keys=True).encode()).hexdigest()
    return f"sca-tools-{system}-{digest[:16]}"


def parse_args(argv: Sequence[str] | None, prog: str | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog=prog, description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--tools", default=",".join(pins.TOOLS), help="comma separated; default: all")
    common.add_argument("--output-dir", default=Path("out"), type=Path)
    common.add_argument("--trivy-version", help="a tag vX.Y.Z; default: the pinned one")
    common.add_argument(
        "--trivy-sha256", help="sha256 of the archive; needed for a version that is not pinned"
    )
    install_parser = commands.add_parser(
        "install", parents=[common], description="Install the tools into a directory."
    )
    install_parser.add_argument("--dir", required=True, type=Path)
    commands.add_parser(
        "key",
        parents=[common],
        description="The cache key of the install directory (output key), without installing.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None, prog: str | None = None) -> int:
    args = parse_args(argv, prog)
    tools = list(dict.fromkeys(name.strip() for name in args.tools.split(",") if name.strip()))

    def body(_notes: Annotations) -> tuple[str, dict[str, Any]]:
        if unknown := [name for name in tools if name not in pins.TOOLS]:
            raise UsageError(f"unknown tools {', '.join(unknown)}; known: {', '.join(pins.TOOLS)}")
        if args.trivy_version is not None and not TAG.fullmatch(args.trivy_version):
            raise UsageError(
                f"--trivy-version must be a release tag of the form vX.Y.Z, got {args.trivy_version!r}"
            )
        if args.trivy_sha256 is not None and not SHA256.fullmatch(args.trivy_sha256):
            raise UsageError("--trivy-sha256 must be 64 lowercase hex digits")
        system = current_platform()
        resolved = resolve(tools, args.trivy_version, args.trivy_sha256, system)
        if args.command == "key":
            return "ok", {"key": cache_key(resolved, system)}
        directory = args.dir.resolve()
        return "ok", {"dir": str(directory), "versions": install(resolved, directory)}

    return execute(f"tools-{args.command}", args.output_dir, body)
