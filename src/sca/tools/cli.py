"""Install the tools of the scan: ``sca tools install --dir DIR``."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import platform
import re
import shutil
import tarfile
import tempfile
import time
import urllib.request
from collections.abc import Sequence
from pathlib import Path
from typing import Any, BinaryIO

from sca.lib.context import CommandError, UsageError
from sca.lib.outputs import Annotations, execute

from . import pins

ATTEMPTS = 3
DOWNLOADS, BIN = "downloads", "bin"
CHUNK = 1 << 20
TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+")
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
        except (OSError, http.client.HTTPException) as error:
            if attempt == ATTEMPTS:
                raise CommandError(f"cannot download {url}: {error}") from error
            time.sleep(2 * attempt)


def sha256_of(f: BinaryIO) -> str:
    """The sha256 of the whole file, which is left at its start."""
    digest = hashlib.sha256()
    f.seek(0)
    while chunk := f.read(CHUNK):
        digest.update(chunk)
    f.seek(0)
    return digest.hexdigest()


def clear(path: Path) -> None:
    """Nothing at ``path`` any more, whatever it was."""
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink(missing_ok=True)


def open_verified(path: Path, sha256: str) -> BinaryIO | None:
    """``path`` open, if it is a regular file with this sha256; the handle that was
    hashed is the one to read from, so the content cannot change in between.
    """
    if path.is_symlink() or not path.is_file():
        return None
    f = path.open("rb")
    if sha256_of(f) == sha256:
        return f
    f.close()
    return None


def verified_download(url: str, sha256: str, directory: Path) -> BinaryIO:
    """The artifact of ``url`` in ``directory``, open and verified: a file found there
    is checked again and downloaded again if it does not match; a download that does
    not match is an error and leaves no file.
    """
    path = directory / url.rsplit("/", 1)[1]
    if (f := open_verified(path, sha256)) is not None:
        return f
    clear(path)
    with tempfile.TemporaryDirectory(dir=directory) as scratch:
        part = Path(scratch) / path.name
        fetch(url, part)
        with part.open("rb") as f:
            found = sha256_of(f)
        if found != sha256:
            raise CommandError(f"sha256 of {path.name} is {found}, the pinned value is {sha256}")
        part.replace(path)
    if (f := open_verified(path, sha256)) is None:
        raise CommandError(f"{path.name} changed after the download")
    return f


def place(tool: str, member: str | None, artifact: BinaryIO, directory: Path) -> None:
    """The binary of ``tool`` in ``directory``, executable: the one ``member`` of the
    tar.gz ``artifact``, or the artifact itself; written aside and moved into place.
    """
    binary = directory / tool
    with artifact:
        if member is None:
            write_executable(artifact, binary)
            return
        with tarfile.open(fileobj=artifact) as archive:
            try:
                entry = archive.getmember(member)
            except KeyError:
                raise CommandError(f"the archive of {tool} has no {member}") from None
            source = archive.extractfile(entry) if entry.isfile() else None
            if source is None:
                raise CommandError(f"{member} in the archive of {tool} is not a regular file")
            with source:
                write_executable(source, binary)


def write_executable(source: BinaryIO, binary: Path) -> None:
    fd, name = tempfile.mkstemp(dir=binary.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            shutil.copyfileobj(source, f, CHUNK)
        os.chmod(name, 0o755)
        os.replace(name, binary)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise


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
    """Install the resolved tools: the verified downloads stay in ``directory/downloads``
    (the only part to cache), the binaries are placed in ``directory/bin``, which is
    recreated empty, so only what was just placed from a verified artifact is in it.
    The version of each tool.
    """
    downloads, binaries = directory / DOWNLOADS, directory / BIN
    if not downloads.is_dir():
        clear(downloads)
        downloads.mkdir(parents=True)
    clear(binaries)
    binaries.mkdir(parents=True)
    for name, (_, sha256, url) in resolved.items():
        place(name, pins.TOOLS[name].member, verified_download(url, sha256, downloads), binaries)
    return {name: tag for name, (tag, _, _) in resolved.items()}


def cache_key(resolved: dict[str, tuple[str, str, str]], system: str) -> str:
    """The cache key of the downloads: the platform and the tools with their versions
    and checksums, so a change of the table is a new key.
    """
    digest = hashlib.sha256(json.dumps([system, resolved], sort_keys=True).encode()).hexdigest()
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
    common.add_argument(
        "--dir", required=True, type=Path, help="the install directory; resolved to an absolute path"
    )
    commands.add_parser(
        "install",
        parents=[common],
        description="Install the tools: verified downloads in DIR/downloads, binaries in DIR/bin.",
    )
    commands.add_parser(
        "key",
        parents=[common],
        description="The cache key of DIR/downloads (output key) and its path (output downloads), "
        "without installing.",
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
        trivy_sha256 = args.trivy_sha256 and args.trivy_sha256.lower()
        if trivy_sha256 is not None and not SHA256.fullmatch(trivy_sha256):
            raise UsageError("--trivy-sha256 must be 64 hex digits")
        system = current_platform()
        resolved = resolve(tools, args.trivy_version, trivy_sha256, system)
        directory = args.dir.resolve()
        outputs = {"downloads": str(directory / DOWNLOADS)}
        if args.command == "key":
            return "ok", {"key": cache_key(resolved, system), **outputs}
        versions = install(resolved, directory)
        return "ok", {"dir": str(directory / BIN), **outputs, "versions": versions}

    return execute(f"tools-{args.command}", args.output_dir, body)
