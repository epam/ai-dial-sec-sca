"""``sca java <dir> [--provided 11,17,21,25]``: the JDK to run the Gradle wrapper of a
checkout on, as JSON on stdout. Exit 2 (reason on stderr and in the JSON) when it is unknown.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Sequence
from pathlib import Path

# Minimum Gradle version that runs on a Java version (docs.gradle.org compatibility, "Running Gradle")
MIN_GRADLE = {
    11: (5, 0),
    17: (7, 3),
    21: (8, 5),
    23: (8, 10),
    24: (8, 14),
    25: (9, 1, 0),
}
GRADLE_9_MIN_JAVA = 17
PROPERTIES = "gradle/wrapper/gradle-wrapper.properties"
DISTRIBUTION = re.compile(r"gradle-(\d+(?:\.\d+)*(?:-(?:rc|milestone)-\d+)?)-(?:bin|all)\.zip$")


def gradle_version(directory: Path) -> str:
    """The Gradle version of the wrapper; ``ValueError`` (the reason) when there is none."""
    path = directory / PROPERTIES
    if not path.is_file():
        raise ValueError(f"no {PROPERTIES}")
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        key, _, value = line.partition("=")
        if key.strip() == "distributionUrl":
            url = value.strip().replace("\\:", ":")
            if match := DISTRIBUTION.search(url.rsplit("/", 1)[-1]):
                return match.group(1)
            raise ValueError(f"no Gradle version in distributionUrl {url!r}")
    raise ValueError(f"no distributionUrl in {PROPERTIES}")


def choose(gradle: str, provided: Sequence[int]) -> int:
    """The highest provided JDK that Gradle ``gradle`` runs on; ``ValueError`` when none."""
    number = tuple(int(part) for part in re.match(r"\d+(?:\.\d+)*", gradle)[0].split("."))  # type: ignore[index]
    floor = GRADLE_9_MIN_JAVA if number[0] >= 9 else 0
    fits = [java for java in provided if java >= floor and MIN_GRADLE[java] <= number]
    if not fits:
        raise ValueError(f"no JDK of {','.join(map(str, provided))} can run Gradle {gradle}")
    return max(fits)


def installations(provided: Sequence[int], env: dict[str, str]) -> dict[str, int]:
    """The installed JDKs of ``provided`` as JAVA_HOME_<v>_<arch> variable name -> version."""
    names = {f"JAVA_HOME_{java}_{arch}": java for java in provided for arch in ("X64", "ARM64")}
    return {name: names[name] for name in names if env.get(name)}


def setup(java: int, provided: Sequence[int], env: dict[str, str], gradle_home: Path) -> str:
    """Make the provided JDKs detectable by Gradle toolchains (``gradle.properties`` of the
    Gradle user home) and return the JAVA_HOME of ``java``; ``ValueError`` when it is not installed."""
    found = installations(provided, env)
    home = next((env[name] for name, version in found.items() if version == java), None)
    if home is None:
        raise ValueError(f"JDK {java} is not installed (no JAVA_HOME_{java}_X64 or JAVA_HOME_{java}_ARM64)")
    key = "org.gradle.java.installations.fromEnv"
    path = gradle_home / "gradle.properties"
    lines = path.read_text(encoding="utf-8").splitlines() if path.is_file() else []
    lines = [line for line in lines if line.partition("=")[0].strip() != key]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join([*lines, f"{key}={','.join(found)}"]) + "\n", encoding="utf-8")
    return home


def main(argv: Sequence[str] | None = None, prog: str | None = None) -> int:
    parser = argparse.ArgumentParser(prog=prog, description=__doc__)
    parser.add_argument("directory", type=Path, help="checkout with the Gradle wrapper")
    parser.add_argument("--provided", default="11,17,21,25", help="installed JDKs, comma separated")
    parser.add_argument("--setup", action="store_true", help="also write the Gradle toolchain detection and print java_home")
    args = parser.parse_args(argv)
    try:
        provided = [int(java) for java in args.provided.split(",")]
        if unknown := [java for java in provided if java not in MIN_GRADLE]:
            raise ValueError(f"unknown JDK {unknown[0]} (known: {','.join(map(str, MIN_GRADLE))})")
        gradle = gradle_version(args.directory)
        java = choose(gradle, provided)
        home = setup(java, provided, dict(os.environ), Path(os.environ.get("GRADLE_USER_HOME") or Path.home() / ".gradle")) if args.setup else None
    except ValueError as error:
        print(json.dumps({"java": None, "gradle": None, "reason": str(error)}))
        print(f"sca java: {error}", file=sys.stderr)
        return 2
    reason = f"Gradle {gradle} runs on JDK {java} (highest of {args.provided})"
    print(json.dumps({"java": str(java), "gradle": gradle, "reason": reason, **({"java_home": home} if home else {})}))
    return 0
