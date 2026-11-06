"""The target rule: the version to upgrade one installed version of a package to."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .versions import VersionError, compare, major, version_key

Record = Mapping[str, Any]

ALLOW_MAJOR = ("none", "dev-proven")
NO_FIXED_VERSION = "no_fixed_version"
NEEDS_MAJOR = "needs_major"
VERSION_UNPARSABLE = "version_unparsable"


def fixed_versions(record: Record) -> list[str]:
    """The fixed versions of a record (``fixed`` is a comma separated list)."""
    return [v.strip() for v in record["fixed"].split(",") if v.strip()]


def choose_target(
    installed: str,
    records: Sequence[Record],
    dev_versions: Sequence[str],
    allow_major: str,
) -> tuple[str | None, str, str | None]:
    """The target version for one installed version: ``(target, evidence, None)`` or
    ``(None, reason, reason_code)``. Raises ``VersionError`` for a version it cannot
    compare.
    """
    applicable = [r for r in records if installed in r["installed"]]
    fixes = sorted({f for r in applicable for f in fixed_versions(r)}, key=version_key)
    required: str | None = None
    for record in applicable:
        above = [f for f in fixed_versions(record) if compare(f, installed) > 0]
        if not above:
            continue
        lowest = min(above, key=version_key)
        if required is None or compare(lowest, required) > 0:
            required = lowest
    if required is None:
        return None, f"no fixed version above {installed}", NO_FIXED_VERSION
    same_major = major(installed)
    from_dev = sorted(
        (v for v in dev_versions if compare(v, required) >= 0), key=version_key
    )
    allowed = [
        v for v in from_dev if major(v) == same_major or allow_major == "dev-proven"
    ]
    if allowed:
        return allowed[0], f"development runs {allowed[0]}", None
    reachable = [f for f in fixes if compare(f, required) >= 0]
    in_major = [f for f in reachable if major(f) == same_major]
    if in_major:
        return in_major[0], "lowest fixed version in the same major", None
    note = (
        "development runs it, allow-major is none"
        if from_dev
        else "no development evidence"
    )
    text = f"fix needs another major ({', '.join(reachable)}), {note}"
    return None, text, NEEDS_MAJOR


def upgrade_target(
    installed: str,
    records: Sequence[Record],
    dev_versions: Sequence[str] = (),
    allow_major: str = "none",
) -> tuple[str | None, str, str | None]:
    """The version to upgrade ``installed`` to, by the rule of the plan:
    ``(target, evidence, None)``, or ``(None, text, reason_code)`` when no target
    exists.

    ``records`` are the vulnerability records of one package (``fixed`` is a comma
    separated list, ``installed`` a list); only those installed at ``installed`` count.
    The required version is the highest over the records of the lowest fixed version
    above ``installed``. The target is the lowest ``dev_versions`` entry at or above
    it, else the lowest fixed version at or above it, each in the major of
    ``installed`` (``allow_major="dev-proven"`` also takes a development version of
    another major). ``evidence`` is a plain string; ``reason_code`` is
    ``no_fixed_version``, ``needs_major`` or ``version_unparsable`` (a version that
    cannot be compared: the result is returned, not raised). ``ValueError`` for an
    ``allow_major`` that is not ``none`` or ``dev-proven``.
    """
    if allow_major not in ALLOW_MAJOR:
        raise ValueError(f"allow_major: one of {', '.join(ALLOW_MAJOR)} is expected")
    try:
        return choose_target(installed, records, tuple(dev_versions), allow_major)
    except VersionError as exc:
        return None, f"cannot compare versions {exc}", VERSION_UNPARSABLE
