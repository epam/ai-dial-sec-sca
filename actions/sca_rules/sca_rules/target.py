"""The target rule: the version to upgrade one installed version of a package to."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .versions import (
    VersionError,
    VersionKey,
    compare,
    major,
    release_part,
    version_key,
)

Record = Mapping[str, Any]

ALLOW_MAJOR = ("none", "dev-proven")
NO_FIXED_VERSION = "no_fixed_version"
NEEDS_MAJOR = "needs_major"
VERSION_UNPARSABLE = "version_unparsable"


def fixed_versions(record: Record) -> list[str]:
    """The fixed versions of a record (``fixed`` is a comma separated list)."""
    return [v.strip() for v in record["fixed"].split(",") if v.strip()]


def ordered(version: str, installed: str) -> tuple[VersionKey, int, str]:
    """Sort key: version order, then the spelling with as many components as the
    ``installed`` version (``1.3`` and ``1.3.0`` are equal versions; the one that looks
    like the installed one names an existing artifact), then the text, so the choice
    is the same on every run.
    """
    gap = abs(len(release_part(version)) - len(release_part(installed)))
    return version_key(version), gap, version


def safe_for(candidate: str, record: Record) -> bool:
    """True when ``candidate`` is not vulnerable to ``record``: it is at or above the
    highest fixed version of the record, or at or above a fixed version of the same
    major.minor (the fix of the maintained branch the candidate is on), or at or above
    the highest fixed version of its own major (a record that lists one fix per major).
    """
    fixed = fixed_versions(record)
    if compare(candidate, max(fixed, key=version_key)) >= 0:
        return True
    line = release_part(candidate)[:2]
    if any(release_part(f)[:2] == line and compare(candidate, f) >= 0 for f in fixed):
        return True
    own = [f for f in fixed if major(f) == major(candidate)]
    return bool(own) and compare(candidate, max(own, key=version_key)) >= 0


def choose_target(
    installed: str,
    records: Sequence[Record],
    dev_versions: Sequence[str],
    allow_major: str,
) -> tuple[str | None, str, str | None]:
    """The target version for one installed version: ``(target, evidence, None)`` or
    ``(None, reason, reason_code)``. Raises ``VersionError`` for a version it cannot
    compare. A development version at or above ``required`` is the target as it is
    (development's own scan proves it; the caller passes only versions of a
    development that fixes every record). A fixed version must also be safe for every
    record that has a fixed version above ``installed`` (``safe_for``).
    """
    applicable = [r for r in records if installed in r["installed"]]
    required: str | None = None
    fixable = []  # the records that have a fixed version above ``installed``
    for record in applicable:
        above = [f for f in fixed_versions(record) if compare(f, installed) > 0]
        if not above:
            continue
        fixable.append(record)
        lowest = min(above, key=version_key)
        if required is None or compare(lowest, required) > 0:
            required = lowest
    if required is None:
        return None, f"no fixed version above {installed}", NO_FIXED_VERSION
    fixes = sorted(
        {f for r in applicable for f in fixed_versions(r)},
        key=lambda f: ordered(f, installed),
    )
    same_major = major(installed)
    from_dev = sorted(
        (v for v in dev_versions if compare(v, required) >= 0),
        key=lambda v: ordered(v, installed),
    )
    allowed = [
        v
        for v in from_dev
        if major(v) == same_major or allow_major == "dev-proven"
    ]
    if allowed:
        return allowed[0], f"development runs {allowed[0]}", None
    reachable = [f for f in fixes if compare(f, required) >= 0]
    for f in reachable:  # the lowest one in the major that is safe for every record
        if major(f) == same_major and all(safe_for(f, r) for r in fixable):
            return f, "lowest fixed version in the same major", None
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
    another major); a fixed version must also not be vulnerable to any of the records
    (``safe_for``). ``evidence`` is a plain string; ``reason_code`` is
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
