"""The fixed-in-development rule for one record (the rule of the fix spec, 4.3).

What the development version's data says about a record of a release version, once
the development version is known to have been scanned where the record lives (the
caller decides that): fixed, removed or open.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
from typing import Any

from .keys import norm

Record = Mapping[str, Any]
Key = tuple[str, str]

FIXED, REMOVED, OPEN = "fixed", "removed", "open"


def key_of(record: Record) -> Key:
    """The package key ``(class, norm(pkg))`` of a record or a package entry."""
    return record["class"], norm(record["pkg"])


def identifiers(record: Record) -> set[str]:
    """``id``, ``names`` and ``aliases`` of a record."""
    return {record["id"], *record["names"], *(record.get("aliases") or [])}


def development_state(
    record: Record, runs: Collection[Key], ids: Mapping[Key, Collection[str]]
) -> str:
    """``removed`` when development does not run the package of ``record``, ``open``
    when a development record of the same package shares an identifier with it, else
    ``fixed``. ``runs`` are the package keys development runs, ``ids`` the identifiers
    of its records per package key. A development record of another package never
    counts.
    """
    key = key_of(record)
    if key not in runs:
        return REMOVED
    if identifiers(record) & set(ids.get(key, ())):
        return OPEN
    return FIXED
