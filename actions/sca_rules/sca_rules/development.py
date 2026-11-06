"""The fixed-in-development rule for one record (the rule of the fix spec, 4.3).

What the development version's data says about a record of a release version: fixed,
removed, open, or incomplete when development was not scanned where the record
lives. The one definition; the planner and the scan engine both use it.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .keys import norm

Record = Mapping[str, Any]
Key = tuple[str, str]

FIXED, REMOVED, OPEN, INCOMPLETE = "fixed", "removed", "open", "incomplete"


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


def usable(target: Mapping[str, Any]) -> bool:
    return target.get("status") == "ok" and target.get("packages_scanned", 0) > 0


@dataclass(frozen=True)
class Development:
    """The development version: its Trivy targets by id, the statuses of the other
    scanners' targets of the same ids (the OSV twins), the packages it runs and the
    identifiers of its records, per package key.
    """

    targets: Mapping[str, Mapping[str, Any]]
    twins: Mapping[str, Sequence[str | None]]
    runs: frozenset[Key]
    ids: Mapping[Key, frozenset[str]]

    @classmethod
    def of(
        cls,
        targets: Mapping[str, Mapping[str, Any]],
        twins: Mapping[str, Sequence[str | None]],
        packages: Sequence[Record],
        vulns: Sequence[Record],
    ) -> Development:
        ids: dict[Key, set[str]] = {}
        for record in vulns:
            ids.setdefault(key_of(record), set()).update(identifiers(record))
        return cls(
            targets,
            twins,
            frozenset(key_of(p) for p in packages if p.get("installed"))
            | frozenset(ids),
            {k: frozenset(v) for k, v in ids.items()},
        )

    def complete(self, id: str) -> bool:
        """The Trivy target ``id`` of development is usable and every other scanner's
        target of the same id (the OSV twin) is ``ok`` or ``not_applicable``.
        """
        target = self.targets.get(id)
        twins = self.twins.get(id, ())
        return (
            target is not None
            and usable(target)
            and all(s in ("ok", "not_applicable") for s in twins)
        )

    def gap(
        self, record: Record, targets: Mapping[str, Mapping[str, Any]]
    ) -> str | None:
        """What is missing to trust the absence of ``record`` from development, or
        None. ``targets`` are the Trivy targets of the record's version.

        The absence counts only when development was scanned, completely, in every
        kind of target the record was found in: in a source target (at least one
        development source target, every one complete), and for each image of the
        record a complete development target of the same image. A library record
        with a source target is checked on the sources only (the source scan sees the
        manifest); one found only in images needs the image, as an OS record does. A
        library record with no known place is checked as a source record. The status
        of the version is not used: a failure of an unrelated target does not block
        the record.
        """
        found = [targets[i] for i in record["where"] if i in targets]
        images = sorted({t["image"] for t in found if t.get("image")})
        in_source = any(t.get("kind") == "fs" for t in found) or (
            record["class"] == "lang" and not images
        )
        if in_source and record["class"] == "lang":
            images = []  # the source scan sees the manifest; the image adds nothing
        if in_source:
            sources = sorted(
                i for i, t in self.targets.items() if t.get("kind") == "fs"
            )
            if not sources or not all(self.complete(i) for i in sources):
                return "no ok source target with packages scanned"
        missing = [
            image
            for image in images
            if not any(
                t.get("image") == image and self.complete(i)
                for i, t in self.targets.items()
            )
        ]
        if missing or (not images and not in_source):
            return f"no ok image target for {', '.join(missing) or 'the record'}"
        return None

    def state(
        self, record: Record, targets: Mapping[str, Mapping[str, Any]]
    ) -> tuple[str, str | None]:
        """``(state, gap)`` of a record of a release version: ``incomplete`` with the
        missing part, else ``development_state``.
        """
        if gap := self.gap(record, targets):
            return INCOMPLETE, gap
        return development_state(record, self.runs, self.ids), None
