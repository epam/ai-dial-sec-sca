"""What development says about a release record: fixed, removed, open or unknown.

The rule lives in ``sca_rules`` (``Development``); this module applies it to the
planner's ``Version`` and exposes ``classify``. The planner and the report model share
it through ``classify``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from sca.rules import Development, identifiers, norm

from .config import Config
from .lines import select_lines
from .reports import Reports, Version, development_version, merge_reports

Record = Mapping[str, Any]


def development_of(version: Version) -> Development:
    """The development data of a ``Version`` (the rule itself is in ``sca_rules``)."""
    return Development.of(
        version.targets, version.twins, version.packages, version.vulns
    )


def classify(reports: Reports | Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """The development state of every record of the planned lines.

    ``reports`` are the schema 4 reports of one repo (or the merged ``Reports``).
    Lines are selected with the default ``release-lines`` and ``include-candidate``;
    accepted records are left out and no severity, fixable or dev filter applies.
    One entry per record: ``{repo, line, ref, kind, class, key, pkg, ids, state}``,
    ``state`` one of ``fixed``, ``removed``, ``open``, ``incomplete``, sorted by repo,
    line order (the candidate first, then newest first), class, key and ids.
    """
    merged = reports if isinstance(reports, Reports) else merge_reports(reports)
    dev = development_of(development_version(merged))
    entries: list[tuple[int, dict[str, Any]]] = []
    for order, planned in enumerate(select_lines(merged, Config())[0]):
        line, version = planned.line, planned.version
        for record in version.vulns:
            if record["accepted"]:
                continue
            entries.append(
                (
                    order,
                    {
                        "repo": merged.repo,
                        "line": f"{line[0]}.{line[1]}",
                        "ref": version.ref,
                        "kind": version.kind,
                        "class": record["class"],
                        "key": norm(record["pkg"]),
                        "pkg": record["pkg"],
                        "ids": sorted(identifiers(record)),
                        "state": dev.state(record, version.targets)[0],
                    },
                )
            )
    entries.sort(
        key=lambda e: (e[1]["repo"], e[0], e[1]["class"], e[1]["key"], e[1]["ids"])
    )
    return [entry for _, entry in entries]
