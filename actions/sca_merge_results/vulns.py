"""``versions[]`` of report.json: the vulnerability records of every scanned version.

The findings of both scanners and of all targets of a version merge into one record
per vulnerability of a package (see ``build_versions``); the counts of the version
are computed from its records.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from normalize import SEVERITIES, norm

Finding = Mapping[str, Any]

VERSION = re.compile(r"(\d+(?:\.\d+)*)(-.+)?")


def version_order(version: str) -> tuple[int, Any]:
    """development first, then releases from the newest (a release candidate after
    its final version), then whatever is not a version, alphabetically.
    """
    if version == "development":
        return 0, ()
    if m := VERSION.fullmatch(version):
        return 1, (tuple(-int(n) for n in m[1].split(".")), m[2] is not None, m[2])
    return 2, version


def versions_of(report: Mapping[str, Any]) -> list[tuple[str, set[str]]]:
    """(version, ids of its targets) in display order. The source and the images of
    one version agree on it: a git tag may carry a ``v`` that a registry tag lacks.
    A target without a ref (its resolution failed) belongs to no version.
    """
    ids: dict[str, set[str]] = {}
    for t in report["targets"]:
        if t["ref"]:
            ids.setdefault(t["ref"].removeprefix("v"), set()).add(t["id"])
    return sorted(ids.items(), key=lambda item: version_order(item[0]))


def is_release(ref: str, default_branch: str | None) -> bool:
    """A plain semver tag: not the default branch, not ``development``, not a
    pre-release, and not a ref that does not parse as semver.
    """
    if ref == default_branch or ref == "development":
        return False
    m = VERSION.fullmatch(ref)
    return m is not None and m[2] is None


def version_kind(ref: str, default_branch: str | None) -> str:
    """``development`` for the default branch or ``development``; ``candidate`` for a
    semver with a pre-release part (``0.50.0-rc.1``); ``release`` otherwise.
    """
    if ref == default_branch or ref == "development":
        return "development"
    m = VERSION.fullmatch(ref)
    if m and m[2] is not None:
        return "candidate"
    return "release"


def components(findings: Sequence[Finding]) -> list[list[Finding]]:
    """Findings of one package grouped by intersecting ``names`` (union-find, so the
    result does not depend on the order); each group keeps the order of its findings.
    """
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for f in findings:
        for name in f["names"]:
            parent[find(name)] = find(f["names"][0])
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(find(f["names"][0]), []).append(f)
    return list(groups.values())


def record_of(fs: Sequence[Finding], source_ids: set[str]) -> dict[str, Any]:
    """The vulnerability record of one component of findings (Trivy first, then OSV,
    each by target and id).
    """
    ids = sorted(f["id"] for f in fs)
    vid = next((i for i in ids if i.startswith("CVE-")), ids[0])
    names = {n for f in fs for n in f["names"]}
    # the rating of Trivy wins; OSV rates a vulnerability Trivy does not report
    rated = [f for f in fs if f["scanner"] == "trivy"] or fs
    fixed = (x.strip() for f in fs for x in f["fixed_version"].split(",") if x.strip())
    dates = [f["published"] for f in fs if f["published"]]
    return {
        "id": vid,
        "names": [vid, *sorted(names - {vid})],
        "pkg": next((f for f in fs if f["target"] in source_ids), fs[0])["pkg"],
        "class": fs[0]["class"],
        "severity": min((f["severity"] for f in rated), key=SEVERITIES.index),
        "fixed": ", ".join(dict.fromkeys(fixed)),
        "dev": all(f["dev"] for f in fs),
        "installed": sorted({f["version"] for f in fs}),
        "where": sorted({f["target"] for f in fs}),
        "sources": [s for s in ("trivy", "osv") if any(f["scanner"] == s for f in fs)],
        "published": min(dates, default=None),
        "accepted": None,
    }


def counts_of(vulns: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    """Severity counts, ``all`` and ``fixable`` of the records."""
    by = [sum(v["severity"] == s for v in vulns) for s in SEVERITIES]
    return {
        **dict(zip(("c", "h", "m", "l", "unknown"), by)),
        "all": len(vulns),
        "fixable": sum(bool(v["fixed"]) for v in vulns),
    }


def build_versions(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    """One record per version of ``versions_of``, in that order: ``status`` (failed
    when a Trivy or an OSV scan of a target failed; a ``not_applicable`` target does
    not fail it), ``kind``, ``latest`` (the newest ``ok`` release), ``targets``, the
    ``vulns`` merged over the targets and scanners, and their ``counts``. A failed
    version keeps what its ``ok`` targets found.
    """
    default_branch = report["default_branch"]
    source_ids = {t["id"] for t in report["targets"] if t["kind"] == "fs"}
    findings = sorted(
        report["findings"],
        key=lambda f: (
            f["scanner"] != "trivy",
            f["target"],
            f["id"],
            f["pkg"],
            f["version"],
        ),
    )
    result = []
    for ref, ids in versions_of(report):
        failed = any(
            t["status"] == "failed" for t in report["targets"] if t["id"] in ids
        )
        packages: dict[tuple[str, str], list[Finding]] = {}
        for f in findings:
            if f["target"] in ids:
                packages.setdefault((f["class"], norm(f["pkg"])), []).append(f)
        records = (
            record_of(c, source_ids) for fs in packages.values() for c in components(fs)
        )
        vulns = sorted(
            records,
            key=lambda v: (v["class"], norm(v["pkg"]), v["id"]),
        )
        result.append(
            {
                "ref": ref,
                "kind": version_kind(ref, default_branch),
                "latest": False,  # resolved below, once every status is known
                "status": "failed" if failed else "ok",
                "targets": sorted(ids),
                "counts": counts_of(vulns),
                "vulns": vulns,
            }
        )
    ok_releases = (
        v
        for v in result
        if v["status"] == "ok" and is_release(v["ref"], default_branch)
    )
    if latest := next(ok_releases, None):
        latest["latest"] = True
    return result
