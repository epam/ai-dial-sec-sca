"""``sca import snyk``: the JSON of ``snyk test --all-projects --json`` (a list of
projects, or one object) as a schema 4 ``report.json``: one ``fs`` target per Snyk
project (``scanner`` ``snyk``) and one record per (package, vulnerability) in the one
version of the given ref.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sca.lib import dump_json, format_time, read_json
from sca.lib.context import CommandError, UsageError
from sca.merge.normalize import SEVERITIES
from sca.merge.vulns import OSV_ECOSYSTEMS, counts_of
from sca.rules import norm

# Snyk package manager -> OSV ecosystem (the engine's names; Snyk spells two differently)
ECOSYSTEMS = {**OSV_ECOSYSTEMS, "maven": "Maven", "gomodules": "Go"}


def target_id(project: Mapping[str, Any]) -> str:
    return "snyk:" + (project.get("targetFile") or project.get("displayTargetFile") or "unknown")


def target_of(project: Mapping[str, Any], ref: str, commit: str) -> dict[str, Any]:
    error = project.get("error")
    return {
        "id": target_id(project),
        "scanner": "snyk",
        "kind": "fs",
        "ref": ref,
        "commit_sha": commit,
        "image": None,
        "image_digest": None,
        "status": "failed" if error else "ok",
        "reason": (project.get("code") or error) if error else None,
        "packages_scanned": project.get("dependencyCount"),
        "os": None,
    }


def fold(
    records: dict[tuple[str, str], dict[str, Any]], project: Mapping[str, Any], v: Mapping[str, Any]
) -> None:
    """Fold the vulnerability ``v`` of ``project`` into the record of its package
    (a vulnerability is listed once per dependency path)."""
    ids = v.get("identifiers") or {}
    cves, ghsas = ids.get("CVE") or [], ids.get("GHSA") or []
    names = list(dict.fromkeys([*cves, *ghsas, v["id"]]))
    severity = (v.get("severity") or "").upper()
    severity = severity if severity in SEVERITIES else "UNKNOWN"
    r = records.setdefault(
        (norm(v["packageName"]), names[0]),
        {
            "id": names[0],
            "names": names,
            "pkg": v["packageName"],
            "pkg_key": norm(v["packageName"]),
            "class": "lang",
            "severity": severity,
            "fixed": [],
            "dev": True,
            "installed": set(),
            "where": set(),
            "sources": ["snyk"],
            "published": (v.get("publicationTime") or "")[:10] or None,
            "modified": (v.get("modificationTime") or "")[:10] or None,
            "cvss": {"score": v.get("cvssScore"), "vector": v.get("CVSSv3"), "source": "snyk"},
            "aliases": names[1:],
            "ecosystem": ECOSYSTEMS.get(project.get("packageManager") or ""),
            "title": v.get("title"),
            "exploit": v.get("exploit"),
            "cwe": ids.get("CWE") or [],
        },
    )
    r["severity"] = min(r["severity"], severity, key=SEVERITIES.index)
    r["fixed"] += [x for x in v.get("fixedIn") or [] if x not in r["fixed"]]
    r["dev"] = r["dev"] and bool(v.get("dev"))
    r["installed"].add(v["version"])
    r["where"].add(target_id(project))


def convert(
    projects: object,
    repo: str,
    ref: str,
    commit: str,
    snyk_version: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """The report of the projects of one ``snyk test`` output (a list or one object)."""
    items = [projects] if isinstance(projects, dict) else projects
    if not isinstance(items, list) or not all(isinstance(p, dict) for p in items):
        raise UsageError("the input is not the JSON of snyk test (a list of projects or one project)")
    targets = {target_id(p): target_of(p, ref, commit) for p in items}
    records: dict[tuple[str, str], dict[str, Any]] = {}
    for p in items:
        for v in p.get("vulnerabilities") or []:
            if v.get("type") != "license":  # licence issues are not vulnerabilities
                fold(records, p, v)
    vulns = [
        {**r, "fixed": ", ".join(r["fixed"]), "installed": sorted(r["installed"]), "where": sorted(r["where"])}
        for r in sorted(records.values(), key=lambda r: (r["pkg_key"], r["id"]))
    ]
    env = os.environ
    failed = any(t["status"] == "failed" for t in targets.values())
    return {
        "schema_version": 4,
        "engine": env.get("SCA_RUN_ENGINE_REF") or None,
        "repo": repo,
        "host": env.get("SCA_RUN_HOST", "github.com"),
        "commit_sha": commit,
        "default_branch": ref,
        "run_id": env.get("SCA_RUN_ID", ""),
        "run_attempt": None,
        "run_url": env.get("SCA_RUN_URL", ""),
        "generated_utc": format_time(now or datetime.now(UTC)),
        "tools": {
            "trivy": None,
            "trivy_db": None,
            "trivy_java_db": None,
            "osv_scanner": None,
            "osv_queried_at": None,
            "snyk": snyk_version,
        },
        "targets": [*targets.values()],
        "findings": [],
        "versions": [
            {
                "ref": ref,
                "kind": "development",
                "latest": False,
                "status": "failed" if failed else "ok",
                "targets": sorted(targets),
                "counts": counts_of(vulns),
                "vulns": vulns,
            }
        ],
    }


def main(argv: Sequence[str] | None = None, prog: str | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog=prog, description="Convert the JSON of snyk test --all-projects to a schema 4 report.json."
    )
    parser.add_argument("--input", required=True, type=Path, help="the JSON of snyk test")
    parser.add_argument("--repo", required=True, help="owner/name")
    parser.add_argument("--ref", required=True, help="the scanned ref (the default branch)")
    parser.add_argument("--commit", required=True, help="the scanned commit sha")
    parser.add_argument("--out", required=True, type=Path, help="the report.json to write")
    parser.add_argument("--snyk-version", help="the version of the Snyk CLI (tools.snyk)")
    args = parser.parse_args(argv)
    try:
        report = convert(read_json(args.input), args.repo, args.ref, args.commit, args.snyk_version)
    except (OSError, ValueError, CommandError) as error:
        print(f"error: cannot convert {args.input}: {error}", file=sys.stderr)
        return 2
    dump_json(args.out, report)
    print(f"{len(report['targets'])} target(s), {report['versions'][0]['counts']['all']} record(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
