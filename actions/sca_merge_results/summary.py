"""summary.md of the SCA merge: the vulnerable packages of every scanned version."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from normalize import SEVERITIES, norm

# GitHub rejects a step summary over 1 MiB; the rest of the limit is left for the
# parts of the job summary that are not this one
STEP_SUMMARY_LIMIT_BYTES = 1024 * 1024 - 16 * 1024

Finding = Mapping[str, Any]


def cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def short_time(value: str | None) -> str:
    return f"{value[:16]}Z" if value else "n/a"


def target_label(target: Mapping[str, Any], repo: str) -> str:
    """``src`` or the short name of the image (``chat``, ``bff``): where a package is
    seen within one version.
    """
    if target["kind"] == "fs":
        return "src"
    image = target["image"].split("/")[-1]
    if image == repo:
        return image.removeprefix("ai-dial-")
    return image.removeprefix(f"{repo}-")


def package_rows(
    findings: Sequence[Finding], source_ids: set[str]
) -> list[dict[str, Any]]:
    """One row per (class, normalized package name) - the version dropped for OS
    packages, which the scanners spell differently (dpkg epochs and revisions) - with
    its unique vulnerabilities merged over targets and scanners (Trivy's severity
    wins). Rows without a fix come last, development-only packages after the others,
    then worst severity first.
    """
    groups: dict[tuple[str, ...], list[Finding]] = {}
    for f in findings:
        key = (f["class"], norm(f["pkg"])) if f["class"] == "os" else (
            f["class"],
            norm(f["pkg"]),
            f["version"],
        )
        groups.setdefault(key, []).append(f)
    rows = []
    for key, fs in groups.items():
        cls = key[0]
        # an OS row keeps a version in its cell: the primary scanner's spelling
        # (Trivy's, else OSV's) - the scanners spell one dpkg version differently,
        # and both spellings in one cell would read as two installed versions
        version = (
            key[-1]
            if len(key) == 3
            else next((f for f in fs if f["scanner"] == "trivy"), fs[0])["version"]
        )
        # the name as written in a source target (lockfile), else the first seen
        pkg = next((f for f in fs if f["target"] in source_ids), fs[0])["pkg"]
        # findings of one vulnerability under different ids merge by shared aliases
        vulns: list[dict[str, Any]] = []
        for f in sorted(fs, key=lambda f: f["scanner"] != "trivy"):
            names = {f["id"], *f.get("aliases", [])}
            v = next((v for v in vulns if v["names"] & names), None)
            if v is None:
                v = {
                    "id": f["id"],
                    "names": set(),
                    "severity": f["severity"],
                    "url": f["url"],
                    "fixed": [],
                    "scanners": set(),
                }
                vulns.append(v)
            v["names"] |= names
            if f["id"].startswith("CVE-") and not v["id"].startswith("CVE-"):
                v["id"], v["url"] = f["id"], f["url"]
            v["fixed"] += [
                x.strip() for x in f["fixed_version"].split(",") if x.strip()
            ]
            v["scanners"].add(f["scanner"])
        ordered = sorted(
            vulns, key=lambda v: (SEVERITIES.index(v["severity"]), v["id"])
        )
        with_chain = next((f for f in fs if f["chain"]), None)
        in_source = [
            loc for f in fs if f["target"] in source_ids for loc in f["locations"]
        ]
        fixed = ", ".join(dict.fromkeys(x for v in ordered for x in v["fixed"]))
        scanners = "+".join(
            s[0].upper()
            for s in ("trivy", "osv")
            if any(s in v["scanners"] for v in ordered)
        )
        rows.append(
            {
                "class": cls,
                "pkg": pkg,
                "version": version,
                "vulns": ordered,
                "severity": ordered[0]["severity"],
                "fixed": fixed,
                "no_fix": not fixed,
                "chain": with_chain["chain"] if with_chain else [],
                "relationship": next(
                    (f["relationship"] for f in fs if f["relationship"]), None
                ),
                "dev": all(f["dev"] for f in fs),
                "where": in_source or [loc for f in fs for loc in f["locations"]],
                "targets": {f["target"] for f in fs},
                "scanners": scanners,
            }
        )
    return sorted(
        rows,
        key=lambda r: (
            r["no_fix"],
            r["dev"],
            SEVERITIES.index(r["severity"]),
            r["pkg"],
            r["version"],
        ),
    )


def where_cell(locations: Sequence[str]) -> str:
    parts = list(dict.fromkeys("/".join(loc.split("/")[-2:]) for loc in locations))
    return cell(
        ", ".join(parts[:2]) + (f" +{len(parts) - 2}" if len(parts) > 2 else "")
    )


def chain_cell(row: Mapping[str, Any]) -> str:
    chain = row["chain"]
    direct = "direct" if chain or row["relationship"] == "direct" else ""
    text = " → ".join(chain) if len(chain) > 1 else direct
    return cell(text)


def vulnerabilities_cell(row: Mapping[str, Any]) -> str:
    mixed = len({v["severity"] for v in row["vulns"]}) > 1
    return ", ".join(
        (v["severity"][0] + " " if mixed else "")
        + (f"[{cell(v['id'])}]({v['url']})" if v["url"] else cell(v["id"]))
        for v in row["vulns"]
    )


def package_table(
    rows: Sequence[Mapping[str, Any]],
    columns: Sequence[tuple[str, str]],
    libraries: bool,
) -> list[str]:
    head = ["Package@version", "Sev", "Fixed", "Vulnerabilities"]
    head += ["Chain", "Where"] if libraries else []
    head += ["Seen in", "Scanner"]
    lines = ["| " + " | ".join(head) + " |", "|" + "|".join(["---"] * len(head)) + "|"]
    for r in rows:
        cells = [
            cell(f"{r['pkg']}@{r['version']}") + (" `dev`" if r["dev"] else ""),
            r["severity"][0],
            cell(r["fixed"] or "no fix"),
            vulnerabilities_cell(r),
        ]
        if libraries:
            cells += [chain_cell(r), where_cell(r["where"])]
        cells += [
            ", ".join(label for label, tid in columns if tid in r["targets"]),
            r["scanners"],
        ]
        lines.append("| " + " | ".join(cells) + " |")
    return lines


def plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def totals(libraries: Sequence[Any], os_rows: Sequence[Any]) -> str:
    no_fix = sum(1 for r in [*libraries, *os_rows] if r["no_fix"])
    return ", ".join(
        [
            plural(len(libraries), "library", "libraries"),
            plural(len(os_rows), "OS package", "OS packages"),
            f"{no_fix} without a fix",
        ]
    )


def severity_block(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Counts of the vulnerabilities of package rows: per severity and overall,
    ``all`` and ``fixable`` (a fixed version is known, as in ``totals``).
    """
    by = {s: {"all": 0, "fixable": 0} for s in SEVERITIES}
    for v in (v for r in rows for v in r["vulns"]):
        by[v["severity"]]["all"] += 1
        by[v["severity"]]["fixable"] += bool(v["fixed"])
    return {
        "all": sum(b["all"] for b in by.values()),
        "fixable": sum(b["fixable"] for b in by.values()),
        "by_severity": by,
    }


def build_counts(report: Mapping[str, Any]) -> dict[str, Any]:
    """The ``counts`` block of report.json, from the same rows the summary lists.

    ``total`` counts the unique vulnerabilities of the repository (a finding present
    in several targets counts once); ``targets`` counts them per target id, so the
    targets do not sum to the total. A target that is not ``ok`` has its status only.
    The status of a target is its Trivy scan's, as in the summary.
    """
    findings = report["findings"]
    source_ids = {t["id"] for t in report["targets"] if t["kind"] == "fs"}
    targets: dict[str, Any] = {}
    for t in sorted(report["targets"], key=lambda t: t["scanner"] != "trivy"):
        targets.setdefault(t["id"], t)
    result: dict[str, Any] = {}
    for tid, t in targets.items():
        if t["status"] == "ok":
            rows = package_rows([f for f in findings if f["target"] == tid], source_ids)
            result[tid] = {"status": "ok", **severity_block(rows)}
        else:
            result[tid] = {"status": t["status"]}
    return {
        "total": severity_block(package_rows(findings, source_ids)),
        "targets": result,
    }


def scan_status(trivy: Mapping[str, Any], osv: Mapping[str, Any] | None) -> str:
    text = trivy["status"] + (f" ({trivy['reason']})" if trivy["reason"] else "")
    if trivy["status"] == "ok" and osv:
        if osv["status"] != "ok":
            detail = (
                f"failed: {osv['reason']}" if osv["status"] == "failed" else osv["status"]
            )
            text += f" · OSV {detail}"
        # an ok with a reason states an exclusion (the image scan disabled for the
        # repository); it must not read as a plain ok
        elif osv["reason"]:
            text += f" · OSV ok ({osv['reason']})"
    return text


def header(report: Mapping[str, Any]) -> list[str]:
    tools = report["tools"]
    parts = [
        f"commit `{(report['commit_sha'] or '')[:7]}`",
        f"default branch `{report['default_branch']}`",
        f"Trivy {tools['trivy']} (DB {short_time(tools['trivy_db'])}, "
        f"Java DB {short_time(tools['trivy_java_db'])})",
        f"osv-scanner {tools['osv_scanner']} (queried {tools['osv_queried_at'] or 'n/a'})",
    ]
    if report["run_url"]:
        parts.append(f"[run {report['run_id']}]({report['run_url']})")
    lines = [f"# SCA · {report['repo']}", "", " · ".join(parts), ""]
    one_offs = one_off_lines(report)
    if one_offs:
        lines += [*one_offs, ""]
    return lines


def one_off_lines(report: Mapping[str, Any]) -> list[str]:
    """What this run covers beyond the regular release set, when it does: a focus
    run on one tag, a direct OSV image scan forced for the run."""
    lines = []
    if scan_ref := report.get("scan_ref"):
        lines.append(f"Focused on tag `{scan_ref}` (a manual run on one tag).")
    if report.get("forced_image_scan"):
        lines.append(
            "The direct OSV image scan runs on this run although it is off for the "
            "repository."
        )
    return lines


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


def scan_cell(report: Mapping[str, Any], ids: set[str]) -> str:
    """ok, or failed when any scan of the version failed, and what was scanned."""
    targets = [t for t in report["targets"] if t["id"] in ids]

    def of(scanner: str, status: str) -> set[str]:
        return {
            t["id"]
            for t in targets
            if t["scanner"] == scanner and t["status"] == status
        }

    failed, skipped = of("trivy", "failed"), of("trivy", "not_applicable")
    osv_failed = of("osv", "failed") - failed
    scanned = {t["id"]: t["kind"] for t in targets if t["id"] not in failed | skipped}
    parts = ["source"] if "fs" in scanned.values() else []
    if images := sum(1 for kind in scanned.values() if kind == "image"):
        parts.append(plural(images, "image", "images"))
    for n, what in ((failed, "failed"), (osv_failed, "OSV failed"), (skipped, "n/a")):
        if n:
            parts.append(f"{len(n)} {what}")
    return f"{'failed' if failed or osv_failed else 'ok'} ({', '.join(parts)})"


def count_cell(n: int) -> str:
    return str(n) if n else "-"


def versions_table(
    report: Mapping[str, Any],
    by_version: Sequence[tuple[str, set[str]]],
    version_rows: Mapping[str, Sequence[Mapping[str, Any]]],
    unique: Sequence[Mapping[str, Any]],
) -> list[str]:
    severities = [
        s
        for s in SEVERITIES
        if s != "UNKNOWN" or any(r["severity"] == s for r in unique)
    ]
    head = ["Version", "Scan", *(f"Libs {s[0]}" for s in severities)]
    head += ["OS pkgs", "No fix"]
    lines = [
        "| " + " | ".join(head) + " |",
        "|---|---|" + "---:|" * (len(head) - 2),
    ]

    def counts(rows: Sequence[Mapping[str, Any]]) -> list[str]:
        libs = [r for r in rows if r["class"] == "lang"]
        return [
            *(
                count_cell(sum(1 for r in libs if r["severity"] == s))
                for s in severities
            ),
            count_cell(len(rows) - len(libs)),
            count_cell(sum(1 for r in rows if r["no_fix"])),
        ]

    for version, ids in by_version:
        cells = [
            cell(version),
            cell(scan_cell(report, ids)),
            *counts(version_rows[version]),
        ]
        lines.append("| " + " | ".join(cells) + " |")
    total = ["**Unique across versions**", "", *counts(unique)]
    lines.append("| " + " | ".join(total) + " |")
    return [
        *lines,
        "",
        "Counts are vulnerable packages by their worst severity. A package present in "
        "several versions is counted once in the last row; the rows do not add up to "
        "this line.",
    ]


def vulnerabilities_table(
    by_version: Sequence[tuple[str, set[str]]],
    version_rows: Mapping[str, Sequence[Mapping[str, Any]]],
    unique: Sequence[Mapping[str, Any]],
) -> list[str]:
    def vulns(rows: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
        return [v for r in rows for v in r["vulns"]]

    severities = [
        s
        for s in SEVERITIES
        if s != "UNKNOWN" or any(v["severity"] == s for v in vulns(unique))
    ]
    head = ["Version", *(s[0] for s in severities), "No fix"]
    lines = ["| " + " | ".join(head) + " |", "|---|" + "---:|" * (len(head) - 1)]

    def counts(rows: Sequence[Mapping[str, Any]]) -> list[str]:
        found = vulns(rows)
        return [
            *(
                count_cell(sum(1 for v in found if v["severity"] == s))
                for s in severities
            ),
            count_cell(sum(1 for v in found if not v["fixed"])),
        ]

    for version, _ in by_version:
        lines.append(
            "| " + " | ".join([cell(version), *counts(version_rows[version])]) + " |"
        )
    lines.append(
        "| " + " | ".join(["**Unique across versions**", *counts(unique)]) + " |"
    )
    return [
        *lines,
        "",
        "Counts are vulnerabilities (one vulnerability under several ids is one) by "
        "their own severity; No fix means no fixed version is known. A vulnerability "
        "of a package present in several versions is counted once in the last row.",
    ]


def version_section(
    version: str,
    rows: Sequence[Mapping[str, Any]],
    columns: Sequence[tuple[str, str]],
) -> list[str]:
    libraries = [r for r in rows if r["class"] == "lang"]
    os_rows = [r for r in rows if r["class"] == "os"]
    lines = [f"## {cell(version)} - {totals(libraries, os_rows)}", ""]
    if libraries:
        lines += ["### Libraries", "", *package_table(libraries, columns, True), ""]
    if os_rows:
        lines += ["### Base image (OS packages)", ""]
        lines += [*package_table(os_rows, columns, False), ""]
    return lines


def results_by_target(report: Mapping[str, Any]) -> list[str]:
    by_id: dict[str, list[Mapping[str, Any]]] = {}
    for t in report["targets"]:
        by_id.setdefault(t["id"], []).append(t)
    lines = [
        "<details><summary>Scan details by target</summary>",
        "",
        "| Target | Type | Version | Scan | Packages scanned |",
        "|---|---|---|---|---:|",
    ]
    for tid, ts in by_id.items():
        trivy = next((t for t in ts if t["scanner"] == "trivy"), ts[0])
        osv = next((t for t in ts if t["scanner"] == "osv"), None)
        ref = trivy["ref"] or "—"
        if trivy["kind"] == "fs" and trivy["commit_sha"]:
            ref = f"{ref}@{trivy['commit_sha'][:7]}"
        packages = (
            "–" if trivy["packages_scanned"] is None else trivy["packages_scanned"]
        )
        kind = "source" if trivy["kind"] == "fs" else "image"
        lines.append(
            f"| {cell(tid)} | {kind} | {cell(ref)} | {cell(scan_status(trivy, osv))} | "
            f"{packages} |"
        )
    return [*lines, "", "</details>"]


def build_summary(report: Mapping[str, Any]) -> str:
    short = report["repo"].split("/")[-1]
    columns, seen = [], set()
    for t in report["targets"]:
        if t["id"] not in seen:
            seen.add(t["id"])
            columns.append((target_label(t, short), t["id"]))
    source_ids = {t["id"] for t in report["targets"] if t["kind"] == "fs"}
    findings = report["findings"]
    by_version = versions_of(report)
    version_rows = {
        version: package_rows([f for f in findings if f["target"] in ids], source_ids)
        for version, ids in by_version
    }
    # a package is one installed version: the rows of the versions, deduplicated
    # (package_rows over all the findings would merge the OS packages of different
    # versions, which it keys without the version)
    unique = {
        (r["class"], norm(r["pkg"]), r["version"]): r
        for rows in reversed(version_rows.values())
        for r in rows
    }.values()
    unique = [*unique]
    lines = header(report) + ["## Versions to fix", ""]
    lines += [*versions_table(report, by_version, version_rows, unique), ""]
    lines += ["## Vulnerabilities by version", ""]
    lines += [*vulnerabilities_table(by_version, version_rows, unique), ""]
    for version, _ in by_version:
        if version_rows[version]:
            lines += version_section(version, version_rows[version], columns)
    lines += [*results_by_target(report), ""]
    lines += [
        "---",
        "Artifact `sca-report`: `report.json` plus native reports in "
        "`_native/trivy/` and `_native/osv/`.",
    ]
    return "\n".join(lines) + "\n"


def truncate_summary(text: str, run_url: str | None) -> str:
    """The summary as the job summary can take it: whole if it fits, else cut at a
    line, with the ``<details>`` the cut leaves open closed and a note on where the
    whole of it is.
    """
    data = text.encode("utf-8")
    if len(data) <= STEP_SUMMARY_LIMIT_BYTES:
        return text
    where = "the `sca-report` artifact of this run"
    if run_url:
        where = f"the `sca-report` artifact of [this run]({run_url})"
    note = (
        f"\n> The summary is cut: it is {len(data)} bytes and a job summary takes "
        f"1 MiB. The whole `summary.md` is in {where}.\n"
    )
    close = "</details>\n"
    room = STEP_SUMMARY_LIMIT_BYTES - len(note.encode("utf-8"))
    while True:
        kept = data[:room].decode("utf-8", errors="ignore")
        kept = kept[: kept.rfind("\n") + 1]
        closing = close * max(kept.count("<details") - kept.count("</details>"), 0)
        if len((kept + closing + note).encode("utf-8")) <= STEP_SUMMARY_LIMIT_BYTES:
            return kept + closing + note
        room -= len(close)
