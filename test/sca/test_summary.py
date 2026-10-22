"""summary.md of the SCA merge."""

import re

import pytest
from summary import (
    STEP_SUMMARY_LIMIT_BYTES,
    build_counts,
    build_summary,
    target_label,
    truncate_summary,
    versions_of,
)


def target(
    tid,
    scanner="trivy",
    kind="fs",
    ref="development",
    status="ok",
    reason=None,
    packages=10,
):
    return {
        "id": tid,
        "scanner": scanner,
        "kind": kind,
        "ref": ref,
        "commit_sha": "0123456789abcdef" if kind == "fs" else None,
        "image": "o/app" if kind == "image" else None,
        "image_digest": None,
        "status": status,
        "reason": reason,
        "packages_scanned": packages if status == "ok" else None,
    }


def finding(
    tid, vid, pkg, severity="HIGH", scanner="trivy", cls="lang", fixed="", **extra
):
    return {
        "target": tid,
        "scanner": scanner,
        "id": vid,
        "aliases": [],
        "pkg": pkg,
        "version": "1.3" if cls == "os" else "1.0",
        "ecosystem": "npm",
        "class": cls,
        "locations": ["web/package-lock.json"] if cls == "lang" else [],
        "severity": severity,
        "fixed_version": fixed,
        "dev": False,
        "relationship": None,
        "chain": [],
        "title": "",
        "url": f"https://example.test/{vid}",
        **extra,
    }


def report(targets, findings):
    return {
        "schema_version": 3,
        "repo": "o/app",
        "commit_sha": "0123456789abcdef",
        "default_branch": "development",
        "run_id": "7",
        "run_url": "https://example.test/run/7",
        "generated_utc": "2026-10-14T00:00:00Z",
        "tools": {
            "trivy": "0.75.0",
            "trivy_db": "2026-10-13T06:41:11.5Z",
            "trivy_java_db": None,
            "osv_scanner": "2.6.0",
            "osv_queried_at": "2026-10-13T11:33:23Z",
        },
        "targets": targets,
        "findings": findings,
    }


def sample():
    src = "source-development"
    lib = {"dev": True}
    targets = [
        target(src),
        target(src, "osv"),
        target("app-1.0", kind="image", ref="1.0", packages=50),
        target(
            "app-1.0",
            "osv",
            kind="image",
            ref="1.0",
            status="failed",
            reason="rate limited",
        ),
        target(
            "app-2.0",
            kind="image",
            ref="2.0",
            status="not_applicable",
            reason="not published",
        ),
    ]
    findings = [
        finding(
            src, "CVE-1", "lib", "CRITICAL", fixed="2.0", chain=["top", "lib"], **lib
        ),
        finding(src, "CVE-2", "lib", "LOW", scanner="osv", fixed="2.1", **lib),
        finding(src, "CVE-1", "lib", "HIGH", scanner="osv", **lib),
        finding(
            src, "CVE-3", "other", "MEDIUM", relationship="direct", chain=["other"]
        ),
        finding("app-1.0", "CVE-3", "other", "MEDIUM"),
        finding("app-1.0", "CVE-4", "zlib", "HIGH", cls="os", fixed="1.4"),
    ]
    return report(targets, findings)


def line(text, prefix):
    return next(row for row in text.splitlines() if row.startswith(prefix))


def table_of(text, heading):
    """The lines of the section ``## heading``."""
    return text.split(f"\n## {heading}\n")[1].split("\n## ")[0]


def vulns_line(text, version):
    return line(table_of(text, "Vulnerabilities"), f"| {version} |")


def packages_line(text, version):
    return line(table_of(text, "Packages to update"), f"| {version} |")


def test_os_rows_of_one_cve_with_differently_spelled_versions_count_once():
    # dpkg: the scanners write the same package's version differently
    # (bash 5.2.37 vs 5.2.37-2+b10), one CVE of one package is one vulnerability
    tid = "app-1.0"
    findings = [
        finding(tid, "CVE-9", "bash", "HIGH", cls="os", fixed="5.2.38", version="5.2.37"),
        finding(
            tid, "CVE-9", "bash", "HIGH", scanner="osv", cls="os",
            fixed="5.2.38-2+b11", version="5.2.37-2+b10",
        ),
    ]
    text = build_summary(report([target(tid, kind="image", ref="1.0")], findings))
    assert packages_line(text, "1.0").endswith("| - | - | - | - | 1 | 1 |")
    # one package row, both scanners on it; the version is Trivy's spelling, the
    # only one shown - both spellings in one cell would read as two installed
    # versions
    row = line(text, "| bash@")
    assert row == (
        "| bash@5.2.37 | H | 5.2.38, 5.2.38-2+b11 | [CVE-9](https://example.test/CVE-9)"
        " | app | T+O |"
    )
    assert "## 1.0 - 0 libraries, 1 OS package, 1 fixable" in text


def test_an_osv_target_ok_with_a_reason_states_it_in_the_scan_column():
    targets = [
        target("app-1.0", kind="image", ref="1.0"),
        target(
            "app-1.0",
            "osv",
            kind="image",
            ref="1.0",
            reason="osv image scan disabled: OS packages not checked by OSV",
        ),
    ]
    text = build_summary(report(targets, []))
    row = line(text, "| app-1.0")
    assert " · OSV ok (osv image scan disabled" in row


@pytest.mark.parametrize(
    "repo, image, label",
    [
        ("ai-dial-chat", "ai-dial-chat-bff", "bff"),
        ("ai-dial-chat", "o/ai-dial-chat", "chat"),
        ("statgpt-backend", "statgpt-admin-backend", "statgpt-admin-backend"),
        ("statgpt-backend", "statgpt-backend", "statgpt-backend"),
    ],
)
def test_an_image_label_is_its_short_name(repo, image, label):
    t = {"kind": "image", "image": image, "ref": "1.0"}
    assert target_label(t, repo) == label


def test_a_source_label_is_src():
    assert target_label({"kind": "fs", "image": None, "ref": "1.0"}, "app") == "src"


def test_packages_differing_in_case_are_one_row_named_as_in_the_source():
    src = "source-development"
    targets = [target(src), target("app-dev", kind="image", ref="development")]
    findings = [
        finding("app-dev", "CVE-1", "PyJWT", severity="HIGH"),
        finding(src, "CVE-1", "pyjwt", scanner="osv", severity="HIGH"),
        finding("app-dev", "CVE-2", "Mako"),
        finding(src, "CVE-3", "mako", severity="LOW"),
    ]
    text = build_summary(report(targets, findings))
    assert "PyJWT@1.0" not in text and "pyjwt@1.0" in text
    assert "Mako@1.0" not in text and text.count("mako@1.0") == 1
    assert "## development - 2 libraries, 0 OS packages, 0 fixable" in text


def test_fixed_versions_of_both_scanners_are_split_and_deduplicated():
    src = "source-development"
    findings = [
        finding(src, "CVE-1", "lib", fixed="2.18.11, 2.21.7, 2.22.3"),
        finding(src, "CVE-1", "lib", scanner="osv", fixed="2.21.7, 2.22.3, 2.18.11"),
    ]
    text = build_summary(report([target(src)], findings))
    assert "| 2.18.11, 2.21.7, 2.22.3 |" in text
    assert "1 library, 0 OS packages, 1 fixable" in text


def test_header_has_the_commit_the_tool_versions_and_the_run():
    text = build_summary(sample())
    header = text.splitlines()[2]
    assert "commit `0123456`" in header and "default branch `development`" in header
    assert "Trivy 0.75.0 (DB 2026-10-13T06:41Z, Java DB n/a)" in header
    assert "osv-scanner 2.6.0 (queried 2026-10-13T11:33:23Z)" in header
    assert "[run 7](https://example.test/run/7)" in header


def test_a_regular_header_names_no_one_offs():
    text = build_summary(report([target("s")], []))
    assert "Focused on tag" not in text
    assert "OSV image scan" not in text


def test_the_header_names_the_focus_run_and_its_tag():
    doc = report([target("s")], [])
    doc["scan_ref"] = "0.22.0"
    text = build_summary(doc)
    assert "Focused on tag `0.22.0`" in text


def test_the_header_names_a_forced_image_scan():
    doc = report([target("s")], [])
    doc["forced_image_scan"] = True
    text = build_summary(doc)
    assert "The direct OSV image scan runs on this run although it is off" in text








def test_where_shows_two_locations_and_the_rest_as_a_count():
    f = finding("s", "CVE-1", "lib", locations=["a/x.lock", "b/x.lock", "c/x.lock"])
    text = build_summary(report([target("s")], [f]))
    assert "| a/x.lock, b/x.lock +1 |" in text


def test_where_prefers_source_lockfiles_to_image_paths():
    findings = [
        finding("img", "CVE-1", "lib", locations=["usr/lib/lib.jar"]),
        finding("s", "CVE-1", "lib", locations=["web/package-lock.json"]),
    ]
    targets = [target("img", kind="image", ref="1.0"), target("s")]
    assert "| web/package-lock.json |" in build_summary(report(targets, findings))






def test_summary_ends_with_the_artifact_footer():
    assert (
        build_summary(sample())
        .rstrip()
        .endswith("`_native/trivy/` and `_native/osv/`.")
    )


def test_a_summary_that_fits_is_not_touched():
    assert truncate_summary("short\n", None) == "short\n"


@pytest.mark.parametrize("run_url", [None, "https://example.test/run/7"])
def test_a_long_summary_is_cut_at_a_line_with_open_blocks_closed_and_a_note(run_url):
    text = "<details><summary>x</summary>\n" + "| row |\n" * (
        STEP_SUMMARY_LIMIT_BYTES // 8
    )
    cut = truncate_summary(text, run_url)
    assert len(cut.encode()) <= STEP_SUMMARY_LIMIT_BYTES
    body, _, note = cut.partition("\n> The summary is cut")
    assert body.rstrip().endswith("</details>")
    assert body.count("<details") == body.count("</details>")
    assert f"it is {len(text.encode())} bytes" in note
    assert (run_url in note) if run_url else "artifact of this run" in note


def test_a_failed_image_without_a_tag_shows_a_marker_not_none():
    t = target("app-release", kind="image", ref=None, status="failed", reason="no tag")
    text = build_summary(report([t, {**t, "scanner": "osv"}], []))
    assert "None" not in text
    assert line(text, "| app-release |").split("|")[3].strip() == "—"


def test_findings_sharing_an_alias_are_one_vulnerability_with_the_cve_shown():
    src = "source-development"
    findings = [
        finding(src, "GHSA-x", "lib", fixed="2.0"),
        finding(
            src, "CVE-2026-9", "lib", scanner="osv", fixed="2.1", aliases=["GHSA-x"]
        ),
    ]
    text = build_summary(report([target(src), target(src, "osv")], findings))
    assert "1 library, 0 OS packages, 1 fixable" in text
    assert "CVE-2026-9" in text and "GHSA-x" not in text


def test_the_cut_leaves_room_for_every_block_it_closes():
    text = "<details><summary>x</summary>\n" * 5 + "| row |\n" * (
        STEP_SUMMARY_LIMIT_BYTES // 8
    )
    cut = truncate_summary(text, None)
    assert len(cut.encode()) <= STEP_SUMMARY_LIMIT_BYTES
    assert cut.count("<details") == cut.count("</details>") == 5



def rows_of(text, version):
    """The package rows of a version section, in order, without the table head."""
    section = text.split(f"\n## {version} - ")[1].split("\n## ")[0]
    section = section.split("<details><summary>Scan details")[0]
    rows = [r for r in section.splitlines() if r.startswith("| ") and "---" not in r]
    return [r for r in rows if not r.startswith("| Package@version")]


def two_versions():
    """A source and two images of 1.2.9 (tag v1.2.9 in git, 1.2.9 in the registry),
    the source of 1.1.15 and development; braces is in both releases."""
    targets = [
        target("source-development"),
        target("source-1.2.9", ref="v1.2.9"),
        target("source-1.1.15", ref="1.1.15"),
        target("app-1.2.9", kind="image", ref="1.2.9"),
        {**target("app-bff-1.2.9", kind="image", ref="1.2.9"), "image": "o/app-bff"},
    ]
    findings = [
        finding("source-1.2.9", "CVE-1", "braces"),
        finding("source-1.1.15", "CVE-1", "braces"),
        finding("source-1.2.9", "CVE-2", "sanitize", "MEDIUM", fixed="2.0"),
        finding("app-1.2.9", "CVE-2", "sanitize", "MEDIUM", fixed="2.0"),
        finding("app-bff-1.2.9", "CVE-2", "sanitize", "MEDIUM", fixed="2.0"),
        finding("source-1.1.15", "CVE-3", "other", "LOW", fixed="2.0"),
    ]
    return report(targets, findings)


def test_a_git_tag_with_v_and_a_registry_tag_are_one_version():
    assert versions_of(two_versions()) == [
        ("development", {"source-development"}),
        ("1.2.9", {"source-1.2.9", "app-1.2.9", "app-bff-1.2.9"}),
        ("1.1.15", {"source-1.1.15"}),
    ]


def test_versions_go_development_first_then_newest_then_unparsable_by_name():
    refs = ["1.9.0", "master", "1.10.0", "development", "1.10.0-rc.1", "v2.0.0", "abc"]
    doc = report([target(f"s{i}", ref=r) for i, r in enumerate(refs)], [])
    assert [v for v, _ in versions_of(doc)] == [
        "development",
        "2.0.0",
        "1.10.0",
        "1.10.0-rc.1",
        "1.9.0",
        "abc",
        "master",
    ]


def test_a_package_of_the_source_and_the_images_of_a_version_is_one_row():
    text = build_summary(two_versions())
    rows = rows_of(text, "1.2.9")
    assert len(rows) == 2
    sanitize = next(r for r in rows if r.startswith("| sanitize@1.0"))
    assert "| src, app, bff |" in sanitize
    # the other release is a section of its own, with its own row of braces
    assert "| src |" in line(text, "| braces@1.0 ")


def test_the_top_table_counts_packages_by_their_worst_severity_not_vulnerabilities():
    src = "source-1.0"
    findings = [
        finding(src, "CVE-1", "vite", "MEDIUM", fixed="2"),
        finding(src, "CVE-2", "vite", "HIGH", fixed="2"),
        finding(src, "CVE-3", "vite", "LOW", fixed="2"),
    ]
    text = build_summary(report([target(src, ref="1.0")], findings))
    assert packages_line(text, "1.0") == (
        "| 1.0 | ok (source) | - | 1 | - | - | - | 1 |"
    )
    assert vulns_line(text, "1.0") == "| 1.0 | - | 1 | 1 | 1 | 3 |"
    assert "## 1.0 - 1 library, 0 OS packages, 1 fixable" in text


def test_unique_across_versions_counts_a_package_of_two_versions_once():
    text = build_summary(two_versions())
    # braces (H, no fix) is in both releases; the rows add up to 2 H, the line says 1
    assert packages_line(text, "1.2.9").endswith("| - | 1 | 1 | - | - | 1 |")
    assert packages_line(text, "1.1.15").endswith("| - | 1 | - | 1 | - | 1 |")
    assert packages_line(text, "**All (unique)**") == (
        "| **All (unique)** |  | - | 1 | 1 | 1 | - | 2 |"
    )
    assert "a package in several branches/tags is counted once" in text


def test_a_package_is_without_a_fix_when_none_of_its_vulnerabilities_has_one():
    src = "source-1.0"
    findings = [
        finding(src, "CVE-1", "none"),
        finding(src, "CVE-2", "mixed"),
        finding(src, "CVE-3", "mixed", fixed="3.1"),
        finding(src, "CVE-4", "mixed", fixed="3.0"),
    ]
    text = build_summary(report([target(src, ref="1.0")], findings))
    assert "| none@1.0 | H | no fix |" in text
    # a mixed package is fixable: it shows the versions that fix its vulnerabilities
    assert "| mixed@1.0 | H | 3.1, 3.0 |" in text
    assert "2 libraries, 0 OS packages, 1 fixable" in text


def test_rows_go_fixable_then_dev_then_without_a_fix_by_severity_then_name():
    src = "source-1.0"
    dev = {"dev": True}
    findings = [
        finding(src, "C1", "z-nofix-crit", "CRITICAL"),
        finding(src, "C2", "a-nofix-low", "LOW"),
        finding(src, "C3", "dev-nofix", "CRITICAL", **dev),
        finding(src, "C4", "dev-fix-high", "HIGH", fixed="2", **dev),
        finding(src, "C5", "dev-fix-crit", "CRITICAL", fixed="2", **dev),
        finding(src, "C6", "fix-med", "MEDIUM", fixed="2"),
        finding(src, "C7", "fix-high-b", "HIGH", fixed="2"),
        finding(src, "C8", "fix-high-a", "HIGH", fixed="2"),
    ]
    text = build_summary(report([target(src, ref="1.0")], findings))
    names = [r.split("@")[0].removeprefix("| ") for r in rows_of(text, "1.0")]
    assert names == [
        "fix-high-a",
        "fix-high-b",
        "fix-med",
        "dev-fix-crit",
        "dev-fix-high",
        "z-nofix-crit",
        "a-nofix-low",
        "dev-nofix",
    ]
    assert "| dev-fix-crit@1.0 `dev` | C |" in text
    assert "`dev`" not in line(text, "| fix-med@")


def test_a_failed_image_without_a_tag_is_in_no_version():
    failed = target("app-release", kind="image", ref=None, status="failed")
    doc = report([target("source-1.0", ref="1.0"), failed], [])
    assert [v for v, _ in versions_of(doc)] == ["1.0"]
    assert "None" not in build_summary(doc)






def test_the_per_target_table_is_collapsed_and_has_no_counts():
    text = build_summary(sample())
    assert "<details><summary>Scan details by target</summary>" in text
    assert "| Target | Type | Version | Scan | Packages scanned |" in text
    assert line(text, "| app-1.0 |") == (
        "| app-1.0 | image | 1.0 | ok · OSV failed: rate limited | 50 |"
    )
    assert line(text, "| app-2.0 |") == (
        "| app-2.0 | image | 2.0 | not_applicable (not published) | – |"
    )


def test_a_run_without_findings_has_tables_of_dashes_and_no_sections():
    text = build_summary(report([target("s")], []))
    assert vulns_line(text, "development") == "| development | - | - | - | - | - |"
    assert packages_line(text, "development") == (
        "| development | ok (source) | - | - | - | - | - | - |"
    )
    assert packages_line(text, "**All (unique)**") == (
        "| **All (unique)** |  | - | - | - | - | - | - |"
    )
    assert "\n## development - " not in text


def test_the_scan_column_says_what_was_scanned_and_what_failed():
    text = build_summary(sample())
    assert packages_line(text, "1.0").startswith(
        "| 1.0 | failed (1 image, 1 OSV failed) |"
    )
    assert packages_line(text, "2.0").startswith("| 2.0 | ok (1 n/a) |")


def test_the_vulnerabilities_table_comes_first_with_its_headings_and_note():
    text = build_summary(sample())
    assert text.index("\n## Vulnerabilities\n") < text.index("\n## Packages to update\n")
    assert "| Branch / tag | Critical | High | Medium | Low | Fixable |" in text
    assert (
        "| Branch / tag | Scan | Critical | High | Medium | Low | OS packages | Fixable |"
        in text
    )
    assert (
        "Each vulnerability counted once per row; one present in several "
        "branches/tags is counted once in the last row." in text
    )
    assert (
        "Vulnerable libraries by worst severity; a package in several branches/tags "
        "is counted once in the last row." in text
    )


def test_only_the_two_tables_and_the_headings_are_visible():
    text = build_summary(sample())
    assert "open" not in "".join(re.findall(r"<details[^>]*>", text))
    release = text.split("\n## 1.0 - ")[1].split("\n## ")[0]
    assert "<details><summary>Libraries</summary>" in release
    assert "<details><summary>Base image (OS packages)</summary>" in release
    # outside the collapsed blocks there are only headings, the two tables and notes
    outside = re.sub(r"<details>.*?</details>", "", text, flags=re.S)
    assert "Package@version" not in outside and "| Target |" not in outside


def test_the_vulnerabilities_table_counts_vulnerabilities_by_their_own_severity():
    src = "source-1.0"
    findings = [
        finding(src, "CVE-1", "vite", "MEDIUM", fixed="2"),
        finding(src, "CVE-2", "vite", "HIGH"),
        finding(src, "CVE-3", "vite", "LOW", fixed="2"),
        # one vulnerability under two ids, seen by both scanners
        finding(src, "GHSA-x", "lib", "LOW", scanner="osv", aliases=["CVE-4"]),
        finding(src, "CVE-4", "lib", "LOW"),
    ]
    text = build_summary(report([target(src, ref="1.0")], findings))
    assert vulns_line(text, "1.0") == "| 1.0 | - | 1 | 1 | 2 | 2 |"
    assert vulns_line(text, "**All (unique)**") == "| **All (unique)** | - | 1 | 1 | 2 | 2 |"


def test_a_vulnerability_of_two_versions_is_counted_once_in_the_last_row():
    text = build_summary(two_versions())
    assert vulns_line(text, "1.2.9") == "| 1.2.9 | - | 1 | 1 | - | 1 |"
    assert vulns_line(text, "1.1.15") == "| 1.1.15 | - | 1 | - | 1 | 1 |"
    assert vulns_line(text, "**All (unique)**") == (
        "| **All (unique)** | - | 1 | 1 | 1 | 2 |"
    )


def test_a_vulnerability_of_an_os_package_in_two_versions_is_one():
    # the installed versions differ (1.3, 1.2), the vulnerability is the same
    targets = [
        target("app-2.0", kind="image", ref="2.0"),
        target("app-1.0", kind="image", ref="1.0"),
    ]
    findings = [
        finding("app-2.0", "CVE-1", "zlib", cls="os", fixed="1.4", version="1.3"),
        finding("app-1.0", "CVE-1", "zlib", cls="os", fixed="1.4", version="1.2"),
        finding("app-1.0", "CVE-2", "zlib", cls="os", version="1.2"),
    ]
    text = build_summary(report(targets, findings))
    assert vulns_line(text, "2.0").endswith("| - | 1 | - | - | 1 |")
    assert vulns_line(text, "1.0").endswith("| - | 2 | - | - | 1 |")
    assert vulns_line(text, "**All (unique)**").endswith("| - | 2 | - | - | 1 |")


def test_the_last_row_of_the_vulnerabilities_table_is_counts_total_of_report_json():
    doc = two_versions()
    doc["counts"] = build_counts(doc)
    total = doc["counts"]["total"]
    row = vulns_line(build_summary(doc), "**All (unique)**").strip("|").split("|")[1:]
    shown = [c.strip() for c in row]
    by = total["by_severity"]
    expected = [by[s]["all"] or "-" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")]
    expected.append(total["fixable"] or "-")
    assert shown == [str(e) for e in expected]
