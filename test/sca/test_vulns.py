"""versions[] of report.json: statuses, vulnerability records and counts."""

import pytest
from merge_results import engine_ref
from test_summary import finding, report, sample, target, two_versions
from vulns import (
    build_versions,
    components,
    is_release,
    version_kind,
    versions_of,
)

SEVS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def vulns_of(doc, ref):
    return next(v for v in build_versions(doc) if v["ref"] == ref)["vulns"]


def keys(vulns):
    return [(v["class"], v["pkg"], v["id"]) for v in vulns]


def osv_os(tid, vid, pkg, names=None, **extra):
    names = names or [vid]
    return finding(
        tid, vid, pkg, "UNKNOWN", scanner="osv", cls="os", names=names, **extra
    )


# --- order, kind, latest ---


def test_versions_follow_versions_of_order_and_name():
    rep = two_versions()
    versions = build_versions(rep)
    assert [r["ref"] for r in versions] == [v for v, _ in versions_of(rep)]
    assert versions[1]["targets"] == ["app-1.2.9", "app-bff-1.2.9", "source-1.2.9"]


def test_kind_is_development_candidate_or_release():
    refs = ["development", "0.50.0-rc.1", "1.2.0", "v2.0.0"]
    doc = report([target(f"s{i}", ref=r) for i, r in enumerate(refs)], [])
    kinds = {r["ref"]: r["kind"] for r in build_versions(doc)}
    assert kinds["development"] == "development"
    assert kinds["0.50.0-rc.1"] == "candidate"
    assert kinds["1.2.0"] == "release"
    assert kinds["2.0.0"] == "release"


def test_the_default_branch_is_development_kind_even_when_not_named_development():
    doc = report([target("s", ref="main")], [])
    doc["default_branch"] = "main"
    (record,) = build_versions(doc)
    assert record["kind"] == version_kind("main", "main") == "development"
    assert not is_release("main", "main")


def test_exactly_one_latest_the_newest_release():
    latest = [r for r in build_versions(two_versions()) if r["latest"]]
    assert [r["ref"] for r in latest] == ["1.2.9"]


def test_no_latest_without_a_release_and_for_a_non_semver_tag():
    doc = report([target("s0", ref="development"), target("s1", ref="0.1.0-rc.1")], [])
    assert not any(r["latest"] for r in build_versions(doc))
    doc = report([target("s0", ref="development"), target("s1", ref="nightly")], [])
    assert not any(r["latest"] for r in build_versions(doc))


def test_latest_skips_a_failed_release():
    targets = [
        target("source-2.0", ref="2.0", status="failed", reason="x"),
        target("source-1.0", ref="1.0"),
    ]
    records = {r["ref"]: r for r in build_versions(report(targets, []))}
    assert records["2.0"]["latest"] is False and records["1.0"]["latest"] is True


# --- status ---


def status_of(*targets):
    (record,) = build_versions(report(list(targets), []))
    return record["status"]


@pytest.mark.parametrize(
    "trivy, osv, expected",
    [
        (("failed", "x"), ("not_applicable", "trivy target failed"), "failed"),
        (("not_applicable", "x"), ("not_applicable", "x"), "ok"),
        (("ok", None), ("failed", "x"), "failed"),
        (("ok", None), ("ok", None), "ok"),
    ],
)
def test_status_of_a_version(trivy, osv, expected):
    got = status_of(
        target("i", kind="image", ref="1.0", status=trivy[0], reason=trivy[1]),
        target("i", "osv", kind="image", ref="1.0", status=osv[0], reason=osv[1]),
    )
    assert got == expected


def test_a_not_applicable_image_does_not_fail_a_version_of_an_ok_source():
    assert (
        status_of(
            target("source-1.0", ref="1.0"),
            target("img-1.0", kind="image", ref="1.0", status="not_applicable"),
        )
        == "ok"
    )


def test_a_failed_version_keeps_the_records_of_its_ok_targets():
    targets = [
        target("source-1.0", ref="1.0"),
        target("img-1.0", kind="image", ref="1.0", status="failed", reason="x"),
    ]
    doc = report(targets, [finding("source-1.0", "CVE-1", "lib", fixed="2")])
    (record,) = build_versions(doc)
    assert record["status"] == "failed"
    assert record["counts"] == {
        "c": 0,
        "h": 1,
        "m": 0,
        "l": 0,
        "unknown": 0,
        "all": 1,
        "fixable": 1,
    }
    assert keys(record["vulns"]) == [("lang", "lib", "CVE-1")]


def test_the_sample_versions_with_failed_scans_are_failed():
    statuses = {r["ref"]: r["status"] for r in build_versions(sample())}
    assert statuses["1.0"] == "failed" and statuses["development"] == "ok"
    assert statuses["2.0"] == "ok"  # its only image is not_applicable


# --- components ---


def test_os_package_cves_of_both_scanners_make_one_record_each():
    t = "img-1.0"
    findings = [
        finding(t, "CVE-A", "libblkid1", "MEDIUM", cls="os"),
        finding(t, "CVE-B", "libblkid1", "MEDIUM", cls="os"),
        osv_os(t, "CVE-A", "libblkid1"),
        osv_os(t, "CVE-B", "libblkid1"),
    ]
    doc = report([target(t, kind="image", ref="1.0")], findings)
    vulns = vulns_of(doc, "1.0")
    assert [(v["id"], v["severity"], v["sources"]) for v in vulns] == [
        ("CVE-A", "MEDIUM", ["trivy", "osv"]),
        ("CVE-B", "MEDIUM", ["trivy", "osv"]),
    ]


def osv_lang(tid, vid, names, severity="HIGH"):
    return finding(tid, vid, "lib", severity, scanner="osv", names=names)


def test_a_lang_record_keeps_its_key_when_trivy_learns_the_cve():
    t = "source-development"
    day1 = report([target(t)], [osv_lang(t, "CVE-X", ["CVE-X", "GHSA-1"])])
    (v1,) = vulns_of(day1, "development")
    assert (v1["id"], v1["names"], v1["sources"]) == (
        "CVE-X",
        ["CVE-X", "GHSA-1"],
        ["osv"],
    )
    day2 = report(
        [target(t)],
        [osv_lang(t, "CVE-X", ["CVE-X", "GHSA-1"]), finding(t, "CVE-X", "lib")],
    )
    (v2,) = vulns_of(day2, "development")
    assert (v2["id"], v2["sources"]) == ("CVE-X", ["trivy", "osv"])


def test_a_trivy_ghsa_and_an_osv_cve_with_the_ghsa_name_are_one_record():
    t = "source-development"
    findings = [
        finding(t, "GHSA-1", "lib", "MEDIUM"),
        osv_lang(t, "CVE-X", ["CVE-X", "GHSA-1"]),
    ]
    (v,) = vulns_of(report([target(t)], findings), "development")
    assert v["id"] == "CVE-X" and v["names"] == ["CVE-X", "GHSA-1"]
    assert v["severity"] == "MEDIUM"  # Trivy's


def test_two_cves_of_an_osv_group_join_the_trivy_rows_of_each():
    t = "source-development"
    findings = [
        finding(t, "CVE-2", "lib"),
        finding(t, "CVE-1", "lib"),
        osv_lang(t, "CVE-1", ["CVE-1", "CVE-2", "GHSA-1"]),
    ]
    (v,) = vulns_of(report([target(t)], findings), "development")
    assert v["id"] == "CVE-1" and v["names"] == ["CVE-1", "CVE-2", "GHSA-1"]


def test_components_do_not_depend_on_the_order_of_the_findings():
    t = "s"
    findings = [
        finding(t, "CVE-2", "lib", names=["CVE-2"]),
        finding(t, "CVE-1", "lib", names=["CVE-1"]),
        finding(t, "GHSA-1", "lib", names=["CVE-1", "CVE-2", "GHSA-1"]),
        finding(t, "CVE-9", "lib", names=["CVE-9"]),
    ]

    def partition(fs):
        return sorted(sorted(f["id"] for f in c) for c in components(fs))

    expected = [["CVE-1", "CVE-2", "GHSA-1"], ["CVE-9"]]
    assert partition(findings) == partition(findings[::-1]) == expected
    assert partition(findings[1:] + findings[:1]) == expected


def test_an_osv_only_component_takes_the_worst_osv_severity():
    t = "source-development"
    findings = [
        osv_lang(t, "GHSA-1", ["GHSA-1", "GHSA-2"], "MEDIUM"),
        osv_lang(t, "GHSA-2", ["GHSA-2", "GHSA-1"], "HIGH"),
    ]
    (v,) = vulns_of(report([target(t)], findings), "development")
    assert v["severity"] == "HIGH" and v["sources"] == ["osv"]


def test_without_a_cve_the_id_is_the_smallest_id():
    t = "source-development"
    findings = [
        finding(t, "GHSA-2", "lib", "MEDIUM"),
        osv_lang(t, "GHSA-1", ["GHSA-1", "GHSA-2"]),
    ]
    (v,) = vulns_of(report([target(t)], findings), "development")
    assert v["id"] == "GHSA-1" and v["names"] == ["GHSA-1", "GHSA-2"]


def test_two_images_of_two_distros_make_one_record_with_the_worst_severity():
    targets = [
        target("deb-1.0", kind="image", ref="1.0"),
        target("alp-1.0", kind="image", ref="1.0"),
    ]
    findings = [
        finding("deb-1.0", "CVE-1", "libexpat", "MEDIUM", cls="os", version="2.7.1-1"),
        finding("alp-1.0", "CVE-1", "libexpat", "HIGH", cls="os", version="2.7.1-r0"),
    ]
    (v,) = vulns_of(report(targets, findings), "1.0")
    assert v["severity"] == "HIGH"
    assert v["installed"] == ["2.7.1-1", "2.7.1-r0"]
    assert v["where"] == ["alp-1.0", "deb-1.0"]


def test_a_bulletin_only_finding_is_its_own_unknown_osv_record():
    t = "img-1.0"
    findings = [osv_os(t, "USN-1", "libx"), finding(t, "CVE-1", "libx", cls="os")]
    doc = report([target(t, kind="image", ref="1.0")], findings)
    by_id = {v["id"]: v for v in vulns_of(doc, "1.0")}
    assert (by_id["USN-1"]["severity"], by_id["USN-1"]["sources"]) == (
        "UNKNOWN",
        ["osv"],
    )
    assert by_id["CVE-1"]["sources"] == ["trivy"]


def test_the_same_cve_under_lang_and_os_is_two_records():
    targets = [
        target("source-1.0", ref="1.0"),
        target("img-1.0", kind="image", ref="1.0"),
    ]
    findings = [
        finding("source-1.0", "CVE-1", "zlib"),
        finding("img-1.0", "CVE-1", "zlib", cls="os"),
    ]
    vulns = vulns_of(report(targets, findings), "1.0")
    assert keys(vulns) == [("lang", "zlib", "CVE-1"), ("os", "zlib", "CVE-1")]


# --- fields ---


def test_fixed_published_dev_and_pkg_fields():
    targets = [
        target("source-1.0", ref="1.0"),
        target("img-1.0", kind="image", ref="1.0"),
    ]
    findings = [
        finding(
            "img-1.0",
            "CVE-1",
            "Foo_Bar",
            fixed="2, 3",
            published="2026-02-02",
            dev=True,
        ),
        finding(
            "source-1.0",
            "CVE-1",
            "foo-bar",
            fixed="3",
            published="2026-01-01",
            dev=True,
        ),
        finding(
            "source-1.0",
            "CVE-1",
            "foo.bar",
            scanner="osv",
            fixed="4, 2",
            published=None,
            dev=True,
        ),
    ]
    (v,) = vulns_of(report(targets, findings), "1.0")
    assert v["pkg"] == "foo-bar"  # as written in the source target, Trivy's first
    assert v["fixed"] == "2, 3, 4"
    assert v["published"] == "2026-01-01"
    assert v["dev"] is True and v["accepted"] is None
    findings[0]["dev"] = False
    (v,) = vulns_of(report(targets, findings), "1.0")
    assert v["dev"] is False


def test_a_record_without_a_fix_or_date():
    t = "source-1.0"
    (v,) = vulns_of(report([target(t, ref="1.0")], [finding(t, "CVE-1", "lib")]), "1.0")
    assert v["fixed"] == "" and v["published"] is None


def test_the_records_are_sorted_by_class_package_and_id():
    t = "source-1.0"
    findings = [
        finding(t, "CVE-2", "b"),
        finding(t, "CVE-9", "A"),
        finding(t, "CVE-1", "b"),
    ]
    vulns = vulns_of(report([target(t, ref="1.0")], findings), "1.0")
    assert [v["id"] for v in vulns] == ["CVE-9", "CVE-1", "CVE-2"]


# --- counts ---


def test_counts_match_the_records_per_severity():
    for record in build_versions(two_versions()):
        vulns = record["vulns"]
        counts = record["counts"]
        by = [sum(v["severity"] == s for v in vulns) for s in SEVS]
        assert [counts[k] for k in ("c", "h", "m", "l", "unknown")] == by
        assert counts["all"] == len(vulns)
        assert counts["fixable"] == sum(bool(v["fixed"]) for v in vulns)


def test_the_counts_of_the_sample_versions_are_pinned():
    records = {r["ref"]: r for r in build_versions(two_versions())}
    new, old = records["1.2.9"]["counts"], records["1.1.15"]["counts"]
    assert (new["h"], new["m"], new["fixable"]) == (1, 1, 1)
    assert (old["h"], old["l"]) == (1, 1)


# --- header ---


@pytest.mark.parametrize(
    "path, ref",
    [
        ("/w/_actions/epam/ai-dial-sec-sca/v0.7.0/actions/m", "v0.7.0"),
        ("/w/_actions/epam/ai-dial-sec-sca/feat/x/actions/m", "feat/x"),
        ("/w/_actions/epam/ai-dial-sec-sca/actions/m", None),
        (r"D:\a\_actions\epam\ai-dial-sec-sca\main\actions\m", "main"),
        ("/home/me/ai-dial-sec-sca/actions/sca_merge_results", None),
        ("", None),
        (None, None),
    ],
)
def test_engine_ref(path, ref):
    assert engine_ref(path) == ref
