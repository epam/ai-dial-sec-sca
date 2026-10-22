"""The counts block of report.json: severity and fixability, from the summary's rows."""

from merge_results import SCHEMA_VERSION
from summary import build_counts, package_rows
from test_summary import finding, report, sample, target

SEVS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def zero():
    return {"all": 0, "fixable": 0}


def shape(by_severity=None, **overall):
    """An expected block: the severities given, the rest zero."""
    by = {s: zero() for s in SEVS}
    for s, (n, m) in (by_severity or {}).items():
        by[s] = {"all": n, "fixable": m}
    return {
        "all": sum(v["all"] for v in by.values()),
        "fixable": sum(v["fixable"] for v in by.values()),
        "by_severity": by,
        **overall,
    }


def test_schema_version_is_bumped():
    assert SCHEMA_VERSION == 3


def test_empty_report_has_zero_counts():
    counts = build_counts(report([target("src")], []))
    assert counts == {"total": shape(), "targets": {"src": shape(status="ok")}}


def test_no_targets_no_findings():
    assert build_counts(report([], [])) == {"total": shape(), "targets": {}}


def test_mixed_severities_and_fixability():
    findings = [
        finding("src", "CVE-1", "a", "CRITICAL", fixed="2"),
        finding("src", "CVE-2", "b", "HIGH"),
        finding("src", "CVE-3", "c", "HIGH", fixed="3"),
        finding("src", "CVE-4", "d", "MEDIUM"),
        finding("src", "CVE-5", "e", "LOW", fixed="1"),
        finding("src", "CVE-6", "f", "UNKNOWN"),
    ]
    counts = build_counts(report([target("src")], findings))
    expected = shape(
        {
            "CRITICAL": (1, 1),
            "HIGH": (2, 1),
            "MEDIUM": (1, 0),
            "LOW": (1, 1),
            "UNKNOWN": (1, 0),
        }
    )
    assert counts["total"] == expected
    assert counts["total"]["all"] == 6 and counts["total"]["fixable"] == 3
    assert counts["targets"]["src"] == {**expected, "status": "ok"}


def test_fixable_is_a_known_fixed_version_on_any_scanner():
    # the same vulnerability: Trivy knows no fix, OSV does - the summary's rule is a
    # fixed version known to either, so it is fixable
    findings = [
        finding("src", "CVE-1", "a", "HIGH"),
        finding("src", "CVE-1", "a", "HIGH", scanner="osv", fixed="2"),
    ]
    counts = build_counts(report([target("src")], findings))
    assert counts["total"]["by_severity"]["HIGH"] == {"all": 1, "fixable": 1}


def test_trivy_severity_wins_over_osv():
    findings = [
        finding("src", "CVE-1", "a", "LOW", scanner="osv"),
        finding("src", "CVE-1", "a", "CRITICAL"),
    ]
    by = build_counts(report([target("src")], findings))["total"]["by_severity"]
    assert by["CRITICAL"]["all"] == 1 and by["LOW"]["all"] == 0


def test_duplicate_across_targets_counts_once_in_total_each_in_target():
    targets = [target("src"), target("img", kind="image", ref="1.0")]
    findings = [
        finding("src", "CVE-1", "a", "HIGH", fixed="2"),
        finding("img", "CVE-1", "a", "HIGH", fixed="2"),
        finding("img", "CVE-2", "z", "HIGH", cls="os"),
    ]
    counts = build_counts(report(targets, findings))
    assert counts["total"] == shape({"HIGH": (2, 1)})
    assert counts["targets"]["src"] == shape({"HIGH": (1, 1)}, status="ok")
    assert counts["targets"]["img"] == shape({"HIGH": (2, 1)}, status="ok")


def test_same_cve_in_another_package_is_another_vulnerability():
    findings = [
        finding("src", "CVE-1", "a", "HIGH"),
        finding("src", "CVE-1", "b", "HIGH"),
    ]
    counts = build_counts(report([target("src")], findings))
    assert counts["total"]["all"] == 2


def test_total_matches_the_summary_rows():
    rep = sample()
    counts = build_counts(rep)
    rows = package_rows(rep["findings"], {"source-development"})
    vulns = [v for r in rows for v in r["vulns"]]
    assert counts["total"]["all"] == len(vulns)
    assert counts["total"]["fixable"] == sum(1 for v in vulns if v["fixed"])


def test_failed_and_not_applicable_targets_are_listed_with_status_only():
    rep = sample()
    targets = counts_targets = build_counts(rep)["targets"]
    assert targets["app-1.0"]["status"] == "ok"  # the Trivy scan decides
    assert targets["app-2.0"] == {"status": "not_applicable"}
    failed = report(
        [target("img", kind="image", status="failed", reason="boom")],
        [],
    )
    assert build_counts(failed)["targets"] == {"img": {"status": "failed"}}
    assert counts_targets["source-development"]["status"] == "ok"


def test_findings_of_a_failed_target_do_not_leak_into_total_of_others():
    targets = [
        target("src"),
        target("img", kind="image", status="failed", reason="x"),
    ]
    findings = [finding("src", "CVE-1", "a", "HIGH")]
    counts = build_counts(report(targets, findings))
    assert counts["total"]["all"] == 1
    assert counts["targets"]["img"] == {"status": "failed"}
