"""``upgrade_target``: the public wrapper of the planner's target rule."""

import json
from pathlib import Path

import pytest
from sca import plan as sca_fix_plan
from cases import CASES, load_case
from helpers import record
from sca.plan import Config, build_plan, merge_reports, upgrade_target


def test_exported() -> None:
    assert "upgrade_target" in sca_fix_plan.__all__


def test_same_major_preferred() -> None:
    rec = record("lib", "1.0.0", "1.0.5, 2.0.0")
    assert upgrade_target("1.0.0", [rec]) == (
        "1.0.5",
        "lowest fixed version in the same major",
        None,
    )


def test_not_a_downgrade() -> None:
    # the first fixed version of one record is below the installed one
    rec = record("lib", "2.21.7", "2.18.11, 2.21.8")
    target, _, code = upgrade_target("2.21.7", [rec])
    assert (target, code) == ("2.21.8", None)


def test_highest_requirement_over_records() -> None:
    recs = [record("lib", "1.0.0", "1.0.5"), record("lib", "1.0.0", "1.1.2", id="B")]
    assert upgrade_target("1.0.0", recs)[0] == "1.1.2"


def test_development_evidence_preferred() -> None:
    rec = record("lib", "1.0.0", "1.0.5")
    assert upgrade_target("1.0.0", [rec], ["1.0.9"]) == (
        "1.0.9",
        "development runs 1.0.9",
        None,
    )
    assert upgrade_target("1.0.0", [rec], ["1.0.2"])[0] == "1.0.5"


def test_dev_version_of_another_major() -> None:
    rec = record("lib", "1.0.0", "1.0.5, 3.0.0")
    assert upgrade_target("1.0.0", [rec], ["3.0.0"])[0] == "1.0.5"
    assert upgrade_target("1.0.0", [rec], ["3.0.0"], "dev-proven")[0] == "3.0.0"


def test_needs_major() -> None:
    rec = record("lib", "1.0.0", "2.0.0")
    assert upgrade_target("1.0.0", [rec]) == (
        None,
        "fix needs another major (2.0.0), no development evidence",
        "needs_major",
    )


def test_no_fixed_version() -> None:
    assert upgrade_target("1.0.0", [record("lib", "1.0.0", "")]) == (
        None,
        "no fixed version above 1.0.0",
        "no_fixed_version",
    )
    assert upgrade_target("1.0.0", [record("lib", "1.0.0", "0.9.0")])[2] == (
        "no_fixed_version"
    )


def test_unparsable_is_returned_not_raised() -> None:
    rec = record("lib", "1.2-3ubuntu1", "1.2-4ubuntu1")
    target, text, code = upgrade_target("1.2-3ubuntu1", [rec])
    assert target is None
    assert code == "version_unparsable"
    assert text.startswith("cannot compare versions")


def test_unknown_allow_major() -> None:
    with pytest.raises(ValueError):
        upgrade_target("1.0.0", [], allow_major="any")


def test_result_is_json_serialisable() -> None:
    rec = record("lib", "1.0.0", "1.0.5")
    json.dumps(upgrade_target("1.0.0", [rec], ["1.0.9"]))


def compare_with_plan(case: str, allow_major: str) -> int:
    """Check every library target of the plan of a case against ``upgrade_target``
    and return how many were checked.
    """
    docs = [json.loads(Path(p).read_text(encoding="utf-8")) for p in load_case(case)]
    reports = merge_reports(docs)
    plan = build_plan(reports, Config(allow_major=allow_major))
    versions = {v.ref: v for v in reports.versions}
    dev = next(v for v in reports.versions if v.kind == "development")
    compared = 0
    for line in plan["lines"]:
        version = versions[line["ref"]]
        for item in line["items"]:
            if item["class"] == "os" or not item["targets"]:
                continue
            ids = {v["id"] for v in item["vulns"]}
            records = [
                r
                for r in version.vulns
                if r["pkg"] == item["pkg"]
                and r["class"] == item["class"]
                and r["id"] in ids
            ]
            dev_versions = [
                x
                for p in dev.packages
                if p["pkg"] == item["pkg"] and p["class"] == item["class"]
                for x in p["installed"]
            ]
            for entry in item["targets"]:
                target, text, _ = upgrade_target(
                    entry["installed"], records, dev_versions, allow_major
                )
                assert target == entry["target"], (case, item["pkg"])
                if target:
                    assert text == entry["evidence"], (case, item["pkg"])
                compared += 1
    return compared


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("allow_major", ["none", "dev-proven"])
def test_agrees_with_build_plan_on_real_fixtures(case: str, allow_major: str) -> None:
    compare_with_plan(case, allow_major)


def test_real_fixtures_give_targets_to_compare() -> None:
    assert sum(compare_with_plan(c, "dev-proven") for c in CASES) >= 10


def test_rv1_a_candidate_must_be_safe_for_every_record() -> None:
    # A is fixed on two branches, B in 2.20.0: 2.20.0 is still vulnerable to A
    a = record("lib", "2.18.0", "2.18.11, 2.21.3", id="A")
    b = record("lib", "2.18.0", "2.20.0", id="B")
    assert upgrade_target("2.18.0", [a, b])[0] == "2.21.3"
    # a development version is proven by development's own scan, not by the list
    assert upgrade_target("2.18.0", [a, b], ["2.20.0", "2.22.0"]) == (
        "2.20.0",
        "development runs 2.20.0",
        None,
    )


def test_rv1_a_fixed_version_of_the_branch_of_the_candidate_is_safe() -> None:
    a = record("lib", "2.18.0", "2.18.11, 2.21.3", id="A")
    assert upgrade_target("2.18.0", [a])[0] == "2.18.11"
    b = record("lib", "2.18.0", "2.18.5", id="B")
    assert upgrade_target("2.18.0", [a, b])[0] == "2.18.11"
    assert upgrade_target("2.18.0", [a, b], ["2.18.12"])[0] == "2.18.12"
    assert upgrade_target("2.18.0", [a, b], ["2.18.8"])[0] == "2.18.11"


def test_rv1_a_record_with_one_fix_per_major_is_safe_in_its_own_major() -> None:
    # express 4.17.1: one advisory fixed in 4.19.2 and 5.0.0-beta.3, another in 4.20.0
    # and 5.0.0; 4.20.0 is at or above the highest fix of the 4.x line of the first
    a = record("express", "4.17.1", "4.19.2, 5.0.0-beta.3", id="CVE-2024-29041")
    b = record("express", "4.17.1", "4.20.0, 5.0.0", id="CVE-2024-43796")
    assert upgrade_target("4.17.1", [a, b])[0] == "4.20.0"
    assert upgrade_target("4.17.1", [a, b], allow_major="dev-proven")[0] == "4.20.0"


def test_rv1_the_same_for_a_generic_per_major_pair() -> None:
    a = record("lib", "1.0.0", "1.2.5, 2.0.1", id="A")
    b = record("lib", "1.0.0", "1.3.0", id="B")
    assert upgrade_target("1.0.0", [a, b])[0] == "1.3.0"


def test_rv1_the_plan_case_still_needs_the_higher_branch() -> None:
    a = record("lib", "2.18.0", "2.18.11, 2.21.3", id="A")
    b = record("lib", "2.18.0", "2.20.0", id="B")
    assert upgrade_target("2.18.0", [a, b])[0] == "2.21.3"


def test_rv1_a_fix_only_in_another_major_is_needs_major() -> None:
    a = record("lib", "2.18.0", "3.0.0", id="A")
    b = record("lib", "2.18.0", "2.20.0, 3.1.0", id="B")
    target, _, code = upgrade_target("2.18.0", [a, b])
    assert (target, code) == (None, "needs_major")


def test_equal_versions_prefer_the_spelling_of_the_installed_version() -> None:
    three = record("lib", "1.2.3", "1.3, 1.3.0", id="A")
    assert upgrade_target("1.2.3", [three])[0] == "1.3.0"
    two = record("lib", "1.2", "1.3.0, 1.3", id="A")
    assert upgrade_target("1.2", [two])[0] == "1.3"


def test_equal_versions_with_the_same_distance_are_ordered_by_text() -> None:
    # 1.3 and 1.3.0.0 are equally far from 1.2.3 in components; the text decides
    a = record("lib", "1.2.3", "1.3.0.0, 1.3", id="A")
    assert upgrade_target("1.2.3", [a])[0] == "1.3"
    b = record("lib", "1.2.3", "1.3.0.0, 1.3", id="B")
    assert upgrade_target("1.2.3", [b, a])[0] == "1.3"


def test_c12_pins_the_spelling_of_the_installed_version() -> None:
    # pip 26.1.2 is fixed in both "26.2" and "26.2.0" (equal versions): the three
    # component spelling of the installed version wins
    plan = build_plan(
        merge_reports(
            [json.loads(Path(p).read_text(encoding="utf-8")) for p in load_case("c12")]
        ),
        Config(),
    )
    targets = [
        t["target"]
        for line in plan["lines"]
        for item in line["items"]
        if item["pkg"] == "pip"
        for t in item["targets"]
    ]
    assert targets and set(targets) == {"26.2.0"}


def test_calendar_version_year_is_not_a_major() -> None:
    rec = record("certifi", "2024.8.30", "2026.10.18")
    assert upgrade_target("2024.8.30", [rec]) == (
        "2026.10.18",
        "lowest fixed version in the same major",
        None,
    )


def test_semver_to_calendar_is_a_scheme_change() -> None:
    rec = record("lib", "3.2.0", "2024.1")
    assert upgrade_target("3.2.0", [rec])[2] == "needs_major"


def test_two_digit_year_keeps_the_semver_major() -> None:
    rec = record("pip", "24.0", "25.0")
    assert upgrade_target("24.0", [rec])[2] == "needs_major"
