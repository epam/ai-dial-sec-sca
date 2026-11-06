"""``upgrades`` of the vulnerability records of report.json versions."""

from test_summary import finding, report, target
from vulns import build_versions


def upgrades(findings, targets=None, package_sets=None, version="1.0.0", cls="lang"):
    """``{id: upgrades}`` of the records of ``version`` (a release source target and,
    unless ``targets`` is given, a development source target).
    """
    targets = targets or [target("dev"), target("rel", ref=version)]
    doc = report(targets, findings)
    versions = {v["ref"]: v for v in build_versions(doc, package_sets or {})}
    return {r["id"]: r["upgrades"] for r in versions[version]["vulns"]}


def row(vid, fixed, version="1.0", pkg="lib", tid="rel", **extra):
    return finding(tid, vid, pkg, fixed=fixed, version=version, **extra)


def entry(installed, target=None, reason=None):
    return {"installed": installed, "target": target, "reason": reason}


def test_a_library_gets_the_lowest_fixed_version_in_its_major_as_the_target():
    got = upgrades([row("CVE-1", "0.9, 1.2, 2.0")])
    assert got == {"CVE-1": [entry("1.0", "1.2")]}


def test_a_fix_in_another_major_only_is_needs_major():
    got = upgrades([row("CVE-1", "2.0")])
    assert got == {"CVE-1": [entry("1.0", None, "needs_major")]}


def test_a_record_without_a_fixed_version_is_no_fixed_version():
    got = upgrades([row("CVE-1", "")])
    assert got == {"CVE-1": [entry("1.0", None, "no_fixed_version")]}


def test_a_version_that_cannot_be_compared_is_version_unparsable():
    got = upgrades([row("CVE-1", "1.2-3ubuntu1")])
    assert got == {"CVE-1": [entry("1.0", None, "version_unparsable")]}


def test_the_version_development_runs_is_preferred_to_the_lowest_fixed_version():
    sets = {"dev": {("lang", "lib", "1.4")}}
    got = upgrades([row("CVE-1", "1.2, 1.5")], package_sets=sets)
    assert got == {"CVE-1": [entry("1.0", "1.4")]}


def test_development_evidence_is_taken_from_the_package_of_the_same_key_only():
    sets = {"dev": {("lang", "other", "1.4"), ("os", "lib", "1.4")}}
    got = upgrades([row("CVE-1", "1.2, 1.5")], package_sets=sets)
    assert got == {"CVE-1": [entry("1.0", "1.2")]}


def test_a_run_without_a_development_version_has_no_development_versions():
    got = upgrades(
        [row("CVE-1", "1.2, 1.5")], targets=[target("rel", ref="1.0.0")]
    )
    assert got == {"CVE-1": [entry("1.0", "1.2")]}


def test_an_os_record_is_an_image_rebuild_for_every_installed_version():
    rows = [
        row("CVE-1", "2.40", version="2.39", pkg="libc6", cls="os"),
        row("CVE-1", "2.40", version="2.38", pkg="libc6", cls="os"),
    ]
    got = upgrades(rows)
    assert got == {
        "CVE-1": [
            entry("2.38", None, "image_rebuild"),
            entry("2.39", None, "image_rebuild"),
        ]
    }


def test_several_installed_versions_give_one_entry_each_in_version_order():
    rows = [
        row("CVE-1", "1.12", version="1.10"),
        row("CVE-1", "1.12", version="1.9"),
        row("CVE-1", "1.12", version="1.0"),
    ]
    got = upgrades(rows)
    assert got == {
        "CVE-1": [entry("1.0", "1.12"), entry("1.9", "1.12"), entry("1.10", "1.12")]
    }


def test_unparsable_installed_versions_come_last_in_string_order():
    rows = [
        row("CVE-1", "1.12", version="b-odd"),
        row("CVE-1", "1.12", version="a-odd"),
        row("CVE-1", "1.12", version="1.0"),
    ]
    got = upgrades(rows)["CVE-1"]
    assert [e["installed"] for e in got] == ["1.0", "a-odd", "b-odd"]
    assert all(e["reason"] == "version_unparsable" for e in got[1:])


def test_the_target_covers_every_record_of_the_package_installed_at_that_version():
    rows = [row("CVE-1", "1.2"), row("CVE-2", "1.3")]
    got = upgrades(rows)
    assert got == {"CVE-1": [entry("1.0", "1.3")], "CVE-2": [entry("1.0", "1.3")]}


def test_reason_is_null_exactly_when_there_is_a_target():
    rows = [row("CVE-1", "1.2"), row("CVE-2", ""), row("CVE-3", "2.0", pkg="p3")]
    for entries in upgrades(rows).values():
        for e in entries:
            assert (e["reason"] is None) == (e["target"] is not None)


def test_rv2_a_record_without_a_fix_above_the_version_is_no_fixed_version():
    rows = [row("CVE-1", "1.2"), row("CVE-2", ""), row("CVE-3", "0.5")]
    got = upgrades(rows)
    assert got == {
        "CVE-1": [entry("1.0", "1.2")],
        "CVE-2": [entry("1.0", None, "no_fixed_version")],
        "CVE-3": [entry("1.0", None, "no_fixed_version")],
    }


def test_rv3_development_that_still_has_the_vulnerability_is_no_evidence():
    sets = {"dev": {("lang", "lib", "1.4")}}
    dev_row = row("CVE-1", "1.2", version="1.4", tid="dev")
    got = upgrades([row("CVE-1", "1.2"), dev_row], package_sets=sets)
    assert got == {"CVE-1": [entry("1.0", "1.2")]}


def test_rv3_one_open_record_withholds_the_evidence_from_all_of_the_version():
    sets = {"dev": {("lang", "lib", "1.4")}}
    dev_row = row("CVE-2", "1.2", version="1.4", tid="dev")
    got = upgrades([row("CVE-1", "1.2"), row("CVE-2", "1.2"), dev_row], package_sets=sets)
    assert got == {
        "CVE-1": [entry("1.0", "1.2")],
        "CVE-2": [entry("1.0", "1.2")],
    }


def test_rv3_no_evidence_when_development_was_not_scanned_completely():
    targets = [target("dev", status="failed"), target("rel", ref="1.0.0")]
    sets = {"dev": {("lang", "lib", "1.4")}}
    got = upgrades([row("CVE-1", "1.2")], targets=targets, package_sets=sets)
    assert got == {"CVE-1": [entry("1.0", "1.2")]}


def test_several_development_versions_are_the_union_of_the_evidence():
    targets = [target("dev"), target("main", ref="main"), target("rel", ref="1.0.0")]
    sets = {"dev": {("lang", "lib", "1.3")}, "main": {("lang", "lib", "1.4")}}
    doc = report(targets, [row("CVE-1", "1.2")])
    doc["default_branch"] = "development"
    kinds = {"main": "development"}
    versions = {v["ref"]: v for v in build_versions(doc, sets, kinds)}
    assert versions["1.0.0"]["vulns"][0]["upgrades"] == [entry("1.0", "1.3")]


def test_an_os_record_without_a_fixed_version_is_no_fixed_version():
    rows = [
        row("CVE-1", "", version="2.39", pkg="libc6", cls="os"),
        row("CVE-2", "2.40", version="2.39", pkg="libc6", cls="os"),
    ]
    got = upgrades(rows)
    assert got == {
        "CVE-1": [entry("2.39", None, "no_fixed_version")],
        "CVE-2": [entry("2.39", None, "image_rebuild")],
    }


# --- dev_state ---


def states(findings, targets=None, package_sets=None, version="1.0.0"):
    targets = targets or [target("dev"), target("rel", ref=version)]
    doc = report(targets, findings)
    versions = {v["ref"]: v for v in build_versions(doc, package_sets or {})}
    return {r["id"]: r["dev_state"] for r in versions[version]["vulns"]}


def test_x2_dev_state_fixed_removed_open_and_incomplete():
    dev_row = row("CVE-2", "1.2", version="1.4", tid="dev")
    rows = [
        row("CVE-1", "1.2", pkg="gone"),
        row("CVE-2", "1.2"),
        row("CVE-3", "1.2", pkg="kept"),
        dev_row,
    ]
    sets = {"dev": {("lang", "kept", "1.4")}}
    assert states(rows, package_sets=sets) == {
        "CVE-1": "removed",
        "CVE-2": "open",
        "CVE-3": "fixed",
    }
    failed = [target("dev", status="failed"), target("rel", ref="1.0.0")]
    assert states(rows[:1], targets=failed) == {"CVE-1": "incomplete"}


def test_x2_dev_state_is_null_on_development_records_and_without_development():
    rows = [row("CVE-1", "1.2", tid="dev"), row("CVE-2", "1.2")]
    doc = report([target("dev"), target("rel", ref="1.0.0")], rows)
    versions = {v["ref"]: v for v in build_versions(doc, {})}
    assert [r["dev_state"] for r in versions["development"]["vulns"]] == [None]
    alone = states([row("CVE-2", "1.2")], targets=[target("rel", ref="1.0.0")])
    assert alone == {"CVE-2": None}


def test_x2_dev_state_of_an_image_only_library_needs_the_development_image():
    image = target("img", kind="image", ref="1.0.0")
    rows = [row("CVE-1", "1.2", tid="img")]
    targets = [target("dev"), image]
    assert states(rows, targets=targets) == {"CVE-1": "incomplete"}
    dev_image = target("dev-img", kind="image", ref="development")
    sets = {"dev": {("lang", "lib", "1.5")}}
    assert states(rows, targets=[*targets, dev_image], package_sets=sets) == {
        "CVE-1": "fixed"
    }


def test_rv4_a_library_in_source_and_image_needs_the_development_sources_only():
    image = target("img", kind="image", ref="1.0.0")
    targets = [target("dev"), target("rel", ref="1.0.0"), image]
    rows = [row("CVE-1", "1.2", tid="rel"), row("CVE-1", "1.2", tid="img")]
    sets = {"dev": {("lang", "lib", "1.5")}}
    assert states(rows, targets=targets, package_sets=sets) == {"CVE-1": "fixed"}


# --- the group contract and RV3 ---

DEV_RUNS = {"dev": {("lang", "lib", "1.2.5")}}


def test_rv3_with_development_evidence_every_record_of_the_group_gets_the_target():
    # development runs 1.2.5 and has none of the records: C has no fix above 1.0 and
    # is absent from development, so it is fixed there like the others
    rows = [row("A", "1.2"), row("B", "1.1"), row("C", "")]
    got = upgrades(rows, package_sets=DEV_RUNS)
    assert got == {k: [entry("1.0", "1.2.5")] for k in "ABC"}


def test_group_contract_without_evidence_a_record_without_a_fix_is_no_fixed_version():
    rows = [row("A", "1.2"), row("B", "1.1"), row("C", "")]
    got = upgrades(rows)
    assert got == {
        "A": [entry("1.0", "1.2")],
        "B": [entry("1.0", "1.2")],
        "C": [entry("1.0", None, "no_fixed_version")],
    }
    rows = [row("A", "2.0"), row("B", "2.1"), row("C", "")]
    got = upgrades(rows)
    assert got["A"] == got["B"] == [entry("1.0", None, "needs_major")]
    assert got["C"] == [entry("1.0", None, "no_fixed_version")]


def test_group_contract_a_group_target_is_shared_by_every_record_that_has_one():
    rows = [row("A", "1.2, 2.0"), row("B", "1.1, 2.0"), row("C", "0.5")]
    for sets in ({}, DEV_RUNS):
        got = upgrades(rows, package_sets=sets)
        targets = {e["target"] for v in got.values() for e in v if e["target"]}
        assert len(targets) == 1


# --- speed ---


def test_many_records_of_one_package_are_computed_in_seconds():
    import time

    rows = []
    for n in range(1000):
        for installed in ("1.0", "1.1", "1.2"):
            rows.append(row(f"CVE-{n}", f"1.{n % 40 + 3}, 2.{n % 7}", version=installed))
    started = time.perf_counter()
    got = upgrades(rows)
    elapsed = time.perf_counter() - started
    assert len(got) == 1000
    assert all(len(v) == 3 for v in got.values())
    assert elapsed < 2, elapsed
