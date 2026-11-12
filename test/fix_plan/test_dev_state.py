"""The engine's ``dev_state`` of a record and ``classify()`` give the same state for the
same record (both are ``sca.rules.Development``; this checks the two ways of feeding it).
"""

import json
from pathlib import Path
from typing import Any

import pytest
from sca.merge import vulns
from cases import CASES, load_case
from sca.plan import classify
from sca.rules import identifiers, norm

GOLDEN = Path(__file__).resolve().parents[1] / "sca" / "golden"


def engine_states(report: dict[str, Any]) -> dict[tuple[str, str, str, str], str]:
    """``(ref, class, pkg_key, id) -> dev_state`` as the engine computes it."""
    development = vulns.development_of(report, report["versions"])
    out = {}
    for version in report["versions"]:
        trivy = {
            t["id"]: t
            for t in report["targets"]
            if t["scanner"] == "trivy" and t["id"] in version["targets"]
        }
        states = vulns.dev_states(version, trivy, development)
        for record in version["vulns"]:
            if states[id(record)]:
                key = (
                    version["ref"],
                    record["class"],
                    norm(record["pkg"]),
                    min(identifiers(record)),
                )
                out[key] = states[id(record)]
    return out


def classified(reports: list[dict[str, Any]]) -> dict[tuple[str, str, str, str], str]:
    return {
        (e["ref"], e["class"], e["key"], e["ids"][0]): e["state"]
        for e in classify(reports)
    }


def agree(reports: list[dict[str, Any]], merged: dict[str, Any]) -> int:
    engine, planner = engine_states(merged), classified(reports)
    assert planner
    for key, state in planner.items():
        assert engine[key] == state, key
    return len(planner)


def test_classify_and_dev_state_agree_on_the_golden_report() -> None:
    report = json.loads((GOLDEN / "report.json").read_text(encoding="utf-8"))
    for version in report["versions"]:  # classify leaves out accepted records
        for record in version["vulns"]:
            record["accepted"] = None
    assert agree([report], report) > 0


def test_a_run_without_development_has_no_dev_state() -> None:
    report = json.loads((GOLDEN / "report_scan_tag.json").read_text(encoding="utf-8"))
    assert not any(v["kind"] == "development" for v in report["versions"])
    assert engine_states(report) == {}


@pytest.mark.parametrize("case", CASES)
def test_classify_and_dev_state_agree_on_the_real_report_fixtures(case: str) -> None:
    release, dev = (json.loads(p.read_text(encoding="utf-8")) for p in load_case(case))
    merged = {
        **release,
        "targets": [*release["targets"], *dev["targets"]],
        "versions": [*release["versions"], *dev["versions"]],
    }
    agree([release, dev], merged)
