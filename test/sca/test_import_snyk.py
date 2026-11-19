"""``sca import snyk``: a golden report per fixture of ``snyk test --all-projects --json``
(Gradle with an error project and an unknown package manager, npm as one object, pip).
"""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from test_schemas import check

from sca.cli import main as sca_main
from sca.imports.snyk import convert

DIR = Path(__file__).parent / "snyk"
NOW = datetime(2026, 11, 19, 5, 30, tzinfo=UTC)
ARGS = ("example/app", "development", "0123456789abcdef")


@pytest.fixture(autouse=True)
def no_run_context(monkeypatch):
    for name in ("SCA_RUN_ENGINE_REF", "SCA_RUN_HOST", "SCA_RUN_ID", "SCA_RUN_URL"):
        monkeypatch.delenv(name, raising=False)


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", ["gradle", "npm", "pip"])
def test_the_report_of_a_fixture_is_its_golden_and_valid(name):
    report = convert(load(DIR / f"{name}.json"), *ARGS, snyk_version="1.1300.0", now=NOW)
    check("report", report)
    assert report == load(DIR / f"{name}.report.json")


def test_gradle_folds_paths_and_projects_and_keeps_failed_and_unknown_projects():
    report = convert(load(DIR / "gradle.json"), *ARGS, now=NOW)
    version = report["versions"][0]
    by_id = {(v["pkg"], v["id"]): v for v in version["vulns"]}
    jackson = by_id["com.fasterxml.jackson.core:jackson-databind", "CVE-2026-1001"]
    assert jackson["installed"] == ["2.15.2", "2.16.0"]
    assert jackson["where"] == ["snyk:build.gradle", "snyk:server/build.gradle"]
    assert jackson["severity"] == "HIGH" and jackson["fixed"] == "2.15.4, 2.16.1"
    assert jackson["names"] == ["CVE-2026-1001", "GHSA-aaaa-bbbb-cccc", "SNYK-JAVA-COMFASTERXMLJACKSONCORE-7569538"]
    assert by_id["io.netty:netty-codec-http2", "GHSA-dddd-eeee-ffff"]["names"][-1].startswith("SNYK-")
    assert by_id["org.yaml:snakeyaml", "SNYK-JAVA-ORGYAML-8000002"]["aliases"] == []
    assert by_id["Alamofire", "CVE-2026-1003"]["ecosystem"] is None
    failed = next(t for t in report["targets"] if t["status"] == "failed")
    assert (failed["id"], failed["reason"]) == ("snyk:legacy/pom.xml", "SNYK-CLI-0008")
    assert version["status"] == "failed"
    assert version["counts"] == {"c": 1, "h": 1, "m": 1, "l": 1, "unknown": 0, "all": 4, "fixable": 3}


def test_the_cli_writes_the_report_of_a_single_object_input(tmp_path, capsys):
    out = tmp_path / "report.json"
    argv = ["import", "snyk", "--input", str(DIR / "npm.json"), "--repo", ARGS[0], "--ref", ARGS[1]]
    assert sca_main([*argv, "--commit", ARGS[2], "--out", str(out)]) == 0
    report = load(out)
    check("report", report)
    assert [t["id"] for t in report["targets"]] == ["snyk:package-lock.json"]
    assert [v["pkg"] for v in report["versions"][0]["vulns"]] == ["@babel/traverse", "lodash"]
    assert "1 target(s), 2 record(s)" in capsys.readouterr().out


def test_an_input_that_is_not_snyk_json_is_a_usage_error(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text('"nope"', encoding="utf-8")
    argv = ["import", "snyk", "--input", str(bad), "--repo", "o/r", "--ref", "main", "--commit", "abc"]
    assert sca_main([*argv, "--out", str(tmp_path / "r.json")]) == 2
    assert "cannot convert" in capsys.readouterr().err
    assert sca_main(["import"]) == 2
