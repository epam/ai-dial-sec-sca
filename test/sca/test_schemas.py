"""What the engine writes validates against the schemas in ``schema/`` (the contract
files shared with the consumers).
"""

import json
import subprocess
from pathlib import Path
from typing import Any

import jsonschema
import pytest
import query_osv
import resolve_targets as rt
from golden_case import merged, merged_scan_tag
from merge_results import main as merge_main
from test_merge_results import Run, cli_args, target, trivy_native
from test_resolve_targets import (
    ENV,
    FakeRunner,
    github_routes,
    parse,
    run_resolve_targets,
    stable,
    tag_routes,
    tags_out,
    tags_url,
)

SCHEMAS = Path(__file__).resolve().parents[2] / "schema"


def check(name: str, document: Any) -> None:
    schema = json.loads((SCHEMAS / f"{name}.schema.json").read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    validator.check_schema(schema)
    errors = [f"{list(e.path)}: {e.message}" for e in validator.iter_errors(document)]
    assert errors == []


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def test_the_schemas_reject_a_wrong_document() -> None:
    with pytest.raises(AssertionError):
        check("outputs", {"contract": 2, "command": "merge", "status": "ok", "outputs": {}})
    with pytest.raises(AssertionError):
        check("annotations", [{"level": "fatal", "message": "x"}])
    with pytest.raises(AssertionError):
        check("targets", {"repo": "o/r"})


def test_a_resolved_target_set_is_valid() -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.1.14", "2025-01-01T00:00:00Z")])
    tag_routes(t, "1.1.14", "b" * 40)
    t.add(tags_url("example/x"), tags_out(["development"]))  # 1.1.14 is not published
    doc = run_resolve_targets(t, ["example/x"])
    assert {x["status"] for x in doc["targets"]} == {"pending", "not_applicable"}
    check("targets", doc)


def test_a_focus_run_target_set_is_valid() -> None:
    t = FakeRunner()
    github_routes(t, [])
    tag_routes(t, "1.1.14", "b" * 40)
    t.add(tags_url("example/x"), tags_out(["1.1.14"]))
    check("targets", run_resolve_targets(t, ["example/x"], scan_tag="1.1.14"))


def test_the_golden_reports_are_valid(tmp_path: Path) -> None:
    check("report", json.loads(merged(tmp_path / "a")))
    check("report", json.loads(merged_scan_tag(tmp_path / "b")))


def test_a_report_with_a_failed_target_is_valid(tmp_path: Path, run_env: Any) -> None:
    run = Run(tmp_path, [target("s", "trivy"), target("t", "trivy")])
    run.part("trivy", "t", trivy_native(), {"status": "ok"})  # "s" has no result
    assert merge_main(cli_args(run)) == 0
    check("report", load(run.out / "report.json"))
    check("outputs", load(run.out / "outputs.json"))
    check("annotations", load(run.out / "annotations.json"))
    assert load(run.out / "outputs.json")["status"] == "failed_targets"


def test_the_outputs_of_a_failed_command_are_valid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ENV:
        monkeypatch.delenv(name, raising=False)
    assert rt.main(["--repository", "example/app", "--output-dir", str(tmp_path)]) == 2
    check("outputs", load(tmp_path / "outputs.json"))
    check("annotations", load(tmp_path / "annotations.json"))


def test_the_outputs_of_targets_are_valid(tmp_path: Path) -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.1.14", "2025-01-01T00:00:00Z")])
    notes: list[dict[str, Any]] = []
    status, outputs = rt.run(parse(tmp_path), {**ENV, "GH_TOKEN": "x"}, notes, t)
    check("annotations", notes)
    check(
        "outputs",
        {"contract": 1, "command": "targets", "status": status, "outputs": outputs},
    )


def test_osv_writes_valid_outputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(command: Any, **_kwargs: Any) -> Any:
        return subprocess.CompletedProcess(command, 0, "osv-scanner version: 2.7.0\n", "")

    monkeypatch.setattr(query_osv, "run_command", fake)
    (tmp_path / "targets.json").write_text('{"targets": []}', encoding="utf-8")
    out = tmp_path / "out"
    code = query_osv.main(
        ["--targets-file", str(tmp_path / "targets.json"), "--parts-dir", str(tmp_path), "--output-dir", str(out)]
    )
    assert code == 0
    check("outputs", load(out / "outputs.json"))
    assert load(out / "outputs.json")["command"] == "osv"
    check("annotations", load(out / "annotations.json"))
