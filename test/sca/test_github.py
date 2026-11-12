"""The GitHub rendering of an output dir (``actions/_github``) and the output files of
a command (``sca.lib.outputs``).
"""

import json
import re
from pathlib import Path

import pytest
from sca.lib import dump_json
from sca.lib.context import CommandError, UsageError, read_run_context
from github_adapter import (
    STEP_SUMMARY_LIMIT_BYTES,
    command_line,
    context_outputs,
    engine_ref,
    output_text,
    render,
    truncate_summary,
)
from sca.lib.outputs import execute, note

RUN_ENV = {
    "SCA_RUN_HOST": "github.com",
    "SCA_RUN_REPO": "example/caller",
    "SCA_RUN_ID": "42",
    "SCA_RUN_URL": "https://github.com/example/caller/actions/runs/42",
    "SCA_RUN_EVENT": "workflow_dispatch",
    "SCA_RUN_ACTOR": "octocat",
}


def test_annotations_render_as_github_workflow_commands() -> None:
    notes = [
        {
            "level": "error",
            "title": "Scan target failed",
            "message": "a-1.0 (trivy): registry login failure",
            "target": "a-1.0",
        },
        {
            "level": "notice",
            "title": "Scan target x-1.1.14 skipped",
            "message": "release 1.1.14 not published for this image",
            "target": "x-1.1.14",
        },
        {
            "level": "warning",
            "title": "Release list truncated",
            "message": "the release set is built from the newest 1000 releases",
            "target": None,
        },
        {"level": "warning", "title": None, "message": "no title", "target": None},
    ]
    assert [command_line(n) for n in notes] == [
        "::error title=Scan target failed::a-1.0 (trivy): registry login failure",
        "::notice title=Scan target x-1.1.14 skipped::"
        "release 1.1.14 not published for this image",
        "::warning title=Release list truncated::"
        "the release set is built from the newest 1000 releases",
        "::warning::no title",
    ]


def test_a_message_cannot_end_or_forge_a_command() -> None:
    hostile = {
        "level": "error",
        "title": "a: b, c%\n::error::x",
        "message": "100% sure\r\n::warning::forged",
        "target": None,
    }
    assert command_line(hostile) == (
        "::error title=a%3A b%2C c%25%0A%3A%3Aerror%3A%3Ax::"
        "100%25 sure%0D%0A::warning::forged"
    )


def test_a_step_output_is_one_line_or_a_delimited_block() -> None:
    assert output_text("failed-count", 2) == "failed-count=2\n"
    assert output_text("targets-file", "/t/targets.json") == "targets-file=/t/targets.json\n"
    matrix = [{"id": "a", "kind": "fs"}]
    assert output_text("matrix", matrix) == 'matrix=[{"id":"a","kind":"fs"}]\n'
    assert output_text("matrix", []) == "matrix=[]\n"
    block = output_text("note", "line 1\nline 2")
    head, body, tail = block.split("\n", 1)[0], "line 1\nline 2", block.rstrip("\n").rsplit("\n", 1)[1]
    assert head == f"note<<{tail}" and body in block and tail.startswith("ghadelim_")


def write_dir(out: Path, **files: object) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, doc in files.items():
        dump_json(out / f"{name}.json", doc)


def test_render_writes_outputs_summary_and_prints_annotations(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "out"
    write_dir(
        out,
        outputs={
            "contract": 1,
            "command": "merge",
            "status": "failed_targets",
            "outputs": {"failed-count": 1, "report-file": "out/report.json"},
        },
        annotations=[
            {"level": "error", "title": "T", "message": "m", "target": None}
        ],
    )
    (out / "summary.md").write_text("# SCA\n", encoding="utf-8")
    step_output, step_summary = tmp_path / "output", tmp_path / "summary"
    render(
        out,
        {"GITHUB_OUTPUT": str(step_output), "GITHUB_STEP_SUMMARY": str(step_summary)},
    )
    assert step_output.read_text(encoding="utf-8") == (
        "failed-count=1\nreport-file=out/report.json\n"
    )
    assert step_summary.read_text(encoding="utf-8") == "# SCA\n"
    assert capsys.readouterr().out == "::error title=T::m\n"


def test_render_of_an_empty_dir_does_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    step_output = tmp_path / "output"
    render(tmp_path, {"GITHUB_OUTPUT": str(step_output)})
    assert not step_output.exists()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""  # a file the command did not write is no error


@pytest.mark.parametrize(
    ("broken", "text"),
    [
        ("outputs.json", "{"),
        ("outputs.json", "[]"),
        ("outputs.json", '{"outputs": 1}'),
        ("annotations.json", "{"),
        ("annotations.json", '[{"level": "error"}]'),
        ("annotations.json", "[1]"),
        ("summary.md", None),
    ],
)
def test_render_skips_only_the_file_that_is_broken(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], broken: str, text: str | None
) -> None:
    out = tmp_path / "out"
    write_dir(
        out,
        outputs={"outputs": {"k": "v"}},
        annotations=[{"level": "notice", "message": "m"}],
    )
    (out / "summary.md").write_text("# SCA\n", encoding="utf-8")
    if text is None:
        (out / broken).unlink()
    else:
        (out / broken).write_text(text, encoding="utf-8")
    step_output, step_summary = tmp_path / "output", tmp_path / "summary"
    render(
        out,
        {"GITHUB_OUTPUT": str(step_output), "GITHUB_STEP_SUMMARY": str(step_summary)},
    )
    good = {
        "outputs.json": (step_output, "k=v\n"),
        "summary.md": (step_summary, "# SCA\n"),
    }
    for name, (target, expected) in good.items():
        if name == broken:
            assert not target.exists()
        else:
            assert target.read_text(encoding="utf-8") == expected
    captured = capsys.readouterr()
    assert (captured.out == "") == (broken == "annotations.json")
    if text is None:  # missing, not broken: skipped without a line
        assert captured.err == ""
    else:
        assert captured.err.count("not rendered") == 1
        assert captured.err.startswith(broken)


def test_render_cuts_the_summary_with_a_link_to_the_run(tmp_path: Path) -> None:
    (tmp_path / "summary.md").write_text("| row |\n" * STEP_SUMMARY_LIMIT_BYTES, encoding="utf-8")
    step_summary = tmp_path / "step"
    render(
        tmp_path,
        {"GITHUB_STEP_SUMMARY": str(step_summary), "SCA_RUN_URL": "https://x.test/run/7"},
    )
    text = step_summary.read_text(encoding="utf-8")
    assert len(text.encode()) <= STEP_SUMMARY_LIMIT_BYTES
    assert "[this run](https://x.test/run/7)" in text


def test_a_summary_that_fits_is_not_touched() -> None:
    assert truncate_summary("short\n", None) == "short\n"


@pytest.mark.parametrize("run_url", [None, "https://example.test/run/7"])
def test_a_long_summary_is_cut_at_a_line_with_open_blocks_closed_and_a_note(run_url) -> None:
    text = "<details><summary>x</summary>\n" + "| row |\n" * (
        STEP_SUMMARY_LIMIT_BYTES // 8
    )
    cut = truncate_summary(text, run_url)
    assert len(cut.encode()) <= STEP_SUMMARY_LIMIT_BYTES
    body, _, tail = cut.partition("\n> The summary is cut")
    assert body.rstrip().endswith("</details>")
    assert body.count("<details") == body.count("</details>")
    assert f"it is {len(text.encode())} bytes" in tail
    assert (run_url in tail) if run_url else "artifact of this run" in tail


def test_the_cut_leaves_room_for_every_block_it_closes() -> None:
    text = "<details><summary>x</summary>\n" * 5 + "| row |\n" * (
        STEP_SUMMARY_LIMIT_BYTES // 8
    )
    cut = truncate_summary(text, None)
    assert len(cut.encode()) <= STEP_SUMMARY_LIMIT_BYTES
    assert cut.count("<details") == cut.count("</details>") == 5


# --- outputs.json of a command ---


def read(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def test_execute_writes_outputs_and_annotations(tmp_path: Path) -> None:
    def body(notes):
        note(notes, "warning", "careful", "Title", "t-1")
        return "ok", {"k": 1}

    assert execute("merge", tmp_path / "o", body, "v1") == 0
    assert read(tmp_path / "o" / "outputs.json") == {
        "contract": 1,
        "command": "merge",
        "status": "ok",
        "engine": "v1",
        "message": None,
        "outputs": {"k": 1},
    }
    assert read(tmp_path / "o" / "annotations.json") == [
        {"level": "warning", "message": "careful", "title": "Title", "target": "t-1"}
    ]


@pytest.mark.parametrize(("error", "code"), [(CommandError("boom"), 1), (UsageError("bad"), 2)])
def test_execute_reports_a_command_error_with_its_exit_code(
    tmp_path: Path, error: CommandError, code: int, capsys: pytest.CaptureFixture[str]
) -> None:
    def body(_notes):
        raise error

    assert execute("targets", tmp_path, body) == code
    outputs = read(tmp_path / "outputs.json")
    assert (outputs["status"], outputs["message"], outputs["outputs"]) == ("error", str(error), {})
    (annotation,) = read(tmp_path / "annotations.json")
    assert (annotation["level"], annotation["title"]) == ("error", "sca targets failed")
    assert f"error: {error}" in capsys.readouterr().err


def test_execute_writes_the_outputs_of_an_unexpected_error_and_raises_it(tmp_path: Path) -> None:
    def body(_notes):
        raise KeyError("x")

    with pytest.raises(KeyError):
        execute("osv", tmp_path, body)
    assert read(tmp_path / "outputs.json")["status"] == "error"


def test_the_engine_of_outputs_json_is_the_run_context_ref(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SCA_RUN_ENGINE_REF", "v0.9.0")
    execute("osv", tmp_path, lambda _notes: ("ok", {}))
    assert read(tmp_path / "outputs.json")["engine"] == "v0.9.0"


# --- the run context ---


def test_the_run_context_reads_the_variables_and_defaults() -> None:
    context = read_run_context(RUN_ENV)
    assert (context.host, context.repo, context.run_id, context.attempt) == (
        "github.com",
        "example/caller",
        "42",
        1,
    )
    assert context.engine_ref is None
    full = read_run_context(
        {**RUN_ENV, "SCA_RUN_ATTEMPT": "3", "SCA_RUN_ENGINE_REF": "v1"}
    )
    assert (full.attempt, full.engine_ref) == (3, "v1")


def test_the_run_context_names_every_missing_variable() -> None:
    with pytest.raises(UsageError, match="SCA_RUN_HOST, SCA_RUN_ACTOR") as caught:
        read_run_context({**RUN_ENV, "SCA_RUN_HOST": "", "SCA_RUN_ACTOR": ""})
    assert caught.value.code == 2


def test_the_run_context_ignores_github_variables() -> None:
    github = {"GITHUB_REPOSITORY": "o/r", "GITHUB_RUN_ID": "1", "GITHUB_SERVER_URL": "https://github.com"}
    with pytest.raises(UsageError, match="SCA_RUN_HOST"):
        read_run_context(github)


@pytest.mark.parametrize(
    ("path", "ref"),
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
def test_engine_ref_is_read_from_the_runner_path(path, ref) -> None:
    assert engine_ref(path) == ref


def test_context_outputs_take_the_input_before_the_path() -> None:
    path = "/w/_actions/epam/ai-dial-sec-sca/v0.8.1/actions/sca_merge_results"
    env = {"SERVER_URL": "https://git.example:8443", "ACTION_PATH": path}
    assert context_outputs(env) == {"host": "git.example:8443", "engine-ref": "v0.8.1"}
    assert context_outputs({**env, "ENGINE_REF_INPUT": "abc123"})["engine-ref"] == "abc123"
    assert context_outputs({})["engine-ref"] == ""


def test_every_python_module_run_of_an_action_leaves_the_workspace_off_the_path() -> None:
    """``-P``: a ``sca`` package in the checked-out workspace must not shadow the engine."""
    runs = [
        (path.parent.name, line.strip())
        for path in Path(__file__).resolve().parents[2].glob("actions/*/action.yml")
        for line in path.read_text(encoding="utf-8").splitlines()
        if re.search(r"\bpython3?\s+(\S+\s+)*-m\b", line)
        and not line.lstrip().startswith("#")
    ]
    assert runs
    assert [r for r in runs if not re.search(r"\bpython3?\s+-P\s+-m\b", r[1])] == []
