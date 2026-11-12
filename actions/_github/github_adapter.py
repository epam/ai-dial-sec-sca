"""The GitHub rendering of a command's output dir, the final step of a composite
action: ``outputs.json`` to the step outputs, ``summary.md`` to the job summary,
``annotations.json`` to workflow commands. The only module that knows these syntaxes
(the ``sca`` package prints no platform syntax). Standard library only, run by path.

Usage: ``python github_adapter.py render OUTPUT_DIR``; it always exits 0, the status
of the action is the one of the command step. ``python github_adapter.py context``
writes the step outputs ``host`` (of ``SERVER_URL``) and ``engine-ref`` (the
``ENGINE_REF_INPUT`` if set, else the ref in the runner path ``ACTION_PATH``), which
the action passes on as ``SCA_RUN_HOST`` and ``SCA_RUN_ENGINE_REF``.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.parse
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


# a job summary takes 1 MiB; some room for the note of a cut one
STEP_SUMMARY_LIMIT_BYTES = 1024 * 1024 - 16 * 1024


def engine_ref(action_path: str | None) -> str | None:
    """The ref of the action in a runner path ``.../_actions/<owner>/<repo>/<ref>/
    actions/<action>`` (a branch ref with a slash is nested directories); None
    outside Actions (a local run). ``github.action_ref`` is not reliable in a composite
    action, the path is.
    """
    parts = (action_path or "").replace("\\", "/").split("/")
    if "_actions" not in parts:
        return None
    return "/".join(parts[parts.index("_actions") + 3 : -2]) or None


def context_outputs(environ: Mapping[str, str]) -> dict[str, str]:
    """The step outputs ``host`` and ``engine-ref`` (empty when there is none)."""
    return {
        "host": urllib.parse.urlsplit(environ.get("SERVER_URL", "")).netloc,
        "engine-ref": environ.get("ENGINE_REF_INPUT")
        or engine_ref(environ.get("ACTION_PATH"))
        or "",
    }


def escape_data(text: object) -> str:
    """The message of a workflow command: ``%``, CR and LF in scanner output or a
    repository name would end or forge the command.
    """
    return str(text).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_property(text: object) -> str:
    return escape_data(text).replace(":", "%3A").replace(",", "%2C")


def command_line(annotation: Mapping[str, Any]) -> str:
    head = f"::{annotation['level']}"
    if title := annotation.get("title"):
        head += f" title={escape_property(title)}"
    return f"{head}::{escape_data(annotation['message'])}"


def output_text(name: str, value: Any) -> str:
    """One entry of ``$GITHUB_OUTPUT``; a value with a line break gets a delimiter."""
    text = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))
    if "\n" not in text:
        return f"{name}={text}\n"
    delimiter = f"ghadelim_{uuid.uuid4().hex}"
    return f"{name}<<{delimiter}\n{text}\n{delimiter}\n"


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


def append_text(path: str, text: str) -> None:
    with open(path, "a", encoding="utf-8", newline="\n") as f:
        f.write(text)


def read_part(path: Path, read: Callable[[Path], Any]) -> Any:
    """What ``read`` makes of the file; None, with a line on stderr, if the file is
    missing or not what the command writes (the other files are still rendered).
    """
    try:
        return read(path)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"{path.name} not rendered: {error!r}", file=sys.stderr)
        return None


def render(output_dir: Path, environ: Mapping[str, str]) -> None:
    """Write the outputs and the summary to the files of the step, print the
    annotations; a file the command did not write or wrote wrongly is skipped.
    """
    outputs = read_part(
        output_dir / "outputs.json", lambda p: dict(read_json(p)["outputs"])
    )
    annotations = read_part(
        output_dir / "annotations.json",
        lambda p: [command_line(a) for a in read_json(p)],
    )
    summary = read_part(
        output_dir / "summary.md", lambda p: p.read_text(encoding="utf-8")
    )
    if (target := environ.get("GITHUB_OUTPUT")) and outputs is not None:
        append_text(target, "".join(output_text(k, v) for k, v in outputs.items()))
    if (target := environ.get("GITHUB_STEP_SUMMARY")) and summary is not None:
        append_text(target, truncate_summary(summary, environ.get("SCA_RUN_URL")))
    for line in annotations or []:
        print(line)


if __name__ == "__main__":
    if sys.argv[1] == "context":
        text = "".join(output_text(k, v) for k, v in context_outputs(os.environ).items())
        append_text(os.environ["GITHUB_OUTPUT"], text)
    else:
        render(Path(sys.argv[2]), os.environ)
