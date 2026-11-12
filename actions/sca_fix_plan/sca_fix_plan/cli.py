"""Plan the fixes of the vulnerable packages of the newest release lines.

Input: one or more schema 4 ``report.json`` files of one repo (their versions are
merged by ref) and a JSON configuration (see ``config``). Output, in the output
directory: ``fix-plan.json`` (the machine plan) and ``fix-plan.md`` (the readable
one), and ``outputs.json`` (``plan-file``) and ``annotations.json``. No network and
no git: the plan is a pure function of the reports and the configuration. The only
contract with the scanner is the schema 4 report.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from _sca_lib.context import CommandError
from _sca_lib.outputs import Annotations, execute

from .config import ConfigError, parse_config
from .plan import build_plan
from .render import render_markdown
from .reports import ReportError, merge_reports


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--reports", nargs="+", required=True, type=Path)
    parser.add_argument("--config", default="{}", help="the configuration as JSON text")
    parser.add_argument("--output-dir", default=Path("out"), type=Path)
    args = parser.parse_args(argv)

    def body(_notes: Annotations) -> tuple[str, dict[str, Any]]:
        try:
            config = parse_config(args.config)
            reports = merge_reports([read_json(path) for path in args.reports])
            plan = build_plan(reports, config)
        except (ConfigError, ReportError) as exc:
            raise CommandError(str(exc)) from exc
        args.output_dir.mkdir(parents=True, exist_ok=True)
        text = json.dumps(plan, indent=1, ensure_ascii=False, sort_keys=True) + "\n"
        write_text(args.output_dir / "fix-plan.json", text)
        write_text(args.output_dir / "fix-plan.md", render_markdown(plan))
        return "ok", {"plan-file": str(args.output_dir / "fix-plan.json")}

    return execute("plan", args.output_dir, body)
