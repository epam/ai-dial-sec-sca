"""Risk acceptance from the ``.trivyignore`` of the default branch.

The grammar is the plain format of Trivy (``parseIgnore``): per line the first
field is the id, of the other fields only the first ``exp:YYYY-MM-DD`` matters. The
file never fails as a whole: a line with an unparsable date is flagged and does not
act.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import date
from pathlib import Path
from typing import Any

from _sca_lib import read_json

DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def parse_line(
    line: str, today: str, reason: str | None = None
) -> dict[str, Any] | None:
    """One ``ignores[]`` entry, None for a blank line or a comment. ``reason`` is
    the comment block above the line; it never acts.
    """
    fields = line.split()
    if not fields or fields[0].startswith("#"):
        return None
    exp = next((f[4:] for f in fields[1:] if f.startswith("exp:")), None)
    until = None
    if exp is not None and DATE.fullmatch(exp):
        try:
            until = date.fromisoformat(exp).isoformat()
        except ValueError:
            pass
    return {
        "id": fields[0],
        "until": until,
        # Trivy: ExpiredAt.Before(now), a line stops acting on the exp day itself
        "expired": until is not None and until <= today,
        "bad_expiry": exp is not None and until is None,
        "no_expiry": exp is None,
        "matched": False,
        "reason": reason,
    }


def read_ignores(
    report: Mapping[str, Any], parts_dir: Path
) -> tuple[list[dict[str, Any]] | None, str | None]:
    """``(ignores, ignores_error)``: the lines of the ignore file the workflow copied
    for the source target of the default branch. The status file is read directly,
    a failed Trivy scan with a successful checkout still yields the file.
    """
    tid = next(
        (
            t["id"]
            for t in report["targets"]
            if (t["scanner"], t["kind"], t["ref"])
            == ("trivy", "fs", report["default_branch"])
        ),
        None,
    )
    if tid is None:
        return None, "no default-branch target in this run"
    trivy = parts_dir / "trivy"
    try:
        status = read_json(trivy / f"{tid}.status.json")
    except (OSError, ValueError):
        status = None
    if not isinstance(status, dict):
        return None, f"no readable status file for {tid}"
    if "ignorefile" not in status:
        return None, "the workflow does not pass the ignore file"
    state = status["ignorefile"]
    if state is None:
        return None, "checkout failed"
    if state == "absent":
        return [], None
    if state != "present":
        return None, f"unexpected ignorefile value: {state!r}"
    try:
        # a stray bad byte must not drop every acceptance
        text = (trivy / f"{tid}.trivyignore").read_text("utf-8", errors="replace")
    except OSError as e:
        return None, f"the ignore file of {tid} is unreadable: {e.strerror}"
    today = report["generated_utc"][:10]
    entries: list[dict[str, Any]] = []
    block: list[str] = []
    for line in text.split("\n"):
        if line.strip().startswith("#"):
            block.append(line.strip().lstrip("#").strip())
            continue
        reason = " ".join(filter(None, block)) or None
        if entry := parse_line(line, today, reason):
            entries.append(entry)
        block = []  # an ignore line or a blank line ends the block
    return entries, None


def add_ignores(report: dict[str, Any], parts_dir: Path) -> None:
    """Set ``ignores`` and ``ignores_error`` of the report, ``accepted`` on every
    record (the earliest ``until`` of the acting lines that name it) and
    ``matched`` on the lines.
    """
    ignores, error = read_ignores(report, parts_dir)
    report["ignores"], report["ignores_error"] = ignores, error
    if ignores is None:
        return
    acting: dict[str, list[str]] = {}
    for e in ignores:
        if e["until"] and not e["expired"]:  # a bad expiry has no until
            acting.setdefault(e["id"], []).append(e["until"])
    seen: set[str] = set()
    for version in report["versions"]:
        for v in version["vulns"]:
            seen.update(v["names"])
            untils = [u for n in v["names"] for u in acting.get(n, ())]
            v["accepted"] = {"until": min(untils)} if untils else None
    for e in ignores:
        e["matched"] = e["id"] in seen
