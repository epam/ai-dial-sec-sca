"""Code shared by the SCA actions (``actions/sca_*``), standard library only.

An action puts the ``actions`` directory on ``PYTHONPATH``
(``${{ github.action_path }}/..``) and imports ``from _sca_lib import ...``. A package
and not a loose module: it cannot shadow a module of the standard library.

``context`` reads the run context (``SCA_RUN_*``), ``outputs`` writes what a command
leaves for its caller (``outputs.json``, ``annotations.json``), ``github`` turns that
into GitHub step outputs, summary and annotations.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def dump_json(path: Path, data: Any) -> None:
    path.write_text(
        json.dumps(data, indent=1, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def format_time(moment: datetime) -> str:
    """UTC as the SCA files write it: ``2026-10-12T01:14:57Z``."""
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
