"""What a command leaves in its output dir for the caller: ``outputs.json``
(``schema/outputs.schema.json``) and ``annotations.json``. The engine prints no
platform syntax; an adapter renders these files.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import dump_json
from .context import CommandError

CONTRACT = 1

Annotations = list[dict[str, Any]]


def note(
    notes: Annotations,
    level: str,
    message: str,
    title: str | None = None,
    target: str | None = None,
) -> None:
    """Add an annotation: ``level`` is notice, warning or error."""
    notes.append({"level": level, "message": message, "title": title, "target": target})


def execute(
    command: str,
    output_dir: Path,
    body: Callable[[Annotations], tuple[str, dict[str, Any]]],
    engine: str | None = None,
) -> int:
    """Run ``body(annotations)`` -> ``(status, outputs)``, write ``outputs.json`` and
    ``annotations.json`` also when it fails, and return the exit code: 0, or the code
    of the ``CommandError`` it raised. Any other exception is written as an error and
    raised again.
    """
    notes: Annotations = []
    status, outputs, message, code = "error", {}, None, 1
    try:
        status, outputs = body(notes)
        code = 0
    except CommandError as error:
        message, code = str(error), error.code
        note(notes, "error", message, error.title or f"sca {command} failed")
        print(f"error: {message}", file=sys.stderr)
    except Exception as error:
        message = repr(error)
        note(notes, "error", message, f"sca {command} failed")
        raise
    finally:
        output_dir.mkdir(parents=True, exist_ok=True)
        dump_json(output_dir / "annotations.json", notes)
        dump_json(
            output_dir / "outputs.json",
            {
                "contract": CONTRACT,
                "command": command,
                "status": status,
                "engine": engine or os.environ.get("SCA_RUN_ENGINE_REF") or None,
                "message": message,
                "outputs": outputs,
            },
        )
    return code
