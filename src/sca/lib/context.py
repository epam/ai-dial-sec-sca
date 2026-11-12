"""The run context an adapter passes to every command (``SCA_RUN_*``)."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


class CommandError(Exception):
    """A command that cannot go on: ``code`` is its exit code (1 error, 2 usage);
    ``outputs`` are the values it still leaves.
    """

    def __init__(
        self,
        message: str,
        code: int = 1,
        title: str | None = None,
        outputs: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.title = title
        self.outputs = outputs or {}


class UsageError(CommandError):
    """A bad argument, a missing required variable or an invalid input file."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code=2)


@dataclass(frozen=True)
class RunContext:
    host: str
    repo: str
    run_id: str
    attempt: int
    url: str
    event: str
    actor: str
    engine_ref: str | None


REQUIRED = {
    "host": "SCA_RUN_HOST",
    "repo": "SCA_RUN_REPO",
    "run_id": "SCA_RUN_ID",
    "url": "SCA_RUN_URL",
    "event": "SCA_RUN_EVENT",
    "actor": "SCA_RUN_ACTOR",
}


def read_run_context(environ: Mapping[str, str] | None = None) -> RunContext:
    """The run context of ``environ`` (default: the process environment); a missing
    required variable is a usage error. No other platform variable is read.
    """
    env = os.environ if environ is None else environ
    missing = [name for name in REQUIRED.values() if not env.get(name)]
    if missing:
        raise UsageError(f"missing environment variable(s): {', '.join(missing)}")
    attempt = env.get("SCA_RUN_ATTEMPT") or "1"
    if not attempt.isdecimal():
        raise UsageError(f"SCA_RUN_ATTEMPT must be a number, got {attempt!r}")
    return RunContext(
        **{field: env[name] for field, name in REQUIRED.items()},
        attempt=int(attempt),
        engine_ref=env.get("SCA_RUN_ENGINE_REF") or None,
    )
