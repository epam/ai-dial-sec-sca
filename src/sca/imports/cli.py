"""``sca import <source> [arguments]``: convert the report of another scanner to a
schema 4 ``report.json``.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from importlib import import_module

SOURCES = {"snyk": "sca.imports.snyk"}


def main(argv: Sequence[str] | None = None, prog: str | None = None) -> int:
    args = list(argv or [])
    if not args or args[0] not in SOURCES:
        print(f"usage: {prog or 'sca import'} {{{','.join(SOURCES)}}} [arguments]", file=sys.stderr)
        return 2
    return import_module(SOURCES[args[0]]).main(args[1:], prog=f"{prog} {args[0]}")
