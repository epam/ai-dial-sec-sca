"""The package key of the report."""

from __future__ import annotations

import re


def norm(pkg: str) -> str:
    """The package key of the report: lowercase, each run of ``-``, ``_``, ``.`` as
    one ``-`` (PEP 503 for every ecosystem; applying it twice changes nothing).
    """
    return re.sub(r"[-_.]+", "-", pkg.lower())
