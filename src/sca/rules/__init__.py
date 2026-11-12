"""The rules the SCA scan engine and the fix planner share: the package key, the
version order, the upgrade target and the fixed-in-development state of a record.
One implementation of each. Standard library only; no side effects on import.
"""

from .development import (
    FIXED,
    INCOMPLETE,
    OPEN,
    REMOVED,
    Development,
    development_state,
    identifiers,
    key_of,
    usable,
)
from .keys import norm
from .target import ALLOW_MAJOR, choose_target, fixed_versions, upgrade_target
from .versions import (
    VersionError,
    compare,
    line_of,
    major,
    release_part,
    version_key,
)

__all__ = [
    "ALLOW_MAJOR",
    "FIXED",
    "INCOMPLETE",
    "OPEN",
    "REMOVED",
    "Development",
    "VersionError",
    "choose_target",
    "compare",
    "development_state",
    "fixed_versions",
    "identifiers",
    "key_of",
    "line_of",
    "major",
    "norm",
    "release_part",
    "upgrade_target",
    "usable",
    "version_key",
]
