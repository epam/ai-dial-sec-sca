"""The rules the SCA scan engine and the fix planner share: the package key, the
version order, the upgrade target and the fixed-in-development state of a record.
One implementation of each. Standard library only; no side effects on import.
"""

from .development import (
    FIXED,
    OPEN,
    REMOVED,
    development_state,
    identifiers,
    key_of,
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

__version__ = "0.8.1"

__all__ = [
    "ALLOW_MAJOR",
    "FIXED",
    "OPEN",
    "REMOVED",
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
    "version_key",
]
