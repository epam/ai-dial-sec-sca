"""Trivy for the scan: the settings the engine owns and the way it runs ``trivy``.

``sca db`` downloads the vulnerability and Java databases, ``sca scan`` scans one
target against them.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path

# Database repositories, comma separated, tried in order (Trivy's own syntax)
DB_REPOSITORY = "mirror.gcr.io/aquasec/trivy-db:2,public.ecr.aws/aquasecurity/trivy-db:2,ghcr.io/aquasecurity/trivy-db:2"
JAVA_DB_REPOSITORY = "mirror.gcr.io/aquasec/trivy-java-db:1,public.ecr.aws/aquasecurity/trivy-java-db:1,ghcr.io/aquasecurity/trivy-java-db:1"

# The scan profile is the exposure of the repository, not a gate: nothing is ignored or
# filtered out. It is set by environment variables, which take precedence over the
# trivy.yaml of the scanned repository (read as is from the scan root, so its skip-dirs
# and skip-files still apply).
SCAN_ENV = {
    # /dev/null, not empty: Trivy treats an empty value as unset and reads .trivyignore
    "TRIVY_IGNOREFILE": "/dev/null",
    "TRIVY_IGNORE_UNFIXED": "false",
    "TRIVY_SEVERITY": "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
    "TRIVY_PKG_TYPES": "os,library",
    "TRIVY_SCANNERS": "vuln",
    # Trivy's default for JSON, set so that a trivy.yaml cannot disable the inventory
    "TRIVY_LIST_ALL_PKGS": "true",
    # Trivy skips dev dependencies by default
    "TRIVY_INCLUDE_DEV_DEPS": "true",
    # findings are the payload, not a failure
    "TRIVY_EXIT_CODE": "0",
    "TRIVY_DISABLE_VEX_NOTICE": "true",
    # every target of a run uses the databases downloaded by ``sca db``
    "TRIVY_SKIP_DB_UPDATE": "true",
    "TRIVY_SKIP_JAVA_DB_UPDATE": "true",
}


def trivy(
    args: Sequence[str],
    env: Mapping[str, str],
    cwd: Path | None = None,
    capture: bool = False,
    drop: Sequence[str] = (),
) -> subprocess.CompletedProcess[str]:
    """Run ``trivy`` with the process environment, minus ``drop``, plus ``env``; its
    output goes to the log unless ``capture``.
    """
    environ = {k: v for k, v in os.environ.items() if k not in drop} | dict(env)
    return subprocess.run(
        ["trivy", *args],
        env=environ,
        cwd=cwd,
        text=True,
        encoding="utf-8",
        capture_output=capture,
    )
