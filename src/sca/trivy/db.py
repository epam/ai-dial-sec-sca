"""Download the Trivy databases: ``sca db --cache-dir DIR``.

Downloads the vulnerability and the Java database into ``DIR`` with the installed
``trivy`` (so that the scan of every target of a run uses the same snapshot). Trivy runs
with nothing of the machine's configuration: no ``TRIVY_*`` but the repositories, no
Docker config, no credentials. Writes ``db-info.json`` (``vulnerability_db_updated_at``,
``java_db_updated_at``) into the output dir, which is also the output ``db-info`` and
the ``summary.md``.
"""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from sca.lib import dump_json
from sca.lib.context import CommandError
from sca.lib.outputs import Annotations, execute

from . import DB_REPOSITORY, JAVA_DB_REPOSITORY, isolated, trivy

DOWNLOADS = ("--download-db-only", "--download-java-db-only")


def parse_args(argv: Sequence[str] | None, prog: str | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog=prog, description=__doc__)
    parser.add_argument("--cache-dir", required=True, type=Path)
    parser.add_argument(
        "--trivy-db-repository",
        help="comma separated, tried in order; default: TRIVY_DB_REPOSITORY, else the engine's",
    )
    parser.add_argument(
        "--trivy-java-db-repository",
        help="comma separated, tried in order; default: TRIVY_JAVA_DB_REPOSITORY, else the engine's",
    )
    parser.add_argument("--output-dir", default=Path("out"), type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None, prog: str | None = None) -> int:
    args = parse_args(argv, prog)

    def body(_notes: Annotations) -> tuple[str, dict[str, Any]]:
        env = {
            "TRIVY_CACHE_DIR": str(args.cache_dir.resolve()),
            "TRIVY_DB_REPOSITORY": args.trivy_db_repository
            or os.environ.get("TRIVY_DB_REPOSITORY")
            or DB_REPOSITORY,
            "TRIVY_JAVA_DB_REPOSITORY": args.trivy_java_db_repository
            or os.environ.get("TRIVY_JAVA_DB_REPOSITORY")
            or JAVA_DB_REPOSITORY,
        }
        with isolated() as apart:
            for flag in DOWNLOADS:
                if (done := trivy(["image", flag], env | apart)).returncode:
                    raise CommandError(f"trivy image {flag} failed (exit {done.returncode})")
            done = trivy(["version", "--format", "json"], env | apart, capture=True)
        if done.returncode:
            raise CommandError(f"trivy version failed (exit {done.returncode})")
        try:
            version = json.loads(done.stdout)
        except ValueError:
            raise CommandError("trivy version printed no JSON") from None
        print(json.dumps(version, indent=2))
        info = {
            "vulnerability_db_updated_at": (version.get("VulnerabilityDB") or {}).get("UpdatedAt"),
            "java_db_updated_at": (version.get("JavaDB") or {}).get("UpdatedAt"),
        }
        args.output_dir.mkdir(parents=True, exist_ok=True)
        dump_json(args.output_dir / "db-info.json", info)
        compact = json.dumps(info, separators=(",", ":"), ensure_ascii=False)
        (args.output_dir / "summary.md").write_text(
            f"Trivy DB snapshot: {compact}\n", encoding="utf-8", newline="\n"
        )
        return "ok", {"db-info": info}

    return execute("db", args.output_dir, body)
