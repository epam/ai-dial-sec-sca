"""Scan one target with Trivy: ``sca scan --targets-file F --target-id ID ...``.

Runs ``trivy fs .`` in ``--tree`` (a source target: the ``trivy.yaml`` of the
repository applies, the settings of ``sca.trivy.SCAN_ENV`` win) or ``trivy image REF``
against the databases of ``sca db`` in ``--cache-dir``. Writes into
``<parts-dir>/trivy``: ``<id>.json`` (the Trivy result, only if the scan is ``ok``),
``<id>.status.json`` (always, also when the scan broke), ``<id>.txt`` (the table),
``<id>.trivyignore`` (the ``.trivyignore`` of the tree, if there is one) and
``<id>.gradle-graph/`` (a copy of ``--graph-dir``). ``--failed REASON`` is a step before
the scan that broke: the target is failed with that reason and Trivy does not run.

A failed target exits 1 with the output ``status`` ``failed``, like the failed step of
a job; the merge reads the status part.

Registry credentials come only from ``SCA_REGISTRY_USER`` and ``SCA_REGISTRY_PASSWORD``
and are given to Trivy (``TRIVY_USERNAME``, ``TRIVY_PASSWORD``, in its environment, never
as arguments) only for an image of ``--registry``; any other target is anonymous.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from sca.lib import dump_json, read_json
from sca.lib.context import CommandError, UsageError
from sca.lib.outputs import Annotations, execute

from . import SCAN_ENV, trivy

USER_ENV, PASSWORD_ENV = "SCA_REGISTRY_USER", "SCA_REGISTRY_PASSWORD"
# the credentials Trivy takes from its environment: whatever the caller has set must not
# reach a scan that is not allowed them
CREDENTIAL_ENV = (USER_ENV, PASSWORD_ENV, "TRIVY_USERNAME", "TRIVY_PASSWORD", "TRIVY_REGISTRY_TOKEN")


def parse_args(argv: Sequence[str] | None, prog: str | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog=prog, description=__doc__)
    parser.add_argument("--targets-file", required=True, type=Path)
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--tree", type=Path, help="the checkout of a source (fs) target")
    parser.add_argument("--parts-dir", required=True, type=Path)
    parser.add_argument("--cache-dir", required=True, type=Path)
    parser.add_argument("--registry", help="the registry host the credentials are for")
    parser.add_argument("--lockfiles", type=int, help="number of generated Gradle lockfiles")
    parser.add_argument("--graph-dir", type=Path, help="the Gradle dependency graph to keep")
    parser.add_argument("--failed", help="the reason a step before the scan broke")
    parser.add_argument("--output-dir", default=Path("out"), type=Path)
    return parser.parse_args(argv)


def find_target(targets_file: Path, target_id: str) -> dict[str, Any]:
    try:
        targets = read_json(targets_file)["targets"]
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise UsageError(f"{targets_file} is not a readable targets file: {error!r}") from None
    for target in targets:
        if target["scanner"] == "trivy" and target["id"] == target_id:
            return target
    raise UsageError(f"{targets_file} has no Trivy target {target_id!r}")


def credentials(target: dict[str, Any], registry: str | None) -> dict[str, str]:
    """``TRIVY_USERNAME`` and ``TRIVY_PASSWORD`` for an image of ``registry``, else none."""
    user, password = os.environ.get(USER_ENV), os.environ.get(PASSWORD_ENV)
    if target["kind"] != "image" or not registry or not target["ref"].startswith(f"{registry}/"):
        return {}
    if bool(user) != bool(password):
        raise UsageError(f"{USER_ENV} and {PASSWORD_ENV} are set together or not at all")
    return {"TRIVY_USERNAME": user, "TRIVY_PASSWORD": password} if user and password else {}


def scan(
    args: argparse.Namespace,
    target: dict[str, Any],
    parts: Path,
    status: dict[str, Any],
    registry_env: dict[str, str],
) -> str | None:
    """The reason the target failed, if it did; ``status['ignorefile']`` is set here."""
    tid, fs = args.target_id, target["kind"] == "fs"
    if fs and args.tree:
        ignorefile = args.tree / ".trivyignore"
        status["ignorefile"] = "present" if ignorefile.is_file() else "absent"
        if ignorefile.is_file():
            shutil.copyfile(ignorefile, parts / f"{tid}.trivyignore")
    if args.graph_dir and args.graph_dir.is_dir():
        shutil.copytree(args.graph_dir, parts / f"{tid}.gradle-graph", dirs_exist_ok=True)
    if args.failed:
        return args.failed
    result, table = parts / f"{tid}.json", parts / f"{tid}.txt"
    env = SCAN_ENV | {"TRIVY_CACHE_DIR": str(args.cache_dir.resolve())}
    cwd = args.tree if fs else None
    output = ["--format", "json", "--output", str(result)]
    scanned = trivy(
        ["fs", *output, "."] if fs else ["image", *output, target["ref"]],
        env | registry_env,
        cwd,
        drop=CREDENTIAL_ENV,
    )
    if scanned.returncode:
        return "trivy scan failure"
    # the table is a convenience copy of the JSON; a failure here is not a failed target
    trivy(["convert", "--format", "table", "--output", str(table), str(result)], env, cwd, drop=CREDENTIAL_ENV)
    try:
        json.loads(result.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "trivy output is missing or is not valid JSON"
    return None


def main(argv: Sequence[str] | None = None, prog: str | None = None) -> int:
    args = parse_args(argv, prog)

    def body(_notes: Annotations) -> tuple[str, dict[str, Any]]:
        target = find_target(args.targets_file, args.target_id)
        if target["kind"] == "fs" and not args.tree and not args.failed:
            raise UsageError("a source (fs) target needs --tree")
        registry_env = credentials(target, args.registry)
        parts = args.parts_dir.resolve() / "trivy"
        parts.mkdir(parents=True, exist_ok=True)
        status: dict[str, Any] = {
            "id": args.target_id,
            "status": "ok",
            "reason": None,
            "lockfiles": args.lockfiles,
        }
        if target["kind"] == "fs":
            status["ignorefile"] = None
        try:
            reason = scan(args, target, parts, status, registry_env)
        except Exception as error:  # a broken scan must still leave its failed status
            reason = f"scan error: {error!r}"
        if reason:
            status |= {"status": "failed", "reason": reason}
            # the part of a failed target holds no result
            (parts / f"{args.target_id}.json").unlink(missing_ok=True)
        dump_json(parts / f"{args.target_id}.status.json", status)
        print(f"{args.target_id}: {status['status']}" + (f" ({reason})" if reason else ""))
        if reason:
            raise CommandError(
                f"{args.target_id}: {reason}", title="Trivy scan failed", outputs={"status": "failed"}
            )
        return "ok", {"status": "ok"}

    return execute("scan", args.output_dir, body)
