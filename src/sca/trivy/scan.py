"""Scan one target with Trivy: ``sca scan --targets-file F --target-id ID --kind K ...``.

Runs ``trivy fs .`` in ``--tree`` (a source target) or ``trivy image REF`` against the
databases of ``sca db`` in ``--cache-dir``. Trivy runs with nothing of the machine's
configuration (no inherited ``TRIVY_*``, no Docker config) and with the settings of
``sca.trivy.SCAN_ENV``; the ``trivy.yaml`` of the repository is never read. Writes into
``<parts-dir>/trivy``: ``<id>.json`` (the Trivy result, only if the scan is ``ok``),
``<id>.status.json`` (always, whatever broke after the arguments were read),
``<id>.txt`` (the table), ``<id>.trivyignore`` (the ``.trivyignore`` of the tree, if
there is one) and ``<id>.gradle-graph/`` (a copy of ``--graph-dir``). ``--failed REASON``
is a step before the scan that broke: the target is failed with that reason and Trivy
does not run, the targets file is not read.

A failed target exits 1 (a bad argument value, 2) with the output ``status`` ``failed``,
like the failed step of a job; the merge reads the status part.

Registry credentials come only from ``SCA_REGISTRY_USER`` and ``SCA_REGISTRY_PASSWORD``
(no comma: Trivy splits them on it) and are given to Trivy (``TRIVY_USERNAME``,
``TRIVY_PASSWORD``, in its environment, never as arguments) only for an image of
``--registry``, a host; any other target is anonymous.
"""

from __future__ import annotations

import argparse
import json
import shutil
import traceback
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from sca.lib import dump_json, read_json
from sca.lib.context import CommandError, UsageError
from sca.lib.outputs import Annotations, execute
from sca.lib.registry import login

from . import SCAN_ENV, isolated, trivy

TITLE = "Trivy target failed"


def parse_args(argv: Sequence[str] | None, prog: str | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog=prog, description=__doc__)
    parser.add_argument("--targets-file", required=True, type=Path)
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--kind", required=True, choices=("fs", "image"))
    parser.add_argument("--tree", type=Path, help="the checkout of a source (fs) target")
    parser.add_argument("--parts-dir", required=True, type=Path)
    parser.add_argument("--cache-dir", required=True, type=Path)
    parser.add_argument("--registry", help="the registry host the credentials are for")
    parser.add_argument("--lockfiles", type=int, help="number of generated Gradle lockfiles")
    parser.add_argument("--graph-dir", type=Path, help="the Gradle dependency graph to keep")
    parser.add_argument("--failed", help="the reason a step before the scan broke")
    parser.add_argument("--output-dir", default=Path("out"), type=Path)
    return parser.parse_args(argv)


def find_target(args: argparse.Namespace) -> dict[str, Any]:
    try:
        for target in read_json(args.targets_file)["targets"]:
            if target["scanner"] == "trivy" and target["id"] == args.target_id:
                if target["kind"] != args.kind:
                    raise UsageError(f"target {args.target_id!r} is {target['kind']!r}, not {args.kind!r}")
                return target
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise UsageError(f"{args.targets_file} is not a readable targets file: {error!r}") from None
    raise UsageError(f"{args.targets_file} has no Trivy target {args.target_id!r}")


def credentials(ref: str | None, registry: str | None) -> dict[str, str]:
    """``TRIVY_USERNAME`` and ``TRIVY_PASSWORD`` for an image of ``registry``, else none."""
    given = login(ref, registry)
    return {"TRIVY_USERNAME": given[0], "TRIVY_PASSWORD": given[1]} if given else {}


def scan(args: argparse.Namespace, parts: Path, status: dict[str, Any]) -> str | None:
    """The reason the target failed, if it did; ``status['ignorefile']`` is set here."""
    tid, fs = args.target_id, args.kind == "fs"
    if fs and not args.tree and not args.failed:
        raise UsageError("a source (fs) target needs --tree")
    ref = None if args.failed else find_target(args)["ref"]
    registry_env = credentials(ref, args.registry)
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
    output = ["--format", "json", "--output", str(result)]
    with isolated() as apart:
        scanned = trivy(
            ["fs", *output, "."] if fs else ["image", *output, ref],
            env | apart | registry_env,
            args.tree if fs else None,
        )
        if scanned.returncode:
            return "trivy scan failure"
        # the table is a convenience copy of the JSON; a failure here is not a failed target
        trivy(["convert", "--format", "table", "--output", str(table), str(result)], env | apart)
    try:
        json.loads(result.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "trivy output is missing or is not valid JSON"
    return None


def main(argv: Sequence[str] | None = None, prog: str | None = None) -> int:
    args = parse_args(argv, prog)

    def body(_notes: Annotations) -> tuple[str, dict[str, Any]]:
        parts = args.parts_dir.resolve() / "trivy"
        parts.mkdir(parents=True, exist_ok=True)
        status: dict[str, Any] = {
            "id": args.target_id,
            "status": "ok",
            "reason": None,
            "lockfiles": args.lockfiles,
        }
        if args.kind == "fs":
            status["ignorefile"] = None
        code = 1
        try:
            reason = scan(args, parts, status)
        except UsageError as error:
            reason, code = str(error), error.code
        except Exception as error:  # a broken scan must still leave its failed status
            traceback.print_exc()
            reason = f"scan error: {error!r}"
        if reason:
            status |= {"status": "failed", "reason": reason}
            # the part of a failed target holds no result
            (parts / f"{args.target_id}.json").unlink(missing_ok=True)
        dump_json(parts / f"{args.target_id}.status.json", status)
        print(f"{args.target_id}: {status['status']}" + (f" ({reason})" if reason else ""))
        if reason:
            raise CommandError(f"{args.target_id}: {reason}", code, TITLE, {"status": "failed"})
        return "ok", {"status": "ok"}

    return execute("scan", args.output_dir, body)
