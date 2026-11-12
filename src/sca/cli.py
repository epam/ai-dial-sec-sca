"""The ``sca`` command: ``sca <command> [arguments]``, each command is a module with a
``main(argv, prog) -> int`` of its own (``sca <command> --help`` shows its arguments).
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from importlib import import_module

COMMANDS = {
    "targets": ("sca.targets.resolve_targets", "resolve the scan targets (targets.json)"),
    "db": ("sca.trivy.db", "download the Trivy databases (db-info)"),
    "scan": ("sca.trivy.scan", "scan one target with Trivy (the Trivy parts)"),
    "osv": ("sca.osv.query_osv", "query OSV for the packages Trivy found"),
    "merge": ("sca.merge.merge_results", "merge the scan parts into report.json"),
    "plan": ("sca.plan.cli", "plan the fixes from report.json files"),
    "tools": ("sca.tools.cli", "install the tools of the scan (tools install)"),
}


def usage() -> str:
    rows = "\n".join(f"  {name:<8}{what}" for name, (_, what) in COMMANDS.items())
    return f"usage: sca <command> [arguments]\n\ncommands:\n{rows}\n"


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help"):
        print(usage(), end="")
        return 0 if args else 2
    if args[0] not in COMMANDS:
        print(f"sca: unknown command {args[0]!r}\n\n{usage()}", end="", file=sys.stderr)
        return 2
    return import_module(COMMANDS[args[0]][0]).main(args[1:], prog=f"sca {args[0]}")


if __name__ == "__main__":
    sys.exit(main())
