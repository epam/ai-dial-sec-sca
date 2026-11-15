"""Commit the applied files, push the fix branch and open or update the pull request."""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from sca.fix import apply_codes as codes
from sca.rules import norm

FAILING_STATUSES = (
    '[.statuses[] | select(.state == "failure" or .state == "error")'
    ' | .context] | join(", ")'
)
BOT_NAME = "github-actions[bot]"
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"
TRAILER = "SCA-Fixed"
TRANSIENT = frozenset(
    {
        codes.DEPENDABOT_REFUSED,
        codes.DEPENDABOT_NO_CHANGE,
        codes.DEPENDABOT_TIMEOUT,
        codes.DEPENDABOT_FAILED,
        codes.OVERRIDE_NPM_FAILED,
        codes.RESCAN_FAILED,
    }
)


class PublishError(RuntimeError):
    pass


def run(cmd: Sequence[str], cwd: Path | None = None, token: str = "") -> str:
    done = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        check=False,
        text=True,
        env={**os.environ, "GH_TOKEN": token} if token else None,
    )
    if done.returncode != 0:
        raise PublishError(
            f"{' '.join(cmd[:3])} failed: {(done.stderr or done.stdout).strip()[-500:]}"
        )
    return done.stdout.strip()


def baseline_ci(repo: str, branch: str, token: str) -> str:
    """The CI state of the untouched branch: the conclusion of its latest completed
    workflow run (``none`` without one), or ``failure`` when a commit status on the tip
    is failing (CI systems that report statuses and not workflow runs).
    """
    try:
        failing = run(
            [
                "gh",
                "api",
                f"repos/{repo}/commits/{branch}/status",
                "--jq",
                FAILING_STATUSES,
            ],
            token=token,
        )
    except PublishError:
        failing = ""
    if failing:
        return f"failure (commit status: {failing})"
    try:
        out = run(
            [
                "gh",
                "api",
                f"repos/{repo}/actions/runs",
                "-X",
                "GET",
                "-f",
                f"branch={branch}",
                "-f",
                "status=completed",
                "-f",
                "per_page=1",
                "--jq",
                '.workflow_runs[0].conclusion // "none"',
            ],
            token=token,
        )
    except PublishError:
        return "unknown"
    return out or "none"


def remote_fix_branch(tree: Path, branch: str, head: str) -> bool:
    """Fetch the release branch and, when it exists, the fix branch into ``origin/<name>``
    (the whole history of a shallow checkout, to tell the commits of the fix branch
    from those of the release branch). True when the fix branch exists.
    """
    exists = bool(run(["git", "ls-remote", "--heads", "origin", head], tree))
    cmd = ["git", "fetch", "--no-tags"]
    if run(["git", "rev-parse", "--is-shallow-repository"], tree) == "true":
        cmd.append("--unshallow")
    refs = [branch, head] if exists else [branch]
    run([*cmd, "origin", *(f"+refs/heads/{r}:refs/remotes/origin/{r}" for r in refs)], tree)
    return exists


def owned(tree: Path, branch: str, head: str, email: str) -> bool:
    """True when every commit of ``origin/<head>`` that is not on ``origin/<branch>`` has
    a fixer identity as author and as committer: the current one or the workflow bot.
    """
    emails = run(
        ["git", "log", "--format=%ae%n%ce", f"origin/{branch}..origin/{head}"], tree
    ).split()
    return all(a.lower() in {email.lower(), BOT_EMAIL} for a in emails)


def item_key(item: Mapping[str, Any]) -> str:
    return f"{item['class']}/{norm(item['pkg'])}"


def commit_message(title: str, items: Sequence[Mapping[str, Any]]) -> str:
    """``title`` and one ``SCA-Fixed: <class>/<package>`` trailer per applied item."""
    keys = sorted({item_key(i) for i in items if i["status"] == "applied"})
    trailers = "\n".join(f"{TRAILER}: {k}" for k in keys)
    return f"{title}\n\n{trailers}" if keys else title


def dropped(tree: Path, head: str, items: Sequence[Mapping[str, Any]]) -> list[str]:
    """The packages the fix branch head says it fixed (``SCA-Fixed`` trailers) that this
    run only has as a manual item with a transient code.
    """
    said = run(
        [
            "git",
            "log",
            "-1",
            f"--format=%(trailers:key={TRAILER},valueonly)",
            f"origin/{head}",
        ],
        tree,
    ).split()
    transient = {
        item_key(i)
        for i in items
        if i["status"] == "manual" and i["reason_code"] in TRANSIENT
    }
    return sorted(transient & set(said))


def closed_unmerged(repo: str, branch: str, head: str, token: str) -> bool:
    """True when the newest pull request from ``head`` was closed without a merge."""
    found = json.loads(
        run(
            [
                "gh",
                "pr",
                "list",
                "--repo",
                repo,
                "--head",
                head,
                "--base",
                branch,
                "--state",
                "all",
                "--limit",
                "1",
                "--json",
                "state",
            ],
            token=token,
        )
    )
    return bool(found) and found[0]["state"] == "CLOSED"


def publish(
    tree: Path,
    repo: str,
    branch: str,
    files: Sequence[str],
    title: str,
    body_file: Path,
    token: str,
    name: str = BOT_NAME,
    email: str = BOT_EMAIL,
    *,
    items: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Push ``sca-fix/<branch>`` (forced, with a lease on the fetched remote tip) with one
    commit of ``files`` on the tip of the branch, authored by the fixer identity ``name`` / ``email``, and open or update the
    pull request. Nothing is pushed when the release branch moved since the checkout
    (``base_moved``, the result has no pull request and the pull request is not touched),
    the remote fix branch, based on the same tip, holds a fix (``SCA-Fixed`` trailer)
    that this run has only as a manual item with a transient code (``fix_would_drop``),
    or the remote fix branch has commits of others
    (``branch_has_manual_changes``, the result has no pull request) or already holds
    the same tree on the same base (``unchanged``, the pull request is still
    updated), or the same tree as a branch whose newest pull request a human closed
    (``closed_unchanged``, nothing is reopened or created). The branch stays pushed when the pull request cannot be opened (the
    result says ``failed`` with the reason).
    """
    head = f"sca-fix/{branch}"
    exists = remote_fix_branch(tree, branch, head)
    base = run(["git", "rev-parse", "HEAD"], tree)
    if run(["git", "rev-parse", f"origin/{branch}"], tree) != base:
        return {
            "action": "none",
            "reason": f"{branch} moved during the run, not pushed; the next run starts from its tip",
            "reason_code": codes.BASE_MOVED,
        }
    if exists and not owned(tree, branch, head, email):
        return {
            "action": "none",
            "reason": f"{head} has commits of others, not pushed",
            "reason_code": codes.BRANCH_HAS_MANUAL_CHANGES,
        }
    if exists and run(["git", "rev-parse", f"origin/{head}^"], tree) == base:
        if lost := dropped(tree, head, items):
            return {
                "action": "none",
                "reason": f"{head} keeps fixes this run did not reproduce: {', '.join(lost)}",
                "reason_code": codes.FIX_WOULD_DROP,
            }
    run(["git", "checkout", "-B", head], tree)
    run(["git", "add", "--all", "--", *files], tree)
    same_tree = exists and run(["git", "write-tree"], tree) == run(
        ["git", "rev-parse", f"origin/{head}^{{tree}}"], tree
    )
    if same_tree:
        try:
            if closed_unmerged(repo, branch, head, token):
                return {
                    "action": "none",
                    "reason": f"the pull request of {head} was closed and the tree is unchanged",
                    "reason_code": codes.CLOSED_UNCHANGED,
                }
        except PublishError as exc:
            return {"head": head, "action": "failed", "reason": str(exc)}
    unchanged = same_tree and run(["git", "rev-parse", f"origin/{head}^"], tree) == base
    if not unchanged:
        run(
            [
                "git",
                "-c",
                f"user.name={name}",
                "-c",
                f"user.email={email}",
                "commit",
                "-m",
                commit_message(title, items),
            ],
            tree,
        )
        lease = run(["git", "rev-parse", f"origin/{head}"], tree) if exists else ""
        run(
            [
                "git",
                "push",
                f"--force-with-lease=refs/heads/{head}:{lease}",
                "origin",
                f"HEAD:refs/heads/{head}",
            ],
            tree,
        )
    try:
        pr = open_pull_request(repo, branch, head, title, body_file, token)
    except PublishError as exc:
        return {"head": head, "action": "failed", "reason": str(exc)}
    return {**pr, "reason_code": codes.UNCHANGED} if unchanged else pr


def open_pull_request(
    repo: str, branch: str, head: str, title: str, body_file: Path, token: str
) -> dict[str, Any]:
    """Update the open pull request from ``head`` or create one."""
    found = json.loads(
        run(
            [
                "gh",
                "pr",
                "list",
                "--repo",
                repo,
                "--head",
                head,
                "--base",
                branch,
                "--state",
                "open",
                "--json",
                "number,url",
            ],
            token=token,
        )
    )
    if found:
        number = str(found[0]["number"])
        run(
            [
                "gh",
                "pr",
                "edit",
                number,
                "--repo",
                repo,
                "--title",
                title,
                "--body-file",
                str(body_file),
            ],
            token=token,
        )
        return {
            "head": head,
            "action": "updated",
            "url": found[0]["url"],
            "number": found[0]["number"],
        }
    url = run(
        [
            "gh",
            "pr",
            "create",
            "--repo",
            repo,
            "--base",
            branch,
            "--head",
            head,
            "--title",
            title,
            "--body-file",
            str(body_file),
        ],
        token=token,
    )
    url = url.splitlines()[-1]
    number = re.search(r"/pull/(\d+)$", url)
    return {
        "head": head,
        "action": "created",
        "url": url,
        "number": int(number[1]) if number else None,
    }
