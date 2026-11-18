import subprocess
from pathlib import Path
from typing import Any

from sca.fix import publish as publish_module
import pytest
from sca.fix.publish import PublishError, baseline_ci, publish


def git(cwd: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True
    )
    return done.stdout.strip()


@pytest.fixture
def clone(tmp_path: Path) -> Path:
    remote = tmp_path / "remote.git"
    git(tmp_path, "init", "--bare", "-b", "release-1.2", str(remote))
    work = tmp_path / "work"
    git(tmp_path, "clone", str(remote), str(work))
    (work / "lock").write_text("old", encoding="utf-8")
    git(work, "add", "lock")
    git(work, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-m", "base")
    git(work, "push", "origin", "HEAD:release-1.2")
    (work / "lock").write_text("new", encoding="utf-8")
    (work / "scratch").write_text("never committed", encoding="utf-8")
    return work


def test_pushes_the_fix_branch_with_only_the_applied_files(
    clone: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[Any, ...]] = []

    def opened(*args: Any) -> dict[str, Any]:
        calls.append(args)
        return {"head": args[2], "action": "created", "url": "u"}

    monkeypatch.setattr(publish_module, "open_pull_request", opened)
    result = publish(clone, "o/r", "release-1.2", ["lock"], "title", clone / "b", "", items=())
    assert result["action"] == "created"
    assert calls[0][:3] == ("o/r", "release-1.2", "sca-fix/release-1.2")
    files = git(clone, "ls-tree", "-r", "--name-only", "origin/sca-fix/release-1.2")
    assert files == "lock"
    assert git(clone, "show", "origin/sca-fix/release-1.2:lock") == "new"
    assert (
        git(clone, "log", "-1", "--format=%s", "origin/sca-fix/release-1.2") == "title"
    )


def test_a_pull_request_failure_keeps_the_pushed_branch(
    clone: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refused(*args: Any) -> dict[str, Any]:
        raise PublishError("not permitted")

    monkeypatch.setattr(publish_module, "open_pull_request", refused)
    result = publish(clone, "o/r", "release-1.2", ["lock"], "title", clone / "b", "", items=())
    assert result == {
        "head": "sca-fix/release-1.2",
        "action": "failed",
        "reason": "not permitted",
    }
    assert git(clone, "ls-remote", "--heads", "origin", "sca-fix/release-1.2")


APP = ("sca-app[bot]", "7+sca-app[bot]@users.noreply.github.com")
FIX = "sca-fix/release-1.2"


@pytest.fixture
def opened(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(repo: str, branch: str, head: str, *rest: Any) -> dict[str, Any]:
        return {"head": head, "action": "updated", "url": "u"}

    monkeypatch.setattr(publish_module, "open_pull_request", fake)
    monkeypatch.setattr(publish_module, "closed_unmerged", lambda *args: False)


def run_fixer(
    work: Path,
    content: str = "new",
    who: tuple[str, str] = APP,
    items: list[dict[str, Any]] = [],
) -> Any:
    """One fixer run: a fresh checkout of the release branch with ``lock`` changed."""
    git(work, "checkout", "-f", "-q", "release-1.2")
    (work / "lock").write_text(content, encoding="utf-8")
    return publish(
        work, "o/r", "release-1.2", ["lock"], "t", work / "b", "", *who, items=items
    )


def fixed(
    pkg: str,
    status: str = "applied",
    code: str | None = None,
    planned: tuple[str, ...] = ("2.0.0",),
    result: str | None = None,
) -> dict[str, Any]:
    return {
        "class": "lang",
        "pkg": pkg,
        "status": status,
        "reason_code": code,
        "planned": list(planned),
        "dependabot_result": result,
    }


def remote_sha(work: Path) -> str:
    return git(work, "ls-remote", "--heads", "origin", FIX).split()[0]


def other_clone(work: Path) -> Path:
    other = work.parent / "other"
    git(work.parent, "clone", "-q", str(work.parent / "remote.git"), str(other))
    return other


def commit_as(repo: Path, email: str, text: str) -> None:
    (repo / "lock").write_text(text, encoding="utf-8")
    git(repo, "-c", "user.name=x", "-c", f"user.email={email}", "commit", "-qam", text)


def test_n7_2_identity_is_author_and_committer(clone: Path, opened: None) -> None:
    run_fixer(clone)
    assert git(clone, "log", "-1", "--format=%an %ae|%cn %ce", f"origin/{FIX}") == (
        f"{APP[0]} {APP[1]}|{APP[0]} {APP[1]}"
    )


def test_n7_2_changed_tree_of_an_owned_branch_is_pushed(
    clone: Path, opened: None
) -> None:
    run_fixer(clone, "new")
    first = remote_sha(clone)
    result = run_fixer(clone, "newer")
    assert remote_sha(clone) != first
    assert git(clone, "show", f"origin/{FIX}:lock") == "newer"
    assert "reason_code" not in result


def test_n7_2_same_tree_on_the_same_base_is_not_pushed(
    clone: Path, opened: None
) -> None:
    run_fixer(clone)
    first = remote_sha(clone)
    result = run_fixer(clone)
    assert remote_sha(clone) == first
    assert result == {
        "head": FIX,
        "action": "updated",
        "url": "u",
        "reason_code": "unchanged",
    }


def test_n7_2_the_workflow_bot_counts_as_a_fixer(clone: Path, opened: None) -> None:
    run_fixer(clone, who=(publish_module.BOT_NAME, publish_module.BOT_EMAIL))
    first = remote_sha(clone)
    assert run_fixer(clone)["reason_code"] == "unchanged"
    assert remote_sha(clone) == first


def test_n7_2_commit_of_a_human_on_top_stops_the_push(
    clone: Path, opened: None
) -> None:
    run_fixer(clone, "new")
    other = other_clone(clone)
    git(other, "checkout", "-q", FIX)
    commit_as(other, "dev@x", "hand")
    git(other, "push", "-q", "origin", FIX)
    before = remote_sha(clone)
    result = run_fixer(clone, "newer")
    assert remote_sha(clone) == before
    assert result["action"] == "none"
    assert result["reason_code"] == "branch_has_manual_changes"


def test_n7_2_commit_of_a_human_below_a_fixer_commit_stops_the_push(
    clone: Path, opened: None
) -> None:
    other = other_clone(clone)
    git(other, "checkout", "-q", "-b", FIX)
    commit_as(other, "dev@x", "hand")
    commit_as(other, APP[1], "fixer")
    git(other, "push", "-q", "origin", FIX)
    before = remote_sha(clone)
    result = run_fixer(clone)
    assert remote_sha(clone) == before
    assert result["reason_code"] == "branch_has_manual_changes"


def test_n7_2_a_moved_release_branch_gets_a_new_commit(
    clone: Path, opened: None
) -> None:
    run_fixer(clone)
    first = remote_sha(clone)
    other = other_clone(clone)
    (other / "more").write_text("x", encoding="utf-8")
    git(other, "add", "more")
    git(other, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "moved")
    git(other, "push", "-q", "origin", "HEAD:release-1.2")
    git(clone, "fetch", "-q", "origin")
    git(clone, "checkout", "-f", "-q", "-B", "release-1.2", "origin/release-1.2")
    (clone / "lock").write_text("new", encoding="utf-8")
    result = publish(clone, "o/r", "release-1.2", ["lock"], "t", clone / "b", "", *APP, items=())
    assert remote_sha(clone) != first
    assert "reason_code" not in result
    assert git(clone, "rev-parse", f"origin/{FIX}^") == git(
        clone, "rev-parse", "origin/release-1.2"
    )


def test_n7_2_a_shallow_checkout_is_told_from_the_history(
    clone: Path, tmp_path: Path, opened: None
) -> None:
    run_fixer(clone)
    shallow = tmp_path / "shallow"
    git(tmp_path, "clone", "-q", "--depth", "1", "-b", "release-1.2",
        (tmp_path / "remote.git").as_uri(), str(shallow))
    (shallow / "lock").write_text("new", encoding="utf-8")
    before = remote_sha(clone)
    result = publish(shallow, "o/r", "release-1.2", ["lock"], "t", shallow / "b", "", *APP, items=())
    assert remote_sha(clone) == before
    assert result["reason_code"] == "unchanged"


def test_baseline_ci_reports_a_failing_commit_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def gh(cmd: list[str], cwd: Path | None = None, token: str = "") -> str:
        calls.append(cmd)
        return "ci/build, ci/lint" if "status" in cmd[2] else "success"

    monkeypatch.setattr(publish_module, "run", gh)
    assert (
        baseline_ci("o/r", "w/release-1.2", "t")
        == "failure (commit status: ci/build, ci/lint)"
    )
    assert calls[0][2] == "repos/o/r/commits/w/release-1.2/status"


def test_baseline_ci_falls_back_to_the_latest_workflow_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def gh(cmd: list[str], cwd: Path | None = None, token: str = "") -> str:
        return "" if "status" in cmd[2] else "cancelled"

    monkeypatch.setattr(publish_module, "run", gh)
    assert baseline_ci("o/r", "b", "t") == "cancelled"

    def refused(cmd: list[str], cwd: Path | None = None, token: str = "") -> str:
        raise PublishError("403")

    monkeypatch.setattr(publish_module, "run", refused)
    assert baseline_ci("o/r", "b", "t") == "unknown"


def test_n7_2_2_a_commit_of_a_human_on_a_fixer_authored_commit_is_not_owned(
    clone: Path, opened: None
) -> None:
    # `git commit --amend` by a human keeps the author: the committer tells
    run_fixer(clone, "new")
    other = other_clone(clone)
    git(other, "checkout", "-q", FIX)
    (other / "lock").write_text("amended", encoding="utf-8")
    git(
        other,
        "-c",
        "user.name=dev",
        "-c",
        "user.email=dev@x",
        "commit",
        "-qa",
        "--amend",
        "--no-edit",
        f"--author={APP[0]} <{APP[1]}>",
    )
    git(other, "push", "-q", "--force", "origin", FIX)
    before = remote_sha(clone)
    result = run_fixer(clone, "newer")
    assert remote_sha(clone) == before
    assert result["reason_code"] == "branch_has_manual_changes"


def test_n7_2_3_a_branch_of_another_token_kind_is_not_owned(
    clone: Path, opened: None
) -> None:
    run_fixer(clone, "new", who=("octo", "1+octo@users.noreply.github.com"))
    before = remote_sha(clone)
    result = run_fixer(clone, "newer", who=APP)
    assert remote_sha(clone) == before
    assert result["reason_code"] == "branch_has_manual_changes"


def pushes(monkeypatch: pytest.MonkeyPatch, before: Any = None) -> list[list[str]]:
    """The push commands of publish; ``before`` runs just ahead of each one."""
    seen: list[list[str]] = []
    real = publish_module.run

    def spy(cmd: Any, *args: Any, **kwargs: Any) -> str:
        if cmd[:2] == ["git", "push"]:
            seen.append(list(cmd))
            if before:
                before()
        return real(cmd, *args, **kwargs)

    monkeypatch.setattr(publish_module, "run", spy)
    return seen


def test_n7_2_4_a_moved_release_branch_is_not_pushed_and_the_pr_not_touched(
    clone: Path, opened: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    other = other_clone(clone)
    commit_as(other, "t@t", "moved")
    git(other, "push", "-q", "origin", "HEAD:release-1.2")
    seen = pushes(monkeypatch)
    monkeypatch.setattr(publish_module, "open_pull_request", pytest.fail)
    git(clone, "checkout", "-f", "-q", "release-1.2")
    (clone / "lock").write_text("new", encoding="utf-8")
    result = publish(clone, "o/r", "release-1.2", ["lock"], "t", clone / "b", "", items=())
    assert result["action"] == "none"
    assert result["reason_code"] == "base_moved"
    assert seen == []
    assert not git(clone, "ls-remote", "--heads", "origin", FIX)


def test_n7_2_4_an_unmoved_release_branch_is_pushed(
    clone: Path, opened: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = pushes(monkeypatch)
    assert "reason_code" not in run_fixer(clone)
    assert len(seen) == 1
    assert remote_sha(clone)


def test_n7_2_4_the_lease_expects_no_branch_for_a_new_fix_branch(
    clone: Path, opened: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = pushes(monkeypatch)
    run_fixer(clone)
    assert seen[0][2] == f"--force-with-lease=refs/heads/{FIX}:"


def test_n7_2_4_the_lease_expects_the_fetched_tip_of_an_existing_fix_branch(
    clone: Path, opened: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_fixer(clone, "new")
    tip = remote_sha(clone)
    seen = pushes(monkeypatch)
    run_fixer(clone, "newer")
    assert seen[0][2] == f"--force-with-lease=refs/heads/{FIX}:{tip}"


def test_n7_2_4_a_push_to_the_fix_branch_during_the_run_is_not_overwritten(
    clone: Path, opened: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_fixer(clone, "new")
    other = other_clone(clone)
    git(other, "checkout", "-q", "-B", "x", f"origin/{FIX}")
    commit_as(other, "h@h", "human")

    def human_push() -> None:
        git(other, "push", "-q", "origin", f"HEAD:{FIX}")

    pushes(monkeypatch, human_push)
    with pytest.raises(PublishError):
        run_fixer(clone, "newer")
    assert git(other, "show", f"{remote_sha(clone)}:lock") == "human"


def test_n7_3_a_closed_pull_request_with_the_same_tree_is_not_reopened(
    clone: Path, opened: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_fixer(clone, "new")
    first = remote_sha(clone)
    monkeypatch.setattr(publish_module, "closed_unmerged", lambda *args: True)
    created: list[Any] = []
    monkeypatch.setattr(
        publish_module, "open_pull_request", lambda *args: created.append(args)
    )
    result = run_fixer(clone, "new")
    assert remote_sha(clone) == first
    assert created == []
    assert result["action"] == "none"
    assert result["reason_code"] == "closed_unchanged"


def test_n7_3_a_closed_pull_request_with_a_different_tree_gets_a_new_one(
    clone: Path, opened: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_fixer(clone, "new")
    first = remote_sha(clone)
    monkeypatch.setattr(publish_module, "closed_unmerged", lambda *args: True)
    result = run_fixer(clone, "newer")
    assert remote_sha(clone) != first
    assert result["action"] == "updated"
    assert "reason_code" not in result


def test_n7_3_closed_unmerged_reads_the_newest_pull_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    answers = iter(['[{"state": "CLOSED"}]', '[{"state": "MERGED"}]', "[]"])
    seen: list[list[str]] = []

    def gh(cmd: list[str], cwd: Path | None = None, token: str = "") -> str:
        seen.append(cmd)
        return next(answers)

    monkeypatch.setattr(publish_module, "run", gh)
    assert publish_module.closed_unmerged("o/r", "b", "h", "t") is True
    assert publish_module.closed_unmerged("o/r", "b", "h", "t") is False
    assert publish_module.closed_unmerged("o/r", "b", "h", "t") is False
    assert "--limit" in seen[0] and "all" in seen[0]


def test_u2_a_created_pull_request_carries_its_number(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    answers = iter(["[]", "https://github.com/o/r/pull/42"])
    monkeypatch.setattr(publish_module, "run", lambda *args, **kw: next(answers))
    pr = publish_module.open_pull_request("o/r", "b", "h", "t", tmp_path / "b", "")
    assert pr == {
        "head": "h",
        "action": "created",
        "url": "https://github.com/o/r/pull/42",
        "number": 42,
    }


def test_u2_an_updated_pull_request_carries_its_number(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    listed = '[{"number": 7, "url": "https://github.com/o/r/pull/7"}]'
    answers = iter([listed, ""])
    monkeypatch.setattr(publish_module, "run", lambda *args, **kw: next(answers))
    pr = publish_module.open_pull_request("o/r", "b", "h", "t", tmp_path / "b", "")
    assert pr["action"] == "updated" and pr["number"] == 7


def test_u2_a_url_without_a_number_gives_a_null_number(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    answers = iter(["[]", "created somewhere"])
    monkeypatch.setattr(publish_module, "run", lambda *args, **kw: next(answers))
    pr = publish_module.open_pull_request("o/r", "b", "h", "t", tmp_path / "b", "")
    assert pr["number"] is None




def message(work: Path) -> str:
    return git(work, "log", "-1", "--format=%B", f"origin/{FIX}")


def test_n7_2_4_the_commit_message_has_a_sorted_trailer_per_applied_item(
    clone: Path, opened: None
) -> None:
    items = [
        fixed("Zed_lib", planned=("3.0.0", "2.1.0")),
        fixed("a.b", planned=()),
        fixed("m", "manual", "needs_major"),
    ]
    run_fixer(clone, items=items)
    assert message(clone) == (
        "t\n\nSCA-Fixed: lang/a-b -\nSCA-Fixed: lang/zed-lib 2.1.0,3.0.0"
    )


def test_n7_2_4_no_applied_item_gives_no_trailer(clone: Path, opened: None) -> None:
    run_fixer(clone, items=[fixed("m", "manual", "needs_major")])
    assert message(clone) == "t"


def guarded(clone: Path, monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """A fix branch that holds a proven fix of ``lodash``; no push or PR call after."""
    run_fixer(clone, "new", items=[fixed("lodash")])
    seen = pushes(monkeypatch)
    monkeypatch.setattr(publish_module, "open_pull_request", pytest.fail)
    return seen


def held(clone: Path, seen: list[list[str]], items: list[dict[str, Any]]) -> None:
    before = remote_sha(clone)
    result = run_fixer(clone, "newer", items=items)
    assert result["action"] == "none"
    assert result["reason_code"] == "fix_would_drop"
    assert "lang/lodash" in result["reason"]
    assert seen == []
    assert remote_sha(clone) == before


TRANSIENT_CODES = [
    "dependabot_refused",
    "dependabot_no_change",
    "dependabot_timeout",
    "dependabot_failed",
    "override_npm_failed",
    "rescan_failed",
    "image_build_failed",
]


@pytest.mark.parametrize("code", TRANSIENT_CODES)
def test_n7_2_5a_a_transient_reason_code_keeps_the_branch(
    clone: Path, opened: None, monkeypatch: pytest.MonkeyPatch, code: str
) -> None:
    seen = guarded(clone, monkeypatch)
    held(clone, seen, [fixed("Lodash", "manual", code)])


@pytest.mark.parametrize(
    "result",
    [
        "security_update_not_possible",
        "security_update_dependency_not_found",
        "security_update_not_needed",
        "dependabot_no_change",
        "dependabot_timeout",
    ],
)
def test_n7_2_5a_a_recorded_fallback_result_keeps_the_branch(
    clone: Path, opened: None, monkeypatch: pytest.MonkeyPatch, result: str
) -> None:
    seen = guarded(clone, monkeypatch)
    manual = fixed("Lodash", "manual", "override_direct", result=result)
    held(clone, seen, [manual])


def test_n7_2_5a_no_result_and_a_nontransient_code_does_not_hold(
    clone: Path, opened: None
) -> None:
    run_fixer(clone, "new", items=[fixed("lodash")])
    first = remote_sha(clone)
    manual = fixed("lodash", "manual", "override_direct", result=None)
    assert "reason_code" not in run_fixer(clone, "newer", items=[manual])
    assert remote_sha(clone) != first


def root_commit_on_fix_branch(clone: Path) -> None:
    other = other_clone(clone)
    git(other, "checkout", "-q", FIX)
    git(other, "checkout", "-q", "--orphan", "root")
    git(other, "-c", f"user.name={APP[0]}", "-c", f"user.email={APP[1]}", "commit", "-qm", "r")
    git(other, "push", "-qf", "origin", f"root:{FIX}")


def test_n7_2_5a_a_root_commit_with_the_same_tree_is_rebuilt_not_an_error(
    clone: Path, opened: None
) -> None:
    run_fixer(clone, "new", items=[fixed("lodash")])
    root_commit_on_fix_branch(clone)
    first = remote_sha(clone)
    run_fixer(clone, "new", items=[fixed("lodash")])
    assert remote_sha(clone) != first


def test_n7_2_5a_a_merge_commit_has_two_parents(clone: Path, opened: None) -> None:
    run_fixer(clone, "new", items=[fixed("lodash")])
    tree = git(clone, "rev-parse", f"origin/{FIX}^{{tree}}")
    both = [git(clone, "rev-parse", f"origin/{r}") for r in ("release-1.2", FIX)]
    merge = git(clone, "-c", "user.name=t", "-c", "user.email=t@t", "commit-tree", tree, "-p", both[0], "-p", both[1], "-m", "m")
    git(clone, "update-ref", "refs/remotes/origin/m", merge)
    assert publish_module.parents(clone, "m") == both
    assert publish_module.parents(clone, "release-1.2") == []


def test_n7_2_5a_a_hold_comes_before_a_closed_pull_request(
    clone: Path, opened: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_fixer(clone, "new", items=[fixed("lodash")])
    monkeypatch.setattr(publish_module, "closed_unmerged", lambda *args: True)
    monkeypatch.setattr(publish_module, "open_pull_request", pytest.fail)
    manual = fixed("lodash", "manual", "dependabot_refused")
    result = run_fixer(clone, "new", items=[manual])
    assert result["reason_code"] == "fix_would_drop"


def test_n7_2_5a_ownership_comes_before_a_hold(clone: Path, opened: None) -> None:
    run_fixer(clone, "new", items=[fixed("lodash")])
    other = other_clone(clone)
    git(other, "checkout", "-q", FIX)
    commit_as(other, "dev@x", "hand")
    git(other, "push", "-q", "origin", FIX)
    manual = fixed("lodash", "manual", "dependabot_refused")
    result = run_fixer(clone, "newer", items=[manual])
    assert result["reason_code"] == "branch_has_manual_changes"


@pytest.mark.parametrize(
    "items",
    [
        [fixed("lodash", "already_fixed", "not_in_baseline")],
        [fixed("lodash", "manual", "needs_major")],
        [fixed("other", "manual", "dependabot_refused")],
        [fixed("lodash", "manual", "dependabot_refused", planned=("3.0.0",))],
        [fixed("lodash", "manual", "dependabot_refused", planned=())],
        [],
    ],
)
def test_n7_2_5a_other_outcomes_may_shrink_the_branch(
    clone: Path, opened: None, items: list[Any]
) -> None:
    run_fixer(clone, "new", items=[fixed("lodash")])
    first = remote_sha(clone)
    result = run_fixer(clone, "newer", items=items)
    assert remote_sha(clone) != first
    assert "reason_code" not in result


def test_n7_2_5a_a_branch_with_two_commits_is_rebuilt(
    clone: Path, opened: None
) -> None:
    run_fixer(clone, "new", items=[fixed("lodash")])
    other = other_clone(clone)
    git(other, "checkout", "-q", FIX)
    commit_as(other, APP[1], "second")
    git(other, "push", "-q", "origin", FIX)
    first = remote_sha(clone)
    manual = fixed("lodash", "manual", "dependabot_refused")
    result = run_fixer(clone, "newer", items=[manual])
    assert remote_sha(clone) != first
    assert "reason_code" not in result


def test_n7_2_5a_a_commit_of_the_workflow_bot_is_rebuilt(
    clone: Path, opened: None
) -> None:
    bot = ("github-actions[bot]", publish_module.BOT_EMAIL)
    run_fixer(clone, "new", items=[fixed("lodash")], who=bot)
    first = remote_sha(clone)
    manual = fixed("lodash", "manual", "dependabot_refused")
    result = run_fixer(clone, "newer", items=[manual])
    assert remote_sha(clone) != first
    assert "reason_code" not in result


def test_n7_2_5a_a_branch_on_an_older_release_tip_is_rebuilt(
    clone: Path, opened: None
) -> None:
    run_fixer(clone, "new", items=[fixed("lodash")])
    other = other_clone(clone)
    commit_as(other, "t@t", "moved")
    git(other, "push", "-q", "origin", "HEAD:release-1.2")
    git(clone, "fetch", "-q", "origin", "+release-1.2:release-1.2")
    first = remote_sha(clone)
    manual = fixed("lodash", "manual", "dependabot_refused")
    result = run_fixer(clone, "newer", items=[manual])
    assert remote_sha(clone) != first
    assert "reason_code" not in result


def test_n7_2_5a_a_branch_without_trailers_is_rebuilt(
    clone: Path, opened: None
) -> None:
    run_fixer(clone, "new")
    first = remote_sha(clone)
    manual = fixed("lodash", "manual", "dependabot_refused")
    result = run_fixer(clone, "newer", items=[manual])
    assert remote_sha(clone) != first
    assert "reason_code" not in result


def test_n7_2_5a_a_raw_security_update_result_on_the_override_path_holds(
    clone: Path, opened: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = guarded(clone, monkeypatch)
    manual = fixed(
        "lodash", "manual", "override_direct", result="security_update_not_possible"
    )
    held(clone, seen, [manual])


def test_n7_2_5a_an_image_build_failure_of_an_os_item_holds(
    clone: Path, opened: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    os_item = {**fixed("libssl3"), "class": "os"}
    run_fixer(clone, "new", items=[os_item])
    seen = pushes(monkeypatch)
    monkeypatch.setattr(publish_module, "open_pull_request", pytest.fail)
    manual = {**fixed("libssl3", "manual", "image_build_failed"), "class": "os"}
    before = remote_sha(clone)
    result = run_fixer(clone, "newer", items=[manual])
    assert (
        result["reason_code"] == "fix_would_drop" and "os/libssl3" in result["reason"]
    )
    assert seen == [] and remote_sha(clone) == before


def test_n7_2_5a_the_trailers_of_reapplied_items_still_hold_the_others(
    clone: Path, opened: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_fixer(clone, "new", items=[fixed("lodash"), fixed("minimist")])
    seen = pushes(monkeypatch)
    monkeypatch.setattr(publish_module, "open_pull_request", pytest.fail)
    items = [fixed("lodash"), fixed("minimist", "manual", "dependabot_failed")]
    before = remote_sha(clone)
    result = run_fixer(clone, "newer", items=items)
    assert result["reason_code"] == "fix_would_drop"
    assert "lang/minimist" in result["reason"] and "lang/lodash" not in result["reason"]
    assert seen == [] and remote_sha(clone) == before


def test_n7_2_5a_a_root_commit_fix_branch_is_rebuilt(clone: Path, opened: None) -> None:
    run_fixer(clone, "new", items=[fixed("lodash")])
    git(clone, "checkout", "-q", "--orphan", "root")
    git(clone, "add", "-A")
    git(
        clone,
        "-c",
        f"user.name={APP[0]}",
        "-c",
        f"user.email={APP[1]}",
        "commit",
        "-qm",
        "root",
    )
    git(clone, "push", "-qf", "origin", f"root:{FIX}")
    first = remote_sha(clone)
    manual = fixed("lodash", "manual", "dependabot_refused")
    result = run_fixer(clone, "newer", items=[manual])
    assert remote_sha(clone) != first
    assert "reason_code" not in result
