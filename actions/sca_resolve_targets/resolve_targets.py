#!/usr/bin/env python3
"""Resolve the scan targets (source snapshot + container images) of one repository.

Used by the SCA scheduled scan. Asks the GitHub REST API through ``gh api`` (token in
``GH_TOKEN``) and the image registry through ``oras repo tags`` (both are on the
runner). Standard library only. The run (host, run id, URL, event, actor) comes from
the ``SCA_RUN_*`` environment, see ``_sca_lib.context``. Writes ``targets.json``,
``outputs.json`` (``matrix``, ``targets-file``) and ``annotations.json`` into the
output directory.

Every call of an external tool goes through a ``Runner`` (a callable
``(argv, stdin) -> stdout``), so the logic can be tested with a fake runner and no
network.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NamedTuple

from _sca_lib import dump_json
from _sca_lib.context import CommandError, RunContext, UsageError, read_run_context
from _sca_lib.outputs import Annotations, execute, note

GITHUB_API_VERSION = "2022-11-28"
GHCR_HOST = "ghcr.io"
DOCKER_HUB_HOST = "registry-1.docker.io"
# Docker Hub answers the registry API on another host than the one it goes by
HOST_ALIASES = {"docker.io": DOCKER_HUB_HOST, "index.docker.io": DOCKER_HUB_HOST}

TOOL_TIMEOUT_SECONDS = 120.0
MAX_ATTEMPTS = 4
BACKOFF_BASE_SECONDS = 1.0
RELEASES_PER_PAGE = 100
# a cap on the pages read (1000 releases), so a runaway listing cannot loop on
MAX_RELEASE_PAGES = 10

_NAME_PART = r"[a-z0-9]+(?:[._-][a-z0-9]+)*"
IMAGE_NAME = re.compile(rf"{_NAME_PART}(?:/{_NAME_PART})*", re.ASCII)
REPOSITORY_NAME = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", re.ASCII)
UNSAFE_ID_CHARS = re.compile(r"[^A-Za-z0-9._-]")
# A client error (not rate limiting) will not go away by itself: no retry.
PERMANENT_ERROR = re.compile(r"(?:HTTP|status code:?) (?!429)4\d\d", re.IGNORECASE)
NOT_FOUND = re.compile(r"(?:HTTP|status code:?) 404", re.IGNORECASE)


class ResolveError(Exception):
    """A GitHub or registry request that failed, or an input that is unusable."""


class ToolError(Exception):
    """An external tool (``gh``, ``oras``) failed; the message is its stderr."""


Runner = Callable[[Sequence[str], str | None], str]


def make_runner(
    token: str | None, sleep: Callable[[float], None] = time.sleep
) -> Runner:
    """The production runner: ``subprocess.run`` with a timeout and bounded retries.

    ``gh`` gets the token as ``GH_TOKEN``. A failure is retried with a growing delay
    unless it is a client error (HTTP 4xx other than 429).
    """
    env = {**os.environ, **({"GH_TOKEN": token} if token else {})}

    def run_tool(argv: Sequence[str], stdin: str | None = None) -> str:
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                done = subprocess.run(
                    list(argv),
                    input=stdin,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=TOOL_TIMEOUT_SECONDS,
                )
                if done.returncode == 0:
                    return done.stdout
                message = done.stderr.strip() or f"{argv[0]} exited {done.returncode}"
            except subprocess.TimeoutExpired:
                message = f"{argv[0]} timed out after {TOOL_TIMEOUT_SECONDS:.0f}s"
            except OSError as err:
                raise ToolError(f"cannot run {argv[0]}: {err}") from err
            if attempt == MAX_ATTEMPTS or PERMANENT_ERROR.search(message):
                raise ToolError(message)
            sleep(BACKOFF_BASE_SECONDS * 2 ** (attempt - 1))

    return run_tool


class GitHubClient:
    """The GitHub REST API through ``gh api``."""

    def __init__(self, run: Runner) -> None:
        self._run = run
        self.notes: Annotations = []  # what the calls found worth telling

    def _get(self, path: str, missing_ok: bool = False) -> Any:
        """The JSON response of GET ``path``; None for HTTP 404 if ``missing_ok``."""
        argv = ["gh", "api", "-H", f"X-GitHub-Api-Version: {GITHUB_API_VERSION}", path]
        try:
            return json.loads(self._run(argv, None))
        except ToolError as err:
            if missing_ok and NOT_FOUND.search(str(err)):
                return None
            raise ResolveError(f"GitHub API GET {path} failed: {err}") from err

    def default_branch(self, repo: str) -> str:
        return self._get(f"repos/{repo}")["default_branch"]

    def commit_sha(self, repo: str, ref: str) -> str:
        quoted = urllib.parse.quote(ref, safe="")
        return self._get(f"repos/{repo}/commits/{quoted}")["sha"]

    def releases(self, repo: str) -> list[dict[str, Any]]:
        """The published releases (newest first), all pages up to the cap; a
        repository without releases has none, which is not an error. Only a listing
        cut by the cap warns."""
        releases: list[dict[str, Any]] = []
        for page in range(1, MAX_RELEASE_PAGES + 1):
            batch = (
                self._get(
                    f"repos/{repo}/releases?per_page={RELEASES_PER_PAGE}&page={page}",
                    missing_ok=True,
                )
                or []
            )
            releases += batch
            if len(batch) < RELEASES_PER_PAGE:
                return releases
        note(
            self.notes,
            "warning",
            f"the release set is built from the newest {len(releases)} releases",
            "Release list truncated",
        )
        return releases

    def tag_commit_sha(self, repo: str, tag: str) -> str:
        """Commit a git tag points to (the API peels an annotated tag to its commit)."""
        quoted = urllib.parse.quote(tag, safe="/")
        return self._get(f"repos/{repo}/commits/refs/tags/{quoted}")["sha"]


class RegistryClient:
    """Lists image tags with ``oras repo tags`` (any OCI registry)."""

    def __init__(
        self, run: Runner, registry: str, github_token: str | None = None
    ) -> None:
        self.registry = registry
        self._run = run
        self._github_token = github_token

    def tags(self, image: str) -> list[str]:
        """All tags of an image; raises ResolveError on any failure."""
        host = HOST_ALIASES.get(self.registry, self.registry)
        repository = image
        if host == DOCKER_HUB_HOST and "/" not in image:
            repository = f"library/{image}"
        argv = ["oras", "repo", "tags"]
        stdin = None
        # Credentials go to ghcr.io only; every other registry is asked anonymously.
        if self._github_token and host == GHCR_HOST:
            argv += ["--username", "github-actions", "--password-stdin"]
            stdin = self._github_token
        try:
            return self._run([*argv, f"{host}/{repository}"], stdin).split()
        except ToolError as err:
            raise ResolveError(
                f"{self.registry}: listing tags of {image} failed: {err}"
            ) from err


def make_target(
    status: str,
    reason: str | None = None,
    *,
    image: str | None = None,
    tag: str | None = None,
    ref: str | None = None,
    git_ref: str | None = None,
    commit_sha: str | None = None,
    stem: str | None = None,
) -> dict[str, Any]:
    """A Trivy target: an image (``ref`` is its reference), or the source at
    ``git_ref`` pinned to ``commit_sha`` (a release source has a ``tag`` too).

    The id names the subject and is stable across runs, so it never contains the
    SHA; without a known tag it ends with ``release``. An image is named by its
    ``stem`` (see ``image_stems``), the source by ``source``.
    """
    stem = stem or (image.rsplit("/", 1)[-1] if image else "source")
    return {
        "id": UNSAFE_ID_CHARS.sub("-", f"{stem}-{tag or git_ref or 'release'}"),
        "scanner": "trivy",
        "kind": "image" if image else "fs",
        "image": image,
        "tag": tag,
        "ref": ref,
        "git_ref": git_ref,
        "commit_sha": commit_sha,
        "status": status,
        "reason": reason,
    }


def make_osv_target(
    trivy_target: Mapping[str, Any], image_scan_disabled: bool = False
) -> dict[str, Any]:
    """The OSV twin of a Trivy target: OSV queries the packages Trivy found, so the
    twin has something to do only if the Trivy target is scanned. An image twin can
    carry ``image_scan_disabled``: the direct OSV image scan is switched off for the
    repository (an image too large for the runner disk), the BOM query stays.
    """
    twin = {**trivy_target, "scanner": "osv"}
    if image_scan_disabled and trivy_target["kind"] == "image":
        twin["image_scan_disabled"] = True
    if trivy_target["status"] != "pending":
        twin["status"] = "not_applicable"
        twin["reason"] = f"trivy target {trivy_target['status']}"
    return twin


def parse_images(raw: str) -> list[str]:
    images = [line.strip() for line in raw.splitlines() if line.strip()]
    for image in images:
        if not IMAGE_NAME.fullmatch(image):
            raise ResolveError(
                f"invalid image name {image!r}: "
                "expected a lowercase name without registry or tag"
            )
    return images


VERSION_TAG = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
PRERELEASE_TAG = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)-([0-9A-Za-z.-]+)$")


class Release(NamedTuple):
    """One GitHub release of the set; ``tag`` None is the placeholder for a
    repository with no releases at all."""

    tag: str | None
    published_at: str


NO_RELEASE = Release(None, "")


class ReleaseSet(NamedTuple):
    """The scan set of releases: the newest patch of each of the last N minor
    lines, at most one candidate, and stables whose tag matches no line (not
    scanned; only counted in a notice)."""

    stables: list[Release]
    candidate: Release | None
    unmatched: list[Release]


def stable_version(tag: str) -> tuple[int, int, int] | None:
    """The version of an ``X.Y.Z`` tag; its first two numbers are the minor line."""
    if match := VERSION_TAG.fullmatch(tag):
        return int(match[1]), int(match[2]), int(match[3])
    return None


def prerelease_version(tag: str) -> tuple[tuple[int, int, int], tuple] | None:
    """The sort key of an ``X.Y.Z-pre`` tag (an optional ``v`` is allowed): the base
    version, then the prerelease identifiers in semver order (numbers compare
    numerically and rank below words, a shorter list below a longer one with the same
    start). None for a tag of another shape."""
    match = PRERELEASE_TAG.fullmatch(tag)
    if not match:
        return None
    base = (int(match[1]), int(match[2]), int(match[3]))
    identifiers = tuple(
        (0, int(part), "") if part.isdigit() else (1, 0, part)
        for part in match[4].split(".")
    )
    return base, identifiers


def resolve_release_set(
    github: GitHubClient, repository: str, release_lines: int
) -> ReleaseSet:
    """The releases to scan, read from the flags the repository sets: a stable is
    a release with ``prerelease`` and ``draft`` false, drafts are ignored. A line's
    patch is its stable published last, so a hotfix lifts the patch, not the line.

    The candidate is the newest prerelease by version (not by date) that is ahead of
    every stable: its base version is greater than the newest stable's. A prerelease
    keeps its flag after the final release is published, and that one is then no
    candidate. A prerelease whose tag is not ``X.Y.Z-pre`` cannot be compared and is
    ignored."""
    stables_by_line: dict[tuple[int, int], Release] = {}
    newest_stable = (0, 0, 0)
    prereleases: list[tuple[tuple, Release]] = []
    unmatched: list[Release] = []
    for item in github.releases(repository):
        if item["draft"]:
            continue
        release = Release(item["tag_name"], item["published_at"])
        if item["prerelease"]:
            if key := prerelease_version(release.tag):
                prereleases.append((key, release))
        elif version := stable_version(release.tag):
            line = version[:2]
            newest_stable = max(newest_stable, version)
            current = stables_by_line.get(line)
            # first seen wins a tie: GitHub returns the releases newest first
            if current is None or release.published_at > current.published_at:
                stables_by_line[line] = release
        else:
            unmatched.append(release)
    newest_lines = sorted(stables_by_line, reverse=True)[:release_lines]
    ahead = [(key, r) for key, r in prereleases if key[0] > newest_stable]
    candidate = max(ahead, key=lambda pair: pair[0], default=(None, None))[1]
    return ReleaseSet(
        [stables_by_line[line] for line in newest_lines], candidate, unmatched
    )


def image_stems(images: Sequence[str]) -> dict[str, str]:
    """The id stem of each image: its last path segment, or the whole name if another
    image of the list ends alike (``a/x`` and ``b/x`` would give one id). The same
    image listed twice still collides, which ``check_unique_ids`` reports."""
    last = {image: image.rsplit("/", 1)[-1] for image in set(images)}
    counts = Counter(last.values())
    return {image: name if counts[name] == 1 else image for image, name in last.items()}


def image_target(
    registry: RegistryClient,
    image: str,
    tag: str | None,
    status: str,
    reason: str | None = None,
    stem: str | None = None,
) -> dict[str, Any]:
    """An image target of ``registry``: the reference is the image at ``tag``."""
    ref = f"{registry.registry}/{image}:{tag}" if tag else None
    return make_target(status, reason, image=image, tag=tag, ref=ref, stem=stem)


def find_registry_tag(tags: Sequence[str], git_tag: str) -> str | None:
    """The registry tag of a git tag: the registry tag may lack the ``v`` of the git
    tag."""
    return next((t for t in (git_tag, git_tag.removeprefix("v")) if t in tags), None)


def resolve_image_targets(
    registry: RegistryClient,
    image: str,
    releases: Sequence[Release],
    stem: str | None = None,
) -> list[dict[str, Any]]:
    """Targets of one image: the ``development`` tag and every release tag of the
    set (one tags listing per image, the ``development`` target once)."""

    def target(tag, status, reason=None):
        return image_target(registry, image, tag, status, reason, stem)

    try:
        tags = registry.tags(image)
    except ResolveError as err:
        return [
            target("development", "failed", str(err)),
            *[target(r.tag, "failed", str(err)) for r in releases],
        ]

    if "development" in tags:
        targets = [target("development", "pending")]
    else:
        reason = "tag development not published for this image"
        targets = [target("development", "not_applicable", reason)]

    for release in releases:
        if release.tag is None:
            targets.append(target(None, "not_applicable", "no GitHub release"))
        elif found := find_registry_tag(tags, release.tag):
            targets.append(target(found, "pending"))
        else:
            reason = f"release {release.tag} not published for this image"
            targets.append(target(release.tag, "not_applicable", reason))
    return targets


def resolve_release_source_target(
    github: GitHubClient, repository: str, release: Release
) -> dict[str, Any]:
    """The source target of one release: the repository at its git tag, so that
    repositories without images have a release scan too."""

    def source_target(status: str, reason: str | None = None, sha: str | None = None):
        return make_target(
            status, reason, tag=release.tag, git_ref=release.tag, commit_sha=sha
        )

    if release.tag is None:
        return source_target("not_applicable", "no GitHub release")
    try:
        sha = github.tag_commit_sha(repository, release.tag)
    except ResolveError as err:
        reason = f"cannot resolve release tag {release.tag}: {err}"
        return source_target("failed", reason)
    return source_target("pending", sha=sha)


def resolve_focus_image_targets(
    registry: RegistryClient, image: str, tag: str, stem: str | None = None
) -> list[dict[str, Any]]:
    """The image targets of a focus run: the scan tag only, no ``development``
    (a manual run of one tag is not about the moving branch head)."""
    try:
        tags = registry.tags(image)
    except ResolveError as err:
        return [image_target(registry, image, tag, "failed", str(err), stem)]
    if found := find_registry_tag(tags, tag):
        return [image_target(registry, image, found, "pending", stem=stem)]
    reason = f"release {tag} not published for this image"
    return [image_target(registry, image, tag, "not_applicable", reason, stem)]


def resolve_focus_targets(
    github: GitHubClient,
    registry: RegistryClient,
    repository: str,
    images: Sequence[str],
    tag: str,
) -> list[dict[str, Any]]:
    """The targets of a focus run on one tag: its source and, per image, the tag
    itself. An unresolvable tag fails the run: there is no set to fall back to."""
    sha = github.tag_commit_sha(repository, tag)
    targets = [make_target("pending", tag=tag, git_ref=tag, commit_sha=sha)]
    stems = image_stems(images)
    for image in images:
        targets.extend(resolve_focus_image_targets(registry, image, tag, stems[image]))
    return targets


def check_unique_ids(targets: Sequence[Mapping[str, Any]]) -> None:
    """A target is identified by its scanner and id (the id names the subject)."""
    seen: set[tuple[str, str]] = set()
    for target in targets:
        identity = (target["scanner"], target["id"])
        if identity in seen:
            raise ResolveError(f"target id collision: {target['id']!r}")
        seen.add(identity)


@dataclass(frozen=True)
class Inputs:
    """The inputs of the action (see ``action.yml``) and the calling workflow run."""

    repository: str
    registry: str = GHCR_HOST
    images: Sequence[str] = ()
    image_scan: bool = True
    release_lines: int = 2
    token: str | None = None
    scan_tag: str | None = None
    force_image_scan: bool = False

    @classmethod
    def from_args(cls, args: argparse.Namespace, token: str | None) -> Inputs:
        """Read the arguments of the command (``parse_args``) and the API token."""
        if not REPOSITORY_NAME.fullmatch(args.repository):
            raise UsageError(
                f"repository must be 'owner/name', got {args.repository!r}"
            )

        raw_lines = (args.release_lines or "2").strip()
        try:
            release_lines = int(raw_lines)
        except ValueError:
            raise UsageError(
                f"release-lines must be a number, got {raw_lines!r}"
            ) from None

        return cls(
            repository=args.repository,
            registry=args.registry or GHCR_HOST,
            images=tuple(parse_images(args.images)),
            image_scan=args.osv_image_scan.strip().lower() not in ("false", "0", "no"),
            release_lines=max(release_lines, 1),
            token=token,
            scan_tag=args.scan_tag.strip() or None,
            force_image_scan=args.force_image_scan.strip().lower() == "true",
        )


def resolve_release_targets(
    github: GitHubClient,
    registry: RegistryClient,
    repository: str,
    images: Sequence[str],
    release_lines: int,
    default_branch: str,
    commit_sha: str,
) -> list[dict[str, Any]]:
    """The targets of the release scan: the default-branch snapshot, the sources
    of the release set and, per image, its ``development`` and release tags."""
    release_set = resolve_release_set(github, repository, release_lines)
    if release_set.unmatched:
        newest = max(release_set.unmatched, key=lambda r: r.published_at)
        note(
            github.notes,
            "notice",
            f"{len(release_set.unmatched)} stable release(s) not scanned, "
            f"the tag is not X.Y.Z (newest: {newest.tag})",
            "Releases outside the X.Y.Z lines",
        )
    if (
        not release_set.stables
        and release_set.candidate is None
        and not release_set.unmatched
    ):
        # the report must show that the repository publishes no releases at all
        release_set = ReleaseSet([NO_RELEASE], None, [])
    image_releases: list[Release] = [*release_set.stables]
    if release_set.candidate is not None:
        image_releases.append(release_set.candidate)
    targets: list[dict[str, Any]] = [
        make_target("pending", git_ref=default_branch, commit_sha=commit_sha)
    ]
    for release in release_set.stables:
        targets.append(resolve_release_source_target(github, repository, release))
    if release_set.candidate is not None:
        targets.append(
            resolve_release_source_target(github, repository, release_set.candidate)
        )
    stems = image_stems(images)
    for image in images:
        targets.extend(
            resolve_image_targets(registry, image, image_releases, stems[image])
        )
    return targets


def resolve_targets(
    inputs: Inputs,
    github: GitHubClient,
    registry: RegistryClient,
    context: RunContext,
) -> dict[str, Any]:
    """Build the targets.json document. Raises ResolveError without a snapshot.

    A scan tag focuses the run on that one tag: its source and, per image, the tag
    itself. Otherwise the release set of ``release_lines`` minor lines is scanned:
    the source of each of its tags and, in every image, each of its tags. Every
    Trivy target has an OSV twin.

    Order: the development source, the release sources (newest line first, then
    the candidate), then the targets of
    each image in ``images`` order.
    """
    repository = inputs.repository
    default_branch = github.default_branch(repository)
    commit_sha = github.commit_sha(repository, default_branch)

    if inputs.scan_tag:
        # a manual run on one tag: the default branch stays in the header as context
        targets = resolve_focus_targets(
            github, registry, repository, inputs.images, inputs.scan_tag
        )
    else:
        targets = resolve_release_targets(
            github,
            registry,
            repository,
            inputs.images,
            inputs.release_lines,
            default_branch,
            commit_sha,
        )
    # A manual run can force the direct image scan on a repository that has it off;
    # the document says so, the targets are then not marked disabled.
    forced = inputs.force_image_scan and not inputs.image_scan
    disabled = not (inputs.image_scan or inputs.force_image_scan)
    # After all trivy targets, in the same order
    targets.extend([make_osv_target(t, image_scan_disabled=disabled) for t in targets])
    check_unique_ids(targets)

    return {
        "repo": repository,
        "host": context.host,
        "default_branch": default_branch,
        "commit_sha": commit_sha,
        "run_id": context.run_id,
        "run_url": context.url,
        "event": context.event,
        "actor": context.actor,
        **({"scan_ref": inputs.scan_tag} if inputs.scan_tag else {}),
        **({"forced_image_scan": True} if forced else {}),
        "targets": targets,
    }


def build_matrix(targets_doc: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The pending Trivy targets (the matrix of the trivy job), with the fields the
    job uses."""
    keys = ("id", "kind", "ref", "commit_sha")
    return [
        {k: t[k] for k in keys}
        for t in targets_doc["targets"]
        if t["status"] == "pending" and t["scanner"] == "trivy"
    ]


def render_table(targets: Sequence[Mapping[str, Any]]) -> str:
    rows = [("ID", "SCANNER", "REF", "STATUS", "REASON")]
    rows += [
        (t["id"], t["scanner"], t["ref"] or t["kind"], t["status"], t["reason"] or "")
        for t in targets
    ]
    widths = [max(len(row[i]) for row in rows) for i in range(4)] + [0]
    return "\n".join(
        "  ".join(cell.ljust(width) for cell, width in zip(row, widths)).rstrip()
        for row in rows
    )


def annotations(targets: Sequence[Mapping[str, Any]]) -> Annotations:
    """Annotations of the Trivy targets; an OSV twin only mirrors its Trivy target."""
    notes: Annotations = []
    for target in targets:
        if target["scanner"] != "trivy":
            continue
        if target["status"] == "not_applicable":
            level, what = "notice", "skipped"
        elif target["status"] == "failed":
            level, what = "warning", "failed to resolve"
        else:
            continue
        title = f"Scan target {target['id']} {what}"
        note(notes, level, target["reason"], title, target["id"])
    return notes


def run(
    args: argparse.Namespace,
    environ: Mapping[str, str],
    notes: Annotations,
    runner: Runner | None = None,
) -> tuple[str, dict[str, Any]]:
    context = read_run_context(environ)
    inputs = Inputs.from_args(args, environ.get("GH_TOKEN") or None)
    run_tool = runner or make_runner(inputs.token)
    github = GitHubClient(run_tool)
    try:
        targets_doc = resolve_targets(
            inputs,
            github,
            RegistryClient(run_tool, inputs.registry, inputs.token),
            context,
        )
    except ResolveError as err:
        raise CommandError(str(err), title="Scan target resolution failed") from err

    args.output_dir.mkdir(parents=True, exist_ok=True)
    targets_file = args.output_dir / "targets.json"
    dump_json(targets_file, targets_doc)

    print(
        f"Repository {targets_doc['repo']} @ {targets_doc['default_branch']} "
        f"({targets_doc['commit_sha']})"
    )
    print(render_table(targets_doc["targets"]))
    notes += [*github.notes, *annotations(targets_doc["targets"])]
    return "ok", {
        "matrix": build_matrix(targets_doc),
        "targets-file": str(targets_file),
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--repository", required=True, help="owner/name")
    parser.add_argument("--registry", default=GHCR_HOST)
    parser.add_argument("--images", default="", help="image names, one per line")
    parser.add_argument("--osv-image-scan", default="true", help="true or false")
    parser.add_argument("--force-image-scan", default="false", help="true or false")
    parser.add_argument("--release-lines", default="2")
    parser.add_argument("--scan-tag", default="")
    parser.add_argument("--output-dir", default=Path("out"), type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    return execute(
        "targets", args.output_dir, lambda notes: run(args, os.environ, notes)
    )


if __name__ == "__main__":
    sys.exit(main())
