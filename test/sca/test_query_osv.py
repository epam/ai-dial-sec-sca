"""Tests for sca/osv/query_osv.py (synthetic data, fake commands)."""

from __future__ import annotations

import argparse
import base64
import json
import os
import signal
import subprocess
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sca import cli
from sca.lib.context import UsageError
from sca.osv import query_osv as qo

NOW = datetime(2030, 1, 1, 12, 0, 0, tzinfo=UTC)


# --- fakes and builders -------------------------------------------------------


def component(purl: str | None, kind: str = "library") -> dict[str, Any]:
    last = (purl or "lockfile").split("/")[-1]
    name, _, version = last.partition("@")
    return {
        "type": kind,
        "name": name,
        **({"version": version.split("?")[0]} if version else {}),
        **({"purl": purl} if purl else {}),
    }


BOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "metadata": {"component": {"type": "container", "name": "image"}},
    "components": [
        component("pkg:npm/lodash@4.17.0"),
        component("pkg:pypi/requests@2.0.0"),
        component("pkg:deb/debian/zlib@1.2?distro=debian-12"),
        component("pkg:apk/alpine/musl@1.2.4-r0"),
        component("pkg:rpm/redhat/glibc@2.34"),
        component(None),
        component(None, kind="application"),
        component("pkg:oci/image@sha256:0", kind="container"),
    ],
    "dependencies": [{"ref": "a", "dependsOn": ["b"]}],
    "vulnerabilities": [{"id": "CVE-2030-1"}],
}


def osv_output(*packages: tuple[str, str, str], vulnerable: bool = False) -> dict:
    """An osv-scanner result (``--format json --all-packages``) of one BOM."""
    entries = []
    for ecosystem, name, version in packages:
        entry: dict[str, Any] = {
            "package": {"ecosystem": ecosystem, "name": name, "version": version}
        }
        if vulnerable:
            entry["vulnerabilities"] = [{"id": "GHSA-aaaa-aaaa-aaaa"}]
            entry["groups"] = [{"ids": ["GHSA-aaaa-aaaa-aaaa"], "max_severity": "7.5"}]
        entries.append(entry)
    source = {"path": "x.cdx.json", "type": "sbom"}
    return {"results": [{"source": source, "packages": entries}] if entries else []}


PACKAGES = (("npm", "lodash", "4.17.0"), ("PyPI", "requests", "2.0.0"))


class FakeCommands:
    """Stands in for ``trivy``, ``crane`` and ``osv-scanner``; records every command.

    ``scanner_exit``/``scanner_output``: what osv-scanner does (an output of
    False writes nothing; a string is written as is).
    """

    def __init__(
        self,
        bom: Any = BOM,
        convert_exit: int = 0,
        scanner_exit: int = 1,
        scanner_output: Any = None,
        scanner_stderr: str = "",
        image_exit: int | None = None,
        image_stderr: str | None = None,
        image_output: Any = None,
        crane_exit: int = 0,
    ) -> None:
        self.bom = bom
        self.convert_exit = convert_exit
        self.scanner_exit = scanner_exit
        self.scanner_output = (
            osv_output(*PACKAGES, vulnerable=True)
            if scanner_output is None
            else scanner_output
        )
        self.scanner_stderr = scanner_stderr
        self.image_exit = scanner_exit if image_exit is None else image_exit
        # the stderr of the image scan; by default the one of the BOM scan
        self.image_stderr = scanner_stderr if image_stderr is None else image_stderr
        self.image_output = (
            osv_output(*PACKAGES, vulnerable=True)
            if image_output is None
            else image_output
        )
        self.crane_exit = crane_exit
        self.calls: list[list[str]] = []
        # what the pulls saw: (env, config.json text or None); whether the archive
        # existed at each scan; the archive paths
        self.pulls: list[tuple[dict[str, str], str | None]] = []
        self.tars_scanned: list[bool] = []
        self.scan_envs: list[dict[str, str]] = []
        self.tars: list[Path] = []
        self.scanned_boms: list[dict[str, Any]] = []

    def __call__(
        self, command: Sequence[str], env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        command = list(command)
        self.calls.append(command)
        if command[0] == "crane":
            config = Path((env or {})["DOCKER_CONFIG"]) / "config.json"
            self.pulls.append(
                (dict(env or {}), config.read_text("utf-8") if config.exists() else None)
            )
            tar = Path(command[-1])
            self.tars.append(tar)
            if not self.crane_exit:
                tar.write_bytes(b"tar")
            return subprocess.CompletedProcess(command, self.crane_exit, "", "denied")
        if command[1] == "--version":
            out = "osv-scanner version: 2.6.0\nosv-scalibr version: 0.4.8\n"
            return subprocess.CompletedProcess(command, 0, out, "")
        if command[1] == "convert":
            if self.convert_exit:
                return subprocess.CompletedProcess(
                    command, self.convert_exit, "", "boom"
                )
            Path(command[command.index("--output") + 1]).write_text(
                json.dumps(self.bom), encoding="utf-8"
            )
            return subprocess.CompletedProcess(command, 0, "", "")
        output = Path(command[command.index("--output-file") + 1])
        if command[1:3] == ["scan", "image"]:
            self.tars_scanned.append(Path(command[command.index("--archive") + 1]).exists())
            self.scan_envs.append(dict(env or {}))
            if self.image_output is not False:
                output.write_text(json.dumps(self.image_output), encoding="utf-8")
            return subprocess.CompletedProcess(
                command, self.image_exit, "", self.image_stderr
            )
        bom_path = Path(command[command.index("-L") + 1])
        self.scanned_boms.append(json.loads(bom_path.read_text(encoding="utf-8")))
        if self.scanner_output is not False:
            text = (
                self.scanner_output
                if isinstance(self.scanner_output, str)
                else json.dumps(self.scanner_output)
            )
            output.write_text(text, encoding="utf-8")
        return subprocess.CompletedProcess(
            command, self.scanner_exit, "", self.scanner_stderr
        )

    def scans(self, kind: str = "source") -> list[list[str]]:
        return [c for c in self.calls if c[1:3] == ["scan", kind]]

    def cranes(self) -> list[list[str]]:
        return [c for c in self.calls if c[0] == "crane"]


class Workspace:
    """targets.json (one Trivy target and its OSV twin) and the Trivy parts."""

    def __init__(
        self,
        tmp_path: Path,
        trivy_status: str | None = "ok",
        kind: str = "fs",
        extra: dict[str, Any] | None = None,
    ) -> None:
        self.targets_file = tmp_path / "targets.json"
        self.parts_dir = tmp_path / "parts"
        self.output_dir = tmp_path / "out"
        trivy = self.parts_dir / "trivy"
        trivy.mkdir(parents=True)
        tid = "app-development" if kind == "image" else "source-development"
        target = {
            "id": tid,
            "kind": kind,
            "status": "pending",
            "ref": "ghcr.io/example/app:development" if kind == "image" else None,
            **(extra or {}),
        }
        self.targets_file.write_text(
            json.dumps(
                {
                    "targets": [
                        {**target, "scanner": "trivy"},
                        {**target, "scanner": "osv"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        if trivy_status is not None:
            (trivy / f"{tid}.status.json").write_text(
                json.dumps({"id": tid, "status": trivy_status}), encoding="utf-8"
            )
        if trivy_status == "ok":
            (trivy / f"{tid}.json").write_text(
                json.dumps({"Results": []}), encoding="utf-8"
            )
        self.tid = tid

    def run(
        self,
        commands: FakeCommands,
        offline_db_dir: Path | None = None,
        registry: str | None = None,
    ) -> None:
        args = argparse.Namespace(
            targets_file=self.targets_file,
            parts_dir=self.parts_dir,
            output_dir=self.output_dir,
            offline_db_dir=offline_db_dir,
            registry=registry,
        )
        qo.run_all(args, commands, NOW)

    @property
    def osv_dir(self) -> Path:
        return self.output_dir / "osv"

    def status(self) -> dict[str, Any]:
        path = self.osv_dir / f"{self.tid}.status.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def result(self) -> Path:
        return self.osv_dir / f"{self.tid}.json"


# --- the BOM ------------------------------------------------------------------


def test_filter_bom_keeps_language_packages() -> None:
    bom = qo.filter_bom(BOM)
    # the library without a purl and the lockfile (application) are no packages
    assert [c["purl"] for c in bom["components"]] == [
        "pkg:npm/lodash@4.17.0",
        "pkg:pypi/requests@2.0.0",
        "pkg:oci/image@sha256:0",
    ]
    # the graph and the Trivy findings are of no use to osv-scanner
    assert (bom["dependencies"], bom["vulnerabilities"]) == ([], [])
    assert bom["bomFormat"] == "CycloneDX"


@pytest.mark.parametrize("purl_type", ["deb", "apk", "rpm", "DEB"])
def test_filter_bom_removes_os_packages(purl_type: str) -> None:
    bom = qo.filter_bom({"components": [component(f"pkg:{purl_type}/distro/pkg@1")]})
    assert bom["components"] == []


def test_filter_bom_folds_the_group_into_the_name_as_osv_writes_it() -> None:
    maven = {**component("pkg:maven/org.example/lib@1.0"), "group": "org.example"}
    scoped = {**component("pkg:npm/%40scope/pkg@1.0"), "group": "@scope"}
    plain = component("pkg:npm/plain@1.0")
    bom = qo.filter_bom({"components": [maven, scoped, plain]})
    assert [(c["name"], "group" in c) for c in bom["components"]] == [
        ("org.example:lib", False),
        ("@scope/pkg", False),
        ("plain", False),
    ]
    assert "group" in maven  # the input is not modified


def test_filter_bom_removes_components_without_a_version() -> None:
    no_version = {"type": "library", "name": "ws", "purl": "pkg:npm/ws"}
    empty = {**no_version, "version": "", "purl": "pkg:npm/ws@"}
    blank_purl = {**no_version, "version": "1.0"}
    keep = component("pkg:npm/lodash@4.17.0")
    bom = qo.filter_bom({"components": [no_version, empty, blank_purl, keep]})
    assert bom["components"] == [keep]


def test_filter_bom_without_components() -> None:
    assert qo.filter_bom({})["components"] == []


# --- a target -------------------------------------------------------------------


def test_osv_scanner_is_run_on_the_filtered_bom_with_the_documented_flags(
    tmp_path: Path,
) -> None:
    ws = Workspace(tmp_path)
    commands = FakeCommands()
    ws.run(commands)
    convert = commands.calls[1]
    assert convert[:5] == ["trivy", "convert", "--format", "cyclonedx", "--output"]
    assert convert[-1] == str(ws.parts_dir / "trivy" / "source-development.json")
    (scan,) = commands.scans()
    assert scan[:3] == ["osv-scanner", "scan", "source"]
    # osv-scanner takes the format of a BOM from its file name
    assert scan[scan.index("-L") + 1].endswith(".cdx.json")
    assert "--all-packages" in scan
    assert scan[scan.index("--format") + 1] == "json"
    assert scan[scan.index("--output-file") + 1] == str(ws.result())
    assert len(commands.scanned_boms[0]["components"]) == 3


@pytest.mark.parametrize(("exit_code", "vulnerable"), [(0, False), (1, True)])
def test_exit_0_and_1_are_ok_and_the_output_is_kept_as_is(
    tmp_path: Path, exit_code: int, vulnerable: bool
) -> None:
    ws = Workspace(tmp_path)
    output = osv_output(*PACKAGES, vulnerable=vulnerable)
    ws.run(FakeCommands(scanner_exit=exit_code, scanner_output=output))
    assert json.loads(ws.result().read_text(encoding="utf-8")) == output
    assert ws.status() == {
        "status": "ok",
        "reason": None,
        "queried_at": "2030-01-01T12:00:00Z",
        "scanner_version": "2.6.0",
    }


@pytest.mark.parametrize("exit_code", [2, 127, 128, 130])
def test_any_other_exit_code_is_a_failure_even_with_an_empty_json(
    tmp_path: Path, exit_code: int
) -> None:
    ws = Workspace(tmp_path)
    # a clean-looking output next to a failure must not count as clean
    commands = FakeCommands(
        scanner_exit=exit_code,
        scanner_output=osv_output(),
        scanner_stderr="Error during extraction:\nmax retries exceeded",
    )
    ws.run(commands)
    assert ws.status()["status"] == "failed"
    assert ws.status()["reason"] == (
        f"osv-scanner failed (exit {exit_code}): "
        "Error during extraction: max retries exceeded"
    )


def test_a_missing_osv_scanner_is_exit_127(tmp_path: Path) -> None:
    result = qo.run_command([str(tmp_path / "no-such-binary"), "--version"])
    assert result.returncode == 127
    assert result.stderr


def record_timeouts(monkeypatch: pytest.MonkeyPatch) -> list[float | None]:
    seen: list[float | None] = []

    def fake_run(command: Sequence[str], **kwargs: Any) -> Any:
        seen.append(kwargs.get("timeout"))
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(qo.subprocess, "run", fake_run)
    return seen


def test_every_command_has_a_timeout_and_an_image_scan_a_longer_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = record_timeouts(monkeypatch)
    qo.run_command(["trivy", "convert"])
    qo.run_command(["osv-scanner", "scan", "source", "-L", "x"])
    qo.run_command(["docker", "image", "rm", "ref"])
    qo.run_command(["osv-scanner", "scan", "image", "ref"])
    assert seen == [
        qo.COMMAND_TIMEOUT_SECONDS,
        qo.COMMAND_TIMEOUT_SECONDS,
        qo.COMMAND_TIMEOUT_SECONDS,
        qo.IMAGE_SCAN_TIMEOUT_SECONDS,
    ]
    assert qo.IMAGE_SCAN_TIMEOUT_SECONDS > qo.COMMAND_TIMEOUT_SECONDS


def test_a_command_that_times_out_is_exit_124(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(command: Sequence[str], **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(qo.subprocess, "run", fake_run)
    result = qo.run_command(["osv-scanner", "scan", "image", "ref"])
    assert result.returncode == 124
    assert "timed out" in result.stderr


def test_a_scan_that_times_out_fails_its_target_and_the_loop_goes_on(
    tmp_path: Path,
) -> None:
    class Hanging(FakeCommands):
        def __call__(self, command: Sequence[str]) -> subprocess.CompletedProcess[str]:
            if list(command[1:3]) == ["scan", "source"]:
                return subprocess.CompletedProcess(command, 124, "", "timed out")
            return super().__call__(command)

    ws = Workspace(tmp_path)
    ws.run(Hanging())
    status = ws.status()
    assert status["status"] == "failed"
    assert "exit 124" in status["reason"]
    assert "timed out" in status["reason"]


def test_the_reason_is_the_end_of_stderr_and_is_cut(tmp_path: Path) -> None:
    ws = Workspace(tmp_path)
    ws.run(FakeCommands(scanner_exit=2, scanner_stderr="x" * 5000 + " the end"))
    reason = ws.status()["reason"]
    assert reason.endswith("the end")
    assert len(reason) < 500


def test_trivy_convert_failure_is_a_failed_target(tmp_path: Path) -> None:
    ws = Workspace(tmp_path)
    commands = FakeCommands(convert_exit=1)
    ws.run(commands)
    assert ws.status()["reason"] == "trivy convert failed (exit 1): boom"
    assert commands.scans() == []


def test_an_unreadable_bom_is_a_failed_target(tmp_path: Path) -> None:
    ws = Workspace(tmp_path)
    ws.run(FakeCommands(bom=["not", "a", "bom"]))
    assert ws.status()["reason"].startswith("trivy convert wrote no valid BOM")


def test_a_target_without_language_packages_is_ok_without_running_osv_scanner(
    tmp_path: Path,
) -> None:
    ws = Workspace(tmp_path)
    commands = FakeCommands(bom={"components": [component("pkg:deb/debian/a@1")]})
    ws.run(commands)
    assert commands.scans() == []
    assert json.loads(ws.result().read_text(encoding="utf-8")) == {"results": []}
    assert ws.status()["status"] == "ok"


@pytest.mark.parametrize("trivy_status", ["failed", "not_applicable", None, "ok-ish"])
def test_a_target_whose_trivy_target_was_not_scanned_is_not_applicable(
    tmp_path: Path, trivy_status: str | None
) -> None:
    ws = Workspace(tmp_path, trivy_status)
    commands = FakeCommands()
    ws.run(commands)
    assert ws.status()["status"] == "not_applicable"
    assert ws.status()["reason"] == f"trivy target {trivy_status or 'failed'}"
    assert not ws.result().exists()
    assert commands.scans() == []


def test_only_pending_osv_targets_are_processed(tmp_path: Path) -> None:
    ws = Workspace(tmp_path)
    doc = json.loads(ws.targets_file.read_text(encoding="utf-8"))
    doc["targets"][1]["status"] = "failed"
    ws.targets_file.write_text(json.dumps(doc), encoding="utf-8")
    commands = FakeCommands()
    ws.run(commands)
    assert commands.scans() == []
    assert not (ws.osv_dir / "source-development.status.json").exists()


# --- an image target ----------------------------------------------------------


def image_workspace(tmp_path: Path, **extra: Any) -> Workspace:
    return Workspace(tmp_path, kind="image", extra=extra)


def test_an_image_target_is_scanned_by_bom_and_by_image(tmp_path: Path) -> None:
    ws = image_workspace(tmp_path)
    commands = FakeCommands()
    ws.run(commands)
    bom, image = commands.scans("source")[0], commands.scans("image")[0]
    assert image[:3] == ["osv-scanner", "scan", "image"]
    assert image[3] == "--archive"
    assert commands.cranes() == [
        ["crane", "pull", "--platform", "linux/amd64", "ghcr.io/example/app:development", image[4]]
    ]
    assert "--all-packages" in image
    assert image[image.index("--format") + 1] == "json"
    # the image scan writes to its own file, not over the BOM output
    assert image[image.index("--output-file") + 1] != str(ws.result())
    # the results of both are concatenated into the one output, the BOM query's
    # first (the file is the audit artifact read in order)
    merged = json.loads(ws.result().read_text(encoding="utf-8"))
    bom_names = [p["package"]["name"] for p in commands.scanner_output["results"][0]["packages"]]
    image_names = [p["package"]["name"] for p in commands.image_output["results"][0]["packages"]]
    assert [p["package"]["name"] for p in merged["results"][0]["packages"]] == bom_names
    assert [p["package"]["name"] for p in merged["results"][1]["packages"]] == image_names
    assert len(merged["results"]) == 2
    sources = {r["source"]["type"] for r in merged["results"]}
    assert sources == {"sbom"}
    # the archive existed for the scan and is gone after it
    assert commands.tars_scanned == [True]
    assert not commands.tars[0].exists()


def test_a_failed_pull_fails_the_target_and_runs_no_scan(tmp_path: Path) -> None:
    ws = image_workspace(tmp_path)
    commands = FakeCommands(crane_exit=1)
    ws.run(commands)
    assert ws.status()["status"] == "failed"
    assert ws.status()["reason"] == "crane pull failed (exit 1): denied"
    assert commands.scans("image") == []
    assert not commands.tars[0].exists()


@pytest.mark.parametrize("exit_code", [2, 127])
def test_a_failed_image_scan_fails_the_target_even_with_a_good_bom(
    tmp_path: Path, exit_code: int
) -> None:
    ws = image_workspace(tmp_path)
    commands = FakeCommands(image_exit=exit_code, scanner_stderr="pull failed")
    ws.run(commands)
    assert ws.status()["status"] == "failed"
    assert ws.status()["reason"] == (
        f"osv-scanner scan image failed (exit {exit_code}): pull failed"
    )
    assert not commands.tars[0].exists()


def test_an_image_scan_output_of_an_unexpected_shape_fails_the_target(
    tmp_path: Path,
) -> None:
    ws = image_workspace(tmp_path)
    ws.run(FakeCommands(image_output={"unexpected": True}))
    assert ws.status()["status"] == "failed"
    assert "no valid results to merge" in ws.status()["reason"]


def test_a_bom_query_that_fails_before_the_image_scan_pulls_nothing(
    tmp_path: Path,
) -> None:
    ws = image_workspace(tmp_path)
    commands = FakeCommands(convert_exit=2)
    ws.run(commands)
    assert ws.status()["status"] == "failed"
    assert commands.scans("image") == []
    assert commands.cranes() == []


def test_the_image_scan_flag_skips_only_the_image_scan(tmp_path: Path) -> None:
    ws = image_workspace(tmp_path, image_scan_disabled=True)
    commands = FakeCommands()
    ws.run(commands)
    assert len(commands.scans("source")) == 1
    assert commands.scans("image") == []
    assert commands.cranes() == []
    merged = json.loads(ws.result().read_text(encoding="utf-8"))
    assert len(merged["results"]) == 1
    assert ws.status()["status"] == "ok"
    assert ws.status()["reason"] == (
        "osv image scan disabled for this repository (image too large for the "
        "runner disk): OS packages of the image are not checked by OSV"
    )


# --- registry credentials ----------------------------------------------------

SECRET = "s3cr3t-pass"
GHCR = "ghcr.io"


def with_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCA_REGISTRY_USER", "robot")
    monkeypatch.setenv("SCA_REGISTRY_PASSWORD", SECRET)
    monkeypatch.setenv("DOCKER_CONFIG", "/inherited")


def test_credentials_reach_crane_only_through_a_config_for_the_registry_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with_credentials(monkeypatch)
    ws = image_workspace(tmp_path)
    commands = FakeCommands()
    ws.run(commands, registry=GHCR)
    env, config = commands.pulls[0]
    auth = base64.b64encode(f"robot:{SECRET}".encode()).decode()
    assert json.loads(config or "") == {"auths": {GHCR: {"auth": auth}}}
    assert env["DOCKER_CONFIG"] != "/inherited"
    assert SECRET not in json.dumps(commands.calls)
    # nothing survives: the config directory is gone with the temporary directory
    assert not Path(env["DOCKER_CONFIG"]).exists()


@pytest.mark.skipif(os.name != "posix", reason="file modes")
def test_the_config_file_of_the_credentials_is_private(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with_credentials(monkeypatch)
    modes: list[int] = []

    class Spy(FakeCommands):
        def __call__(self, command, env=None):  # type: ignore[no-untyped-def]
            if command[0] == "crane":
                modes.append((Path(env["DOCKER_CONFIG"]) / "config.json").stat().st_mode & 0o777)
            return super().__call__(command, env)

    image_workspace(tmp_path).run(Spy(), registry=GHCR)
    assert modes == [0o600]


@pytest.mark.parametrize("registry", [None, "registry.example.com"])
def test_another_registry_is_pulled_anonymously_with_an_empty_docker_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, registry: str | None
) -> None:
    with_credentials(monkeypatch)
    commands = FakeCommands()
    image_workspace(tmp_path).run(commands, registry=registry)
    env, config = commands.pulls[0]
    # a config file that exists and has no credentials: no fallback to Podman auth files
    assert json.loads(config or "") == {"auths": {}}
    assert env["DOCKER_CONFIG"] != "/inherited"


@pytest.mark.parametrize("registry", ["ghcr", "ghcr.io/org"])
def test_a_registry_that_is_not_a_host_is_refused(
    tmp_path: Path, registry: str
) -> None:
    with pytest.raises(UsageError):
        image_workspace(tmp_path).run(FakeCommands(), registry=registry)


def test_half_credentials_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SCA_REGISTRY_USER", "robot")
    monkeypatch.delenv("SCA_REGISTRY_PASSWORD", raising=False)
    with pytest.raises(UsageError):
        image_workspace(tmp_path).run(FakeCommands(), registry=GHCR)


@pytest.mark.parametrize("host", ["docker.io", "index.docker.io"])
def test_docker_hub_credentials_use_the_historical_auths_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, host: str
) -> None:
    with_credentials(monkeypatch)
    ws = Workspace(tmp_path, kind="image", extra={"ref": f"{host}/library/app:1"})
    commands = FakeCommands()
    ws.run(commands, registry=host)
    auths = json.loads(commands.pulls[0][1] or "")["auths"]
    assert list(auths) == ["https://index.docker.io/v1/"]


def test_the_config_is_removed_when_the_runner_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with_credentials(monkeypatch)
    seen: list[Path] = []

    def boom(command, env=None):  # type: ignore[no-untyped-def]
        if command[0] == "crane":
            seen.append(Path(env["DOCKER_CONFIG"]))
            assert (seen[0] / "config.json").exists()
            raise KeyboardInterrupt
        return FakeCommands()(command, env)

    with pytest.raises(KeyboardInterrupt):
        image_workspace(tmp_path).run(boom, registry=GHCR)
    assert not seen[0].exists()


def test_the_pair_is_checked_before_any_target_is_processed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SCA_REGISTRY_USER", "robot")
    monkeypatch.delenv("SCA_REGISTRY_PASSWORD", raising=False)
    ws = Workspace(tmp_path)  # a source target: no image would ask for the pair
    commands = FakeCommands()
    with pytest.raises(UsageError):
        ws.run(commands, registry="registry.example.com")
    assert commands.calls == []
    assert not ws.osv_dir.exists()


def test_osv_scanner_gets_its_own_tmpdir_and_no_ambient_registry_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with_credentials(monkeypatch)
    commands = FakeCommands()
    image_workspace(tmp_path).run(commands, registry=GHCR)
    tmpdir = Path(commands.scan_envs[0]["TMPDIR"])
    assert tmpdir == commands.tars[0].parent
    assert not tmpdir.exists()


def test_subprocesses_get_no_registry_credentials_or_auth_files(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with_credentials(monkeypatch)
    monkeypatch.setenv("REGISTRY_AUTH_FILE", "/auth.json")
    monkeypatch.setenv("KEEP", "yes")
    seen: list[dict[str, str]] = []

    def fake_run(command: Sequence[str], **kwargs: Any) -> Any:
        seen.append(kwargs["env"])
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(qo.subprocess, "run", fake_run)
    qo.run_command(["osv-scanner", "scan", "source"])
    qo.run_command(["crane", "pull"], {"DOCKER_CONFIG": "/own"})
    scanner, crane = seen
    for name in ("SCA_REGISTRY_USER", "SCA_REGISTRY_PASSWORD", "DOCKER_CONFIG", "REGISTRY_AUTH_FILE"):
        assert name not in scanner
    assert scanner["KEEP"] == "yes"
    assert crane["DOCKER_CONFIG"] == "/own" and "REGISTRY_AUTH_FILE" not in crane
    assert "SCA_REGISTRY_PASSWORD" not in crane


def test_a_pull_has_its_own_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = record_timeouts(monkeypatch)
    qo.run_command(["crane", "pull", "ref", "tar"])
    assert seen == [qo.PULL_TIMEOUT_SECONDS] == [600.0]


def test_sigterm_ends_the_command_like_an_exit_so_cleanup_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handlers: dict[int, Any] = {}
    monkeypatch.setattr(cli.signal, "signal", lambda num, handler: handlers.update({num: handler}))
    monkeypatch.setattr(cli, "import_module", lambda name: type("M", (), {"main": staticmethod(lambda a, prog: 0)}))
    assert cli.main(["osv"]) == 0
    with pytest.raises(SystemExit) as exit_:
        handlers[signal.SIGTERM](signal.SIGTERM, None)
    assert exit_.value.code == 128 + signal.SIGTERM


# --- offline mode -------------------------------------------------------------


@pytest.fixture
def clean_cache_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """The env var absent, restored to absent after the test."""
    monkeypatch.setenv(qo.CACHE_ENV, "placeholder")
    monkeypatch.delenv(qo.CACHE_ENV)


def test_without_the_offline_option_commands_and_env_are_unchanged(
    tmp_path: Path, clean_cache_env: None
) -> None:
    ws = image_workspace(tmp_path)
    commands = FakeCommands()
    ws.run(commands)
    assert all("--offline" not in c for c in commands.calls)
    assert qo.CACHE_ENV not in os.environ


def test_offline_adds_the_flag_to_both_scans_and_sets_the_cache_env(
    tmp_path: Path, clean_cache_env: None
) -> None:
    ws = image_workspace(tmp_path)
    commands = FakeCommands()
    ws.run(commands, offline_db_dir=tmp_path / "osv-db")
    assert commands.scans("source")[0][-1] == "--offline"
    assert commands.scans("image")[0][-1] == "--offline"
    assert os.environ[qo.CACHE_ENV] == str(tmp_path / "osv-db")
    assert ws.status()["status"] == "ok"
    # the other commands do not get the flag
    assert all("--offline" not in c for c in commands.calls if c[1:2] == ["convert"])


@pytest.mark.parametrize("exit_code", [0, 1])
def test_offline_missing_database_fails_the_bom_scan(
    tmp_path: Path, exit_code: int, clean_cache_env: None
) -> None:
    ws = Workspace(tmp_path)
    stderr = "Error: no offline version of the OSV database for npm is available"
    ws.run(
        FakeCommands(scanner_exit=exit_code, scanner_stderr=stderr),
        offline_db_dir=tmp_path / "osv-db",
    )
    status = ws.status()
    assert status["status"] == "failed"
    assert "no offline version of the OSV database for npm is available" in status["reason"]


@pytest.mark.parametrize("exit_code", [0, 1])
def test_offline_missing_database_fails_the_image_scan(
    tmp_path: Path, exit_code: int, clean_cache_env: None
) -> None:
    ws = image_workspace(tmp_path)
    stderr = "no offline version of the OSV database for Debian"
    ws.run(
        FakeCommands(scanner_exit=0, image_exit=exit_code, image_stderr=stderr),
        offline_db_dir=tmp_path / "osv-db",
    )
    # a clean BOM scan: only the image scan can fail the target
    assert ws.status()["status"] == "failed"
    assert stderr in ws.status()["reason"]
    assert "scan image" in ws.status()["reason"]


def test_the_missing_database_message_is_ignored_online(tmp_path: Path) -> None:
    ws = Workspace(tmp_path)
    ws.run(
        FakeCommands(
            scanner_exit=1, scanner_stderr="no offline version of the OSV database"
        )
    )
    assert ws.status()["status"] == "ok"


def test_an_image_scan_reason_of_the_target_states_the_exclusion(
    tmp_path: Path,
) -> None:
    ws = image_workspace(
        tmp_path,
        image_scan_disabled=True,
        image_scan_disabled_reason="osv image scan off: Ubuntu image, offline matching is wrong",
    )
    commands = FakeCommands()
    ws.run(commands)
    assert commands.scans("image") == []
    assert ws.status()["status"] == "ok"
    assert ws.status()["reason"] == (
        "osv image scan off: Ubuntu image, offline matching is wrong"
    )


def test_a_failed_bom_scan_keeps_its_own_reason_over_the_disabled_reason(
    tmp_path: Path,
) -> None:
    ws = image_workspace(
        tmp_path, image_scan_disabled=True, image_scan_disabled_reason="skipped"
    )
    ws.run(FakeCommands(scanner_exit=127))
    assert ws.status()["status"] == "failed"
    assert "skipped" not in ws.status()["reason"]
