import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from builders import item
from sca.fix.dependabot import (
    DETAILS_LIMIT,
    JobError,
    docker_job,
    job_directories,
    Settings,
    UNKNOWN_ERROR,
    read_events,
    run_job,
    security_job,
)


def touch(tree: Path, *paths: str) -> None:
    for path in paths:
        target = tree / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("x", encoding="utf-8")


def test_npm_root_lockfile(tmp_path: Path) -> None:
    touch(tmp_path, "package-lock.json")
    assert job_directories(tmp_path, item()) == ("npm_and_yarn", ["/"])


def test_image_paths_and_node_modules_do_not_count(tmp_path: Path) -> None:
    touch(tmp_path, "package-lock.json", "app/node_modules/x/package.json")
    locations = (
        "app/node_modules/x/package.json",
        "package-lock.json",
        "app/lib/x.jar",
    )
    assert job_directories(tmp_path, item(locations=locations))[1] == ["/"]


def test_no_manifest_location_means_root(tmp_path: Path) -> None:
    assert job_directories(tmp_path, item(locations=("app/x.jar",)))[1] == ["/"]


def test_pypi_uses_pip_in_the_lockfile_directory(tmp_path: Path) -> None:
    touch(tmp_path, "svc/poetry.lock")
    found = job_directories(
        tmp_path, item(ecosystem="PyPI", locations=("svc/poetry.lock",))
    )
    assert found == ("pip", ["/svc"])


def test_gradle_lockfiles_map_to_build_files(tmp_path: Path) -> None:
    touch(tmp_path, "build.gradle", "secrets-utils/build.gradle", "docs/readme")
    locations = (
        "app/app.jar/BOOT-INF/lib/x.jar",
        "gradle.lockfile",
        "secrets-utils/gradle.lockfile",
        "docs/gradle.lockfile",
    )
    found = job_directories(tmp_path, item(ecosystem="Maven", locations=locations))
    assert found == ("gradle", ["/", "/secrets-utils"])


def test_maven_without_a_build_file_is_maven(tmp_path: Path) -> None:
    touch(tmp_path, "pom.xml")
    found = job_directories(tmp_path, item(ecosystem="Maven", locations=("pom.xml",)))
    assert found[0] == "maven"


def test_unsupported_ecosystem(tmp_path: Path) -> None:
    with pytest.raises(JobError, match="Go not supported"):
        job_directories(tmp_path, item(ecosystem="Go"))


def test_security_job_has_the_advisory_of_the_target() -> None:
    job = security_job(item(), "npm_and_yarn", "o/r", "release-1.2", ["/"])
    assert job["security-updates-only"] is True
    assert job["dependencies"] == ["hono"]
    assert job["source"]["branch"] == "release-1.2"
    assert job["security-advisories"] == [
        {
            "dependency-name": "hono",
            "affected-versions": ["< 2.1.5"],
            "patched-versions": [">= 2.1.5"],
        }
    ]


def test_docker_job_ignores_major_versions() -> None:
    job = docker_job("o/r", "b", ["/", "/app"])
    assert job["package-manager"] == "docker"
    assert "dependencies" not in job
    assert job["ignore-conditions"][0]["update-types"] == [
        "version-update:semver-major"
    ]


def test_read_events() -> None:
    document: dict[str, Any] = {
        "output": [
            {"type": "update_dependency_list", "expect": {"data": {}}},
            {
                "type": "create_pull_request",
                "expect": {
                    "data": {
                        "updated-dependency-files": [{"name": "a"}],
                        "dependencies": [{"name": "d"}],
                    }
                },
            },
            {
                "type": "record_update_job_error",
                "expect": {
                    "data": {"error-type": "boom", "error-details": {"k": ["v", 1]}}
                },
            },
        ]
    }
    result = read_events(document)
    assert result.files == [{"name": "a"}]
    assert result.dependencies == [{"name": "d"}]
    assert result.error == "unknown"
    assert result.error_details is None
    assert read_events({"output": None}).files == []


def error_document(**data: Any) -> dict[str, Any]:
    event = {"type": "record_update_job_error", "expect": {"data": data}}
    return {"output": [event]}


def test_u4_error_details_keep_the_whitelisted_package_fields() -> None:
    fields = {
        "dependency-name": "lodash",
        "dependency-version": "1.0.0",
        "latest-resolvable-version": "1.5.0",
        "lowest-non-vulnerable-version": "2.0.0",
    }
    data = {"error-type": "security_update_not_possible", "error-details": fields}
    assert json.loads(read_events(error_document(**data)).error_details) == fields


def test_u4_conflicting_dependencies_keep_four_keys() -> None:
    conflict = {
        "name": "a",
        "version": "1",
        "requirement": "^1",
        "explanation": "a needs b",
        "source": "x",
        "dependency-urls": ["u"],
    }
    data = {
        "error-type": "e",
        "error-details": {"conflicting-dependencies": [conflict]},
    }
    kept = json.loads(read_events(error_document(**data)).error_details)
    assert kept == {
        "conflicting-dependencies": [
            {
                "name": "a",
                "version": "1",
                "requirement": "^1",
                "explanation": "a needs b",
            }
        ]
    }


def test_u4_free_form_fields_are_dropped() -> None:
    details = {
        "dependency-name": "a",
        "error-message": "token ghs_ABC",
        "error-backtrace": "trace",
        "message": "m",
        "source": "s",
        "dependency-urls": ["u"],
    }
    data = {"error-type": "e", "error-details": details}
    assert json.loads(read_events(error_document(**data)).error_details) == {
        "dependency-name": "a"
    }


@pytest.mark.parametrize("details", [None, "text ghs_ABC", {"error-message": "m"}])
def test_u4_details_without_a_whitelisted_field_give_none(details: Any) -> None:
    data = {"error-type": "e", "error-details": details}
    assert read_events(error_document(**data)).error_details is None


def test_u4_error_details_are_cut() -> None:
    details = {"dependency-name": "x" * 5000}
    data = {"error-type": "e", "error-details": details}
    published = read_events(error_document(**data)).error_details
    assert published is not None and len(published) <= DETAILS_LIMIT


def test_u4_an_unknown_error_type_is_published_as_unknown() -> None:
    data = {"error-type": "ghs_ABC surprise"}
    assert read_events(error_document(**data)).error == UNKNOWN_ERROR
    data = {"error-type": "security_update_not_possible"}
    assert read_events(error_document(**data)).error == "security_update_not_possible"


def test_u4_a_timeout_logs_the_partial_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def slow(command: list[str], **kwargs: Any) -> Any:
        if command[0] != "dependabot":
            return subprocess.CompletedProcess(command, 0, "", "")
        raise subprocess.TimeoutExpired(command, 1, "partial out", "partial err")

    monkeypatch.setattr(subprocess, "run", slow)
    settings = Settings("dependabot", {"pip": "image"}, "proxy")
    assert run_job({}, tmp_path, settings, "pip").error == "dependabot_timeout"
    assert "partial err" in capsys.readouterr().err


def test_u4_a_yq_failure_gives_a_fixed_message_and_logs_the_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if command[0] == "yq":
            return subprocess.CompletedProcess(command, 1, "", "bad ghs_ABC")
        Path(command[command.index("-o") + 1]).write_text("x", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(subprocess, "run", run)
    settings = Settings("dependabot", {"pip": "image"}, "proxy")
    with pytest.raises(JobError, match="see the job log") as raised:
        run_job({}, tmp_path, settings, "pip")
    assert "ghs_ABC" not in str(raised.value)
    assert "ghs_ABC" in capsys.readouterr().err


def test_u4_the_cli_output_goes_to_the_job_log_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def failed(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args, 3, "out", "token ghs_ABC")

    monkeypatch.setattr(subprocess, "run", failed)
    settings = Settings("dependabot", {"pip": "image"}, "proxy")
    result = run_job({}, tmp_path, settings, "pip")
    assert result.error == "dependabot failed (exit 3), see the job log"
    assert "ghs_ABC" in capsys.readouterr().err
