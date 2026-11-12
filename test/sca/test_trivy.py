"""``sca db`` and ``sca scan`` with a fake ``trivy``, without network."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from github_adapter import output_text
from test_merge_results import Run, target

from sca import cli

DB_INFO = {
    "VulnerabilityDB": {"UpdatedAt": "2030-01-01T06:00:00.5Z"},
    "JavaDB": {"UpdatedAt": "2030-01-02T06:00:00Z"},
}
RESULT = {"SchemaVersion": 2, "Results": []}
SECRET = "s3cret"
IMAGE_REF = "ghcr.io/epam/ai-dial-chat:1.0.0"


class FakeTrivy:
    """Stands in for ``subprocess.run`` of ``trivy``: writes what the real one writes
    and records every call.
    """

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.fail: set[str] = set()  # subcommands or flags that exit 1
        self.output = json.dumps(RESULT)  # what a scan writes
        self.explode = False

    def __call__(self, argv, env, cwd, text, encoding, capture_output):
        self.calls.append({"argv": argv, "env": env, "cwd": cwd})
        verb = argv[1]
        if self.explode and verb in ("fs", "image"):
            raise OSError("disk gone")
        failed = verb in self.fail or any(a in self.fail for a in argv)
        out = ""
        if verb == "version":
            out = json.dumps(DB_INFO)
        elif verb in ("fs", "image", "convert") and "--output" in argv and not failed:
            path = Path(argv[argv.index("--output") + 1])
            path.write_text("table" if verb == "convert" else self.output, encoding="utf-8")
        return subprocess.CompletedProcess(argv, 1 if failed else 0, out, "")


@pytest.fixture
def fake(monkeypatch):
    trivy = FakeTrivy()
    monkeypatch.setattr("sca.trivy.subprocess.run", trivy)
    for name in ("TRIVY_DB_REPOSITORY", "TRIVY_JAVA_DB_REPOSITORY", "SCA_REGISTRY_USER", "SCA_REGISTRY_PASSWORD"):
        monkeypatch.delenv(name, raising=False)
    return trivy


def read(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


# --- sca db -------------------------------------------------------------------


def db(tmp_path, *extra) -> int:
    return cli.main(["db", "--cache-dir", str(tmp_path / "cache"), "--output-dir", str(tmp_path / "out"), *extra])


def test_db_downloads_both_databases_and_writes_the_info(fake, tmp_path):
    assert db(tmp_path) == 0
    assert [c["argv"][1:] for c in fake.calls] == [
        ["image", "--download-db-only"],
        ["image", "--download-java-db-only"],
        ["version", "--format", "json"],
    ]
    env = fake.calls[0]["env"]
    assert env["TRIVY_CACHE_DIR"] == str((tmp_path / "cache").resolve())
    assert env["TRIVY_DB_REPOSITORY"].startswith("mirror.gcr.io/aquasec/trivy-db:2,")
    assert env["TRIVY_JAVA_DB_REPOSITORY"].endswith(",ghcr.io/aquasecurity/trivy-java-db:1")
    info = {"vulnerability_db_updated_at": "2030-01-01T06:00:00.5Z", "java_db_updated_at": "2030-01-02T06:00:00Z"}
    assert read(tmp_path / "out" / "db-info.json") == info
    outputs = read(tmp_path / "out" / "outputs.json")
    assert (outputs["command"], outputs["status"], outputs["outputs"]) == ("db", "ok", {"db-info": info})
    assert (tmp_path / "out" / "summary.md").read_text() == (
        'Trivy DB snapshot: {"vulnerability_db_updated_at":"2030-01-01T06:00:00.5Z",'
        '"java_db_updated_at":"2030-01-02T06:00:00Z"}\n'
    )


def test_db_repositories_come_from_the_arguments_then_the_environment(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("TRIVY_DB_REPOSITORY", "env.test/db:2")
    monkeypatch.setenv("TRIVY_JAVA_DB_REPOSITORY", "env.test/java:1")
    assert db(tmp_path, "--trivy-db-repository", "arg.test/db:2") == 0
    env = fake.calls[0]["env"]
    assert (env["TRIVY_DB_REPOSITORY"], env["TRIVY_JAVA_DB_REPOSITORY"]) == ("arg.test/db:2", "env.test/java:1")


def test_db_info_is_what_merge_reads(fake, tmp_path, run_env):
    assert db(tmp_path) == 0
    value = output_text("db-info", read(tmp_path / "out" / "outputs.json")["outputs"]["db-info"])
    run = Run(tmp_path, [target("source-development", "trivy", status="not_applicable")])
    merge = ["merge", "--targets-file", str(run.targets_file), "--parts-dir", str(run.parts)]
    assert cli.main([*merge, "--output-dir", str(run.out), "--trivy-db-info", value.split("=", 1)[1].strip()]) == 0
    tools = read(run.out / "report.json")["tools"]
    assert (tools["trivy_db"], tools["trivy_java_db"]) == ("2030-01-01T06:00:00.5Z", "2030-01-02T06:00:00Z")


@pytest.mark.parametrize("fails", ["--download-java-db-only", "version"])
def test_db_failure_is_an_error_without_info(fake, tmp_path, fails):
    fake.fail = {fails}
    assert db(tmp_path) == 1
    assert not (tmp_path / "out" / "db-info.json").exists()
    assert read(tmp_path / "out" / "outputs.json")["status"] == "error"


# --- sca scan -----------------------------------------------------------------


class Scan:
    """One target in a targets file, a tree and a parts directory in a temp directory."""

    def __init__(self, tmp_path, kind="fs", ref=None):
        self.tmp = tmp_path
        self.tree = tmp_path / "tree"
        self.tree.mkdir()
        self.parts = tmp_path / "parts"
        self.run = Run(tmp_path, [{**target("t1", "trivy", kind=kind), "ref": ref}])

    def __call__(self, *extra, tree=True) -> int:
        args = ["scan", "--targets-file", str(self.run.targets_file), "--target-id", "t1"]
        args += ["--parts-dir", str(self.parts), "--cache-dir", str(self.tmp / "cache")]
        args += ["--output-dir", str(self.tmp / "out")]
        if tree:
            args += ["--tree", str(self.tree)]
        return cli.main([*args, *extra])

    def status(self):
        return read(self.parts / "trivy" / "t1.status.json")

    def outputs(self):
        return read(self.tmp / "out" / "outputs.json")


@pytest.fixture
def scan(tmp_path):
    return Scan(tmp_path)


def test_scan_of_a_source_writes_the_parts(fake, scan):
    assert scan("--lockfiles", "3") == 0
    parts = scan.parts / "trivy"
    assert read(parts / "t1.json") == RESULT and (parts / "t1.txt").read_text() == "table"
    assert scan.status() == {"id": "t1", "status": "ok", "reason": None, "lockfiles": 3, "ignorefile": "absent"}
    assert not (parts / "t1.trivyignore").exists()
    assert [c["argv"][1] for c in fake.calls] == ["fs", "convert"]
    assert fake.calls[0]["argv"][-1] == "." and fake.calls[0]["cwd"] == scan.tree
    out = scan.outputs()
    assert (out["command"], out["status"], out["outputs"]) == ("scan", "ok", {"status": "ok"})


def test_scan_runs_with_the_settings_of_the_engine(fake, scan, monkeypatch):
    monkeypatch.setenv("TRIVY_SEVERITY", "CRITICAL")
    assert scan() == 0
    env = fake.calls[0]["env"]
    assert env["TRIVY_SEVERITY"] == "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
    assert (env["TRIVY_IGNOREFILE"], env["TRIVY_EXIT_CODE"], env["TRIVY_SKIP_DB_UPDATE"]) == ("/dev/null", "0", "true")
    assert env["TRIVY_CACHE_DIR"] == str((scan.tmp / "cache").resolve())


def test_scan_keeps_the_ignorefile_and_the_graph(fake, scan):
    (scan.tree / ".trivyignore").write_text("CVE-2030-1\n")
    graph = scan.tmp / "graph"
    graph.mkdir()
    (graph / "graph-root.json").write_text("{}")
    assert scan("--graph-dir", str(graph)) == 0
    parts = scan.parts / "trivy"
    assert (parts / "t1.trivyignore").read_text() == "CVE-2030-1\n"
    assert (parts / "t1.gradle-graph" / "graph-root.json").read_text() == "{}"
    assert scan.status()["ignorefile"] == "present" and scan.status()["lockfiles"] is None


def test_failed_trivy_writes_a_failed_status_and_no_result(fake, scan):
    fake.fail = {"fs"}
    assert scan() == 1
    assert scan.status() == {
        "id": "t1",
        "status": "failed",
        "reason": "trivy scan failure",
        "lockfiles": None,
        "ignorefile": "absent",
    }
    assert not (scan.parts / "trivy" / "t1.json").exists() and len(fake.calls) == 1
    out = scan.outputs()
    assert (out["status"], out["outputs"]) == ("error", {"status": "failed"})
    assert "trivy scan failure" in out["message"]


def test_invalid_trivy_output_is_a_failed_status(fake, scan):
    fake.output = "not json"
    assert scan() == 1
    assert scan.status()["reason"] == "trivy output is missing or is not valid JSON"
    assert not (scan.parts / "trivy" / "t1.json").exists()


def test_failed_table_is_not_a_failed_target(fake, scan):
    fake.fail = {"convert"}
    assert scan() == 0 and scan.status()["status"] == "ok"


def test_exception_midway_still_writes_the_status(fake, scan):
    fake.explode = True
    assert scan() == 1
    assert scan.status()["status"] == "failed" and "disk gone" in scan.status()["reason"]


def test_failure_of_an_earlier_step_skips_trivy_but_keeps_what_there_is(fake, scan):
    (scan.tree / ".trivyignore").write_text("x\n")
    assert scan("--failed", "lockfile generation failure") == 1
    assert fake.calls == []
    assert scan.status()["reason"] == "lockfile generation failure" and scan.status()["ignorefile"] == "present"
    assert (scan.parts / "trivy" / "t1.trivyignore").exists()


def test_failed_checkout_has_no_ignorefile_state(fake, scan):
    assert scan("--failed", "checkout failure", tree=False) == 1
    assert scan.status()["ignorefile"] is None


def test_scan_of_an_image_has_no_ignorefile_and_scans_the_reference(fake, tmp_path):
    scan = Scan(tmp_path, "image", IMAGE_REF)
    assert scan(tree=False) == 0
    assert scan.status() == {"id": "t1", "status": "ok", "reason": None, "lockfiles": None}
    assert fake.calls[0]["argv"][-1] == IMAGE_REF and fake.calls[0]["cwd"] is None


# --- registry credentials -----------------------------------------------------


def with_credentials(monkeypatch):
    monkeypatch.setenv("SCA_REGISTRY_USER", "robot")
    monkeypatch.setenv("SCA_REGISTRY_PASSWORD", SECRET)
    monkeypatch.setenv("TRIVY_REGISTRY_TOKEN", "inherited")


def test_credentials_reach_trivy_for_the_registry_of_the_image_only_by_environment(fake, tmp_path, monkeypatch):
    with_credentials(monkeypatch)
    assert Scan(tmp_path, "image", IMAGE_REF)("--registry", "ghcr.io", tree=False) == 0
    call = fake.calls[0]
    assert (call["env"]["TRIVY_USERNAME"], call["env"]["TRIVY_PASSWORD"]) == ("robot", SECRET)
    assert "SCA_REGISTRY_PASSWORD" not in call["env"] and "TRIVY_REGISTRY_TOKEN" not in call["env"]
    assert not any(SECRET in part for c in fake.calls for part in c["argv"])
    assert all("TRIVY_PASSWORD" not in c["env"] for c in fake.calls[1:])
    for written in tmp_path.rglob("*.json"):
        assert SECRET not in written.read_text(encoding="utf-8")


@pytest.mark.parametrize("registry", ["docker.io", "ghcr.io.example.test", None])
def test_other_registries_are_anonymous(fake, tmp_path, monkeypatch, registry):
    with_credentials(monkeypatch)
    assert Scan(tmp_path, "image", IMAGE_REF)(*(["--registry", registry] if registry else []), tree=False) == 0
    env = fake.calls[0]["env"]
    assert not {"TRIVY_USERNAME", "TRIVY_PASSWORD", "TRIVY_REGISTRY_TOKEN", "SCA_REGISTRY_USER"} & set(env)


def test_a_source_scan_gets_no_credentials(fake, scan, monkeypatch, capsys):
    with_credentials(monkeypatch)
    assert scan("--registry", "ghcr.io") == 0
    assert all(SECRET not in c["env"].values() for c in fake.calls)
    assert SECRET not in capsys.readouterr().out


def test_half_credentials_are_a_usage_error(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("SCA_REGISTRY_USER", "robot")
    assert Scan(tmp_path, "image", IMAGE_REF)("--registry", "ghcr.io", tree=False) == 2
    assert fake.calls == []


# --- usage --------------------------------------------------------------------


def test_scan_usage_errors_exit_2(fake, scan, tmp_path):
    assert scan(tree=False) == 2  # a source target needs a tree
    assert not (scan.parts / "trivy" / "t1.status.json").exists()
    rest = ["--parts-dir", str(tmp_path / "p"), "--cache-dir", str(tmp_path / "c"), "--output-dir", str(tmp_path / "o")]
    assert cli.main(["scan", "--targets-file", str(tmp_path / "none.json"), "--target-id", "t1", *rest]) == 2
    assert cli.main(["scan", "--targets-file", str(scan.run.targets_file), "--target-id", "nope", *rest]) == 2
    assert fake.calls == []


@pytest.mark.parametrize("command", ["db", "scan"])
def test_missing_arguments_exit_2(command):
    with pytest.raises(SystemExit) as exit_:
        cli.main([command])
    assert exit_.value.code == 2
