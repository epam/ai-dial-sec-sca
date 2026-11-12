"""``sca db`` and ``sca scan`` with a fake ``trivy``, without network."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import jsonschema
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
SCHEMA = json.loads((Path(__file__).resolve().parents[2] / "schema" / "outputs.schema.json").read_text("utf-8"))


class FakeTrivy:
    """Stands in for ``subprocess.run`` of ``trivy``: writes what the real one writes
    and records every call, with the config and Docker config dir as they are during it.
    """

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.fail: set[str] = set()  # subcommands or flags that exit 1
        self.output = json.dumps(RESULT)  # what a scan writes
        self.explode = False

    def __call__(self, argv, env, cwd, text, encoding, capture_output):
        config, docker = env.get("TRIVY_CONFIG"), env.get("DOCKER_CONFIG")
        self.calls.append(
            {
                "argv": argv,
                "env": env,
                "cwd": cwd,
                "config": json.loads(Path(config).read_text("utf-8")) if config else None,
                "docker": sorted(p.name for p in Path(docker).iterdir()) if docker else None,
            }
        )
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


def outputs_of(directory: Path) -> dict:
    """``outputs.json`` of a command, valid against the contract schema."""
    document = read(directory / "outputs.json")
    jsonschema.Draft202012Validator(SCHEMA).validate(document)
    return document


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
    outputs = outputs_of(tmp_path / "out")
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


def test_db_runs_apart_from_the_machine(fake, tmp_path, monkeypatch):
    for name, value in (
        ("TRIVY_USERNAME", "u"),
        ("TRIVY_PASSWORD", SECRET),
        ("TRIVY_SEVERITY", "LOW"),
        ("SCA_REGISTRY_PASSWORD", SECRET),
        ("DOCKER_CONFIG", str(tmp_path)),
    ):
        monkeypatch.setenv(name, value)
    assert db(tmp_path) == 0
    for call in fake.calls:
        assert sorted(k for k in call["env"] if k.startswith(("TRIVY_", "SCA_"))) == [
            "TRIVY_CACHE_DIR",
            "TRIVY_CONFIG",
            "TRIVY_DB_REPOSITORY",
            "TRIVY_JAVA_DB_REPOSITORY",
        ]
        assert SECRET not in call["env"].values() and call["env"]["DOCKER_CONFIG"] != str(tmp_path)
        assert (call["config"], call["docker"]) == ({}, [])


def test_db_info_is_what_merge_reads(fake, tmp_path, run_env):
    assert db(tmp_path) == 0
    value = output_text("db-info", outputs_of(tmp_path / "out")["outputs"]["db-info"])
    run = Run(tmp_path, [target("source-development", "trivy", status="not_applicable")])
    merge = ["merge", "--targets-file", str(run.targets_file), "--parts-dir", str(run.parts)]
    assert cli.main([*merge, "--output-dir", str(run.out), "--trivy-db-info", value.split("=", 1)[1].strip()]) == 0
    tools = read(run.out / "report.json")["tools"]
    assert (tools["trivy_db"], tools["trivy_java_db"]) == ("2030-01-01T06:00:00.5Z", "2030-01-02T06:00:00Z")


@pytest.mark.parametrize(
    "fails, calls", [("--download-db-only", 1), ("--download-java-db-only", 2), ("version", 3)]
)
def test_db_failure_is_an_error_without_info(fake, tmp_path, fails, calls):
    fake.fail = {fails}
    assert db(tmp_path) == 1
    assert not (tmp_path / "out" / "db-info.json").exists() and len(fake.calls) == calls
    assert outputs_of(tmp_path / "out")["status"] == "error"


# --- sca scan -----------------------------------------------------------------


class Scan:
    """One target in a targets file, a tree and a parts directory in a temp directory."""

    def __init__(self, tmp_path, kind="fs", ref=None):
        self.tmp, self.kind = tmp_path, kind
        self.tree = tmp_path / "tree"
        self.tree.mkdir()
        self.parts = tmp_path / "parts"
        self.run = Run(tmp_path, [{**target("t1", "trivy", kind=kind), "ref": ref}])

    def __call__(self, *extra, tree=True) -> int:
        args = ["scan", "--targets-file", str(self.run.targets_file), "--target-id", "t1", "--kind", self.kind]
        args += ["--parts-dir", str(self.parts), "--cache-dir", str(self.tmp / "cache")]
        args += ["--output-dir", str(self.tmp / "out")]
        if tree:
            args += ["--tree", str(self.tree)]
        return cli.main([*args, *extra])

    def status(self):
        return read(self.parts / "trivy" / "t1.status.json")

    def outputs(self):
        return outputs_of(self.tmp / "out")


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


def test_scan_runs_with_the_settings_of_the_engine_and_nothing_inherited(fake, scan, monkeypatch):
    monkeypatch.setenv("TRIVY_SEVERITY", "CRITICAL")
    monkeypatch.setenv("TRIVY_SKIP_DIRS", "src")
    monkeypatch.setenv("TRIVY_REGISTRY_TOKEN", "inherited")
    monkeypatch.setenv("DOCKER_CONFIG", str(scan.tmp))
    assert scan() == 0
    for call in fake.calls:
        env = call["env"]
        assert env["TRIVY_SEVERITY"] == "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
        assert not {"TRIVY_SKIP_DIRS", "TRIVY_REGISTRY_TOKEN"} & set(env)
        assert env["DOCKER_CONFIG"] != str(scan.tmp) and call["docker"] == []
    env = fake.calls[0]["env"]
    assert (env["TRIVY_IGNOREFILE"], env["TRIVY_EXIT_CODE"], env["TRIVY_SKIP_DB_UPDATE"]) == ("/dev/null", "0", "true")
    assert env["TRIVY_CACHE_DIR"] == str((scan.tmp / "cache").resolve())


def test_the_repository_config_is_never_read_and_the_timeout_is_the_engines(fake, scan):
    (scan.tree / "trivy.yaml").write_text("severity: [LOW]\ntimeout: 1s\nscan:\n  skip-dirs:\n    - vendor\n")
    assert scan() == 0
    assert [c["config"] for c in fake.calls] == [{}, {}]
    assert all(c["env"]["TRIVY_TIMEOUT"] == "15m" for c in fake.calls)


def test_an_image_scan_has_a_neutral_config_whatever_the_directory(fake, tmp_path):
    scan = Scan(tmp_path, "image", IMAGE_REF)
    (scan.tree / "trivy.yaml").write_text("scan:\n  skip-dirs:\n    - vendor\n")
    assert scan(tree=False) == 0
    assert [c["config"] for c in fake.calls] == [{}, {}]


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
    notes = read(scan.tmp / "out" / "annotations.json")
    assert [(n["level"], n["title"]) for n in notes] == [("error", "Trivy target failed")]


def test_invalid_trivy_output_is_a_failed_status(fake, scan):
    fake.output = "not json"
    assert scan() == 1
    assert scan.status()["reason"] == "trivy output is missing or is not valid JSON"
    assert not (scan.parts / "trivy" / "t1.json").exists()


def test_failed_table_is_not_a_failed_target(fake, scan):
    fake.fail = {"convert"}
    assert scan() == 0 and scan.status()["status"] == "ok"


def test_exception_midway_still_writes_the_status_and_prints_the_traceback(fake, scan, capsys):
    fake.explode = True
    assert scan() == 1
    assert scan.status()["status"] == "failed" and "disk gone" in scan.status()["reason"]
    assert "Traceback" in capsys.readouterr().err


def test_failure_of_an_earlier_step_skips_trivy_but_keeps_what_there_is(fake, scan):
    (scan.tree / ".trivyignore").write_text("x\n")
    assert scan("--failed", "lockfile generation failure") == 1
    assert fake.calls == []
    assert scan.status()["reason"] == "lockfile generation failure" and scan.status()["ignorefile"] == "present"
    assert (scan.parts / "trivy" / "t1.trivyignore").exists()


def test_failed_checkout_has_no_ignorefile_state(fake, scan):
    assert scan("--failed", "checkout failure", tree=False) == 1
    assert scan.status()["ignorefile"] is None


def test_unreadable_targets_file_with_a_failed_step_still_leaves_the_status(fake, scan):
    scan.run.targets_file.unlink()
    assert scan("--failed", "targets download failure", tree=False) == 1
    assert scan.status() == {
        "id": "t1",
        "status": "failed",
        "reason": "targets download failure",
        "lockfiles": None,
        "ignorefile": None,
    }


def test_scan_of_an_image_has_no_ignorefile_and_scans_the_reference(fake, tmp_path):
    scan = Scan(tmp_path, "image", IMAGE_REF)
    assert scan(tree=False) == 0
    assert scan.status() == {"id": "t1", "status": "ok", "reason": None, "lockfiles": None}
    assert fake.calls[0]["argv"][-1] == IMAGE_REF and fake.calls[0]["cwd"] is None


# --- registry credentials -----------------------------------------------------


def with_credentials(monkeypatch, user="robot", password=SECRET):
    monkeypatch.setenv("SCA_REGISTRY_USER", user)
    monkeypatch.setenv("SCA_REGISTRY_PASSWORD", password)
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


@pytest.mark.parametrize("registry", ["docker.io", "quay.io:443", None])
def test_other_registries_are_anonymous(fake, tmp_path, monkeypatch, registry):
    with_credentials(monkeypatch)
    assert Scan(tmp_path, "image", IMAGE_REF)(*(["--registry", registry] if registry else []), tree=False) == 0
    env = fake.calls[0]["env"]
    assert not {"TRIVY_USERNAME", "TRIVY_PASSWORD", "TRIVY_REGISTRY_TOKEN", "SCA_REGISTRY_USER"} & set(env)


def test_a_registry_that_only_starts_like_the_host_of_the_image_gets_nothing(fake, tmp_path, monkeypatch):
    with_credentials(monkeypatch)
    assert Scan(tmp_path, "image", "ghcr.io.evil.test/x/app:1")("--registry", "ghcr.io", tree=False) == 0
    assert not {"TRIVY_USERNAME", "TRIVY_PASSWORD"} & set(fake.calls[0]["env"])


def test_a_source_scan_gets_no_credentials(fake, scan, monkeypatch, capsys):
    with_credentials(monkeypatch)
    assert scan("--registry", "ghcr.io") == 0
    assert all(SECRET not in c["env"].values() for c in fake.calls)
    assert SECRET not in capsys.readouterr().out


# --- usage errors leave a failed status and exit 2 ----------------------------


def test_half_credentials_are_a_usage_error_with_a_status(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("SCA_REGISTRY_USER", "robot")
    scan = Scan(tmp_path, "image", IMAGE_REF)
    assert scan("--registry", "ghcr.io", tree=False) == 2
    assert fake.calls == [] and scan.status()["status"] == "failed"
    assert scan.outputs()["outputs"] == {"status": "failed"}


@pytest.mark.parametrize("user, password", [("a,b", SECRET), ("robot", "x,y")])
def test_a_comma_in_the_credentials_is_a_usage_error_with_a_status(fake, tmp_path, monkeypatch, user, password):
    with_credentials(monkeypatch, user, password)
    scan = Scan(tmp_path, "image", IMAGE_REF)
    assert scan("--registry", "ghcr.io", tree=False) == 2
    assert fake.calls == [] and "comma" in scan.status()["reason"]
    assert password not in scan.status()["reason"]


@pytest.mark.parametrize("registry", ["ghcr", "ghcr.io/epam"])
def test_a_registry_that_is_not_a_host_is_a_usage_error_with_a_status(fake, tmp_path, registry):
    scan = Scan(tmp_path, "image", IMAGE_REF)
    assert scan("--registry", registry, tree=False) == 2
    assert fake.calls == [] and "host" in scan.status()["reason"]


@pytest.mark.parametrize("registry", ["localhost", "localhost:5000", "registry.example.test"])
def test_localhost_and_hosts_with_a_dot_or_port_are_hosts(fake, tmp_path, registry):
    assert Scan(tmp_path, "image", f"{registry}/app:1")("--registry", registry, tree=False) == 0


def test_a_source_target_without_a_tree_is_a_usage_error_with_a_status(fake, scan):
    assert scan(tree=False) == 2
    assert scan.status()["reason"] == "a source (fs) target needs --tree" and fake.calls == []
    assert scan.outputs()["status"] == "error"


def test_an_unknown_target_a_wrong_kind_or_an_unreadable_targets_file_is_a_usage_error_with_a_status(
    fake, scan, tmp_path
):
    rest = ["--parts-dir", str(scan.parts), "--cache-dir", str(tmp_path / "c"), "--output-dir", str(tmp_path / "o")]
    targets = ["--targets-file", str(scan.run.targets_file)]
    assert cli.main(["scan", *targets, "--target-id", "nope", "--kind", "fs", "--tree", str(scan.tree), *rest]) == 2
    assert read(scan.parts / "trivy" / "nope.status.json")["status"] == "failed"
    assert cli.main(["scan", *targets, "--target-id", "t1", "--kind", "image", *rest]) == 2
    assert "not 'image'" in read(scan.parts / "trivy" / "t1.status.json")["reason"]
    scan.run.targets_file.write_text("[]")
    assert scan() == 2 and "not a readable targets file" in scan.status()["reason"]
    assert fake.calls == []


@pytest.mark.parametrize("command", ["db", "scan"])
def test_missing_arguments_exit_2(command):
    with pytest.raises(SystemExit) as exit_:
        cli.main([command])
    assert exit_.value.code == 2
