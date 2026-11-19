"""``sca java``: the JDK per Gradle wrapper version."""

import json
from pathlib import Path

import pytest

from sca.cli import main
from sca.java import choose, gradle_version, setup

URL = "distributionUrl=https\\://services.gradle.org/distributions/gradle-{}.zip\n"


def wrapper(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "gradle/wrapper/gradle-wrapper.properties"
    path.parent.mkdir(parents=True)
    path.write_text(f"distributionBase=GRADLE_USER_HOME\n{text}zipStoreBase=GRADLE_USER_HOME\n")
    return tmp_path


@pytest.mark.parametrize(
    ("version", "java"),
    [("8.10.2", 21), ("9.1.0", 25), ("9.0.0", 21), ("7.6.4", 17), ("8.5", 21), ("9.2.0-rc-1", 25), ("10.0", 25), ("5.6", 11)],
)
@pytest.mark.parametrize("kind", ["bin", "all"])
def test_choose(tmp_path: Path, capsys: pytest.CaptureFixture[str], version: str, java: int, kind: str) -> None:
    assert main(["java", str(wrapper(tmp_path, URL.format(f"{version}-{kind}")))]) == 0
    out = json.loads(capsys.readouterr().out)
    assert (out["java"], out["gradle"]) == (str(java), version)
    assert out["reason"]


def test_mirror_url(tmp_path: Path) -> None:
    text = "distributionUrl=https\\://mirror.corp.example/a/b/gradle-8.10.2-bin.zip\n"
    assert gradle_version(wrapper(tmp_path, text)) == "8.10.2"


def test_provided_without_best() -> None:
    assert choose("9.1.0", [11, 17, 21]) == 21
    assert choose("8.10.2", [11, 17]) == 17
    assert choose("9.0.0", [11, 17]) == 17
    with pytest.raises(ValueError, match="no JDK"):
        choose("9.0.0", [11])
    with pytest.raises(ValueError, match="no JDK"):
        choose("4.10", [11, 17])


def test_provided_option(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["java", str(wrapper(tmp_path, URL.format("8.10.2-bin"))), "--provided", "11,17"]) == 0
    assert json.loads(capsys.readouterr().out)["java"] == "17"


@pytest.mark.parametrize("text", ["", "distributionUrl=https://example.com/gradle.zip\n", "distributionUrl=gradle-latest-bin.zip\n"])
def test_exit_2(tmp_path: Path, capsys: pytest.CaptureFixture[str], text: str) -> None:
    assert main(["java", str(wrapper(tmp_path, text))]) == 2
    assert json.loads(capsys.readouterr().out)["reason"]


def test_missing_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["java", str(tmp_path)]) == 2
    assert "no gradle/wrapper" in json.loads(capsys.readouterr().out)["reason"]


ENV = {"JAVA_HOME_11_X64": "/j/11", "JAVA_HOME_21_ARM64": "/j/21", "JAVA_HOME_25_X64": "/j/25", "JAVA_HOME_17_X64": ""}


def test_setup(tmp_path: Path) -> None:
    props = tmp_path / "gradle.properties"
    props.write_text("a=b\norg.gradle.java.installations.fromEnv=OLD\n")
    assert setup(21, [11, 17, 21, 25], ENV, tmp_path) == "/j/21"
    assert props.read_text() == (
        "a=b\norg.gradle.java.installations.fromEnv=JAVA_HOME_11_X64,JAVA_HOME_21_ARM64,JAVA_HOME_25_X64\n"
    )


def test_setup_missing_jdk(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="JDK 17 is not installed"):
        setup(17, [11, 17, 21, 25], ENV, tmp_path)
    assert not (tmp_path / "gradle.properties").exists()


def test_setup_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("GRADLE_USER_HOME", str(tmp_path / "home"))
    assert main(["java", str(wrapper(tmp_path, URL.format("8.10.2-bin"))), "--setup"]) == 0
    assert json.loads(capsys.readouterr().out)["java_home"] == "/j/21"
    assert (tmp_path / "home/gradle.properties").is_file()
    monkeypatch.delenv("JAVA_HOME_21_ARM64")
    assert main(["java", str(tmp_path), "--setup"]) == 2
    assert "JDK 21 is not installed" in json.loads(capsys.readouterr().out)["reason"]
