"""``sca tools install``: the pin table and the installer, without network."""

from __future__ import annotations

import hashlib
import io
import json
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from sca import cli
from sca.tools import cli as tools_cli
from sca.tools import pins

SYSTEM = "linux-amd64"
ARCHIVE = "fake-tool_linux_amd64.tar.gz"


def make_tar(path: Path, members: dict[str, bytes], links: dict[str, tuple[bytes, str]] | None = None) -> bytes:
    """``links``: member -> (tar link type, target)."""
    with tarfile.open(path, "w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for name, (kind, target) in (links or {}).items():
            info = tarfile.TarInfo(name)
            info.type, info.linkname = kind, target
            tar.addfile(info)
    return path.read_bytes()


BIN = "tools/bin"
DOWNLOADS = "tools/downloads"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def served(tmp_path, monkeypatch):
    """A fake release of ``trivy`` (tar.gz) and ``osv-scanner`` (raw binary) in the
    table, a ``fetch`` that serves it and counts the downloads.
    """
    trivy_bytes = make_tar(tmp_path / "trivy.tgz", {"README": b"x", "trivy": b"#!trivy\n"})
    osv_bytes = b"#!osv\n"
    files = {"https://example.test/trivy_1.2.3.tar.gz": trivy_bytes, "https://example.test/osv": osv_bytes}
    table = {
        "trivy": pins.Tool(
            url="https://example.test/trivy_{version}.tar.gz",
            arch={SYSTEM: "x"},
            default="v1.2.3",
            sha256={"v1.2.3": {SYSTEM: digest(trivy_bytes)}},
            member="trivy",
        ),
        "osv-scanner": pins.Tool(
            url="https://example.test/osv",
            arch={SYSTEM: "x"},
            default="v2.0.0",
            sha256={"v2.0.0": {SYSTEM: digest(osv_bytes)}},
            member=None,
        ),
    }
    monkeypatch.setattr(pins, "TOOLS", table)
    monkeypatch.setattr(tools_cli, "current_platform", lambda: SYSTEM)
    downloads: list[str] = []

    def fetch(url: str, target: Path) -> None:
        downloads.append(url)
        target.write_bytes(files[url])

    monkeypatch.setattr(tools_cli, "fetch", fetch)
    return downloads, files


def run(tmp_path: Path, *extra: str) -> int:
    return cli.main(
        ["tools", "install", "--dir", str(tmp_path / "tools"), "--output-dir", str(tmp_path / "out"), *extra]
    )


def outputs(tmp_path: Path) -> dict:
    return json.loads((tmp_path / "out" / "outputs.json").read_text(encoding="utf-8"))


def test_the_table_has_every_tool_for_both_platforms() -> None:
    assert set(pins.TOOLS) == {"trivy", "osv-scanner", "oras", "crane"}
    for name, tool in pins.TOOLS.items():
        assert set(tool.arch) == set(pins.PLATFORMS), name
        assert tool.default in tool.sha256, name
        for tag, by_platform in tool.sha256.items():
            assert tag.startswith("v"), name
            assert set(by_platform) == set(pins.PLATFORMS), name
            assert all(len(s) == 64 and int(s, 16) >= 0 for s in by_platform.values()), name
        for platform_name in pins.PLATFORMS:
            url = tool.url.format(tag=tool.default, version=tool.default[1:], arch=tool.arch[platform_name])
            assert url.startswith("https://github.com/"), name


def test_install_puts_executable_binaries_and_writes_outputs(tmp_path, served) -> None:
    assert run(tmp_path) == 0
    binaries = tmp_path / BIN
    assert (binaries / "trivy").read_bytes() == b"#!trivy\n"
    assert (binaries / "osv-scanner").read_bytes() == b"#!osv\n"
    if sys.platform != "win32":
        assert (binaries / "trivy").stat().st_mode & stat.S_IXUSR
    written = outputs(tmp_path)
    assert written["command"] == "tools-install" and written["status"] == "ok"
    assert written["outputs"] == {
        "dir": str(binaries.resolve()),
        "downloads": str((tmp_path / DOWNLOADS).resolve()),
        "versions": {"trivy": "v1.2.3", "osv-scanner": "v2.0.0"},
    }


def test_tools_option_selects_the_tools(tmp_path, served) -> None:
    assert run(tmp_path, "--tools", "osv-scanner") == 0
    assert not (tmp_path / BIN / "trivy").exists()
    assert outputs(tmp_path)["outputs"]["versions"] == {"osv-scanner": "v2.0.0"}


def test_a_verified_cache_is_not_downloaded_again(tmp_path, served) -> None:
    downloads, _ = served
    assert run(tmp_path) == 0
    (tmp_path / BIN / "trivy").unlink()
    assert run(tmp_path) == 0
    assert len(downloads) == 2
    assert (tmp_path / BIN / "trivy").exists()


def test_a_tampered_cache_is_downloaded_again(tmp_path, served) -> None:
    downloads, files = served
    assert run(tmp_path) == 0
    (tmp_path / DOWNLOADS / "trivy_1.2.3.tar.gz").write_bytes(b"tampered")
    assert run(tmp_path) == 0
    assert len(downloads) == 3
    assert (tmp_path / DOWNLOADS / "trivy_1.2.3.tar.gz").read_bytes() == files["https://example.test/trivy_1.2.3.tar.gz"]
    assert (tmp_path / BIN / "trivy").read_bytes() == b"#!trivy\n"


def test_a_mismatch_on_a_fresh_download_is_an_error_without_a_binary(tmp_path, served) -> None:
    _, files = served
    files["https://example.test/osv"] = b"replaced"
    assert run(tmp_path, "--tools", "osv-scanner") == 1
    assert sorted(p.name for p in (tmp_path / BIN).iterdir()) == []
    written = outputs(tmp_path)
    assert written["status"] == "error" and "sha256" in written["message"]


def test_a_mismatch_removes_the_binary_of_an_earlier_run(tmp_path, served) -> None:
    _, files = served
    assert run(tmp_path, "--tools", "osv-scanner") == 0
    (tmp_path / DOWNLOADS / "osv").write_bytes(b"tampered")
    (tmp_path / BIN / "osv-scanner").write_bytes(b"tampered")
    files["https://example.test/osv"] = b"replaced"
    assert run(tmp_path, "--tools", "osv-scanner") == 1
    assert not (tmp_path / BIN / "osv-scanner").exists()


def test_a_trivy_version_that_is_not_pinned_needs_a_sha256(tmp_path, served) -> None:
    assert run(tmp_path, "--tools", "trivy", "--trivy-version", "v9.9.9") == 2
    assert "--trivy-sha256" in outputs(tmp_path)["message"]


def test_a_trivy_version_with_its_sha256_is_installed(tmp_path, served) -> None:
    _, files = served
    data = files["https://example.test/trivy_1.2.3.tar.gz"]
    files["https://example.test/trivy_9.9.9.tar.gz"] = data
    assert run(tmp_path, "--tools", "trivy", "--trivy-version", "v9.9.9", "--trivy-sha256", digest(data)) == 0
    assert outputs(tmp_path)["outputs"]["versions"] == {"trivy": "v9.9.9"}


@pytest.mark.parametrize("version", ["1.2.3", "v1.2", "v1.2.3-rc1", "latest"])
def test_a_trivy_version_must_be_a_release_tag(tmp_path, served, version) -> None:
    assert run(tmp_path, "--trivy-version", version) == 2
    assert "vX.Y.Z" in outputs(tmp_path)["message"]


def test_a_bad_trivy_sha256_and_an_unknown_tool_are_usage_errors(tmp_path, served) -> None:
    assert run(tmp_path, "--trivy-sha256", "abc") == 2
    assert run(tmp_path, "--tools", "trivy,nope") == 2


def test_the_archive_must_hold_the_binary(tmp_path, served, monkeypatch) -> None:
    data = make_tar(tmp_path / "empty.tgz", {"other": b"x"})
    monkeypatch.setitem(
        pins.TOOLS, "trivy", pins.Tool(
            url="https://example.test/empty.tgz", arch={SYSTEM: "x"}, default="v1.0.0",
            sha256={"v1.0.0": {SYSTEM: digest(data)}}, member="trivy",
        ),
    )
    served[1]["https://example.test/empty.tgz"] = data
    assert run(tmp_path, "--tools", "trivy") == 1
    assert not (tmp_path / BIN / "trivy").exists()


@pytest.mark.parametrize(
    ("system", "machine", "expected"),
    [("Linux", "x86_64", "linux-amd64"), ("Linux", "aarch64", "linux-arm64"), ("Linux", "arm64", "linux-arm64")],
)
def test_the_platform_is_linux_amd64_or_arm64(monkeypatch, system, machine, expected) -> None:
    monkeypatch.setattr(tools_cli.platform, "system", lambda: system)
    monkeypatch.setattr(tools_cli.platform, "machine", lambda: machine)
    assert tools_cli.current_platform() == expected


@pytest.mark.parametrize(("system", "machine"), [("Darwin", "arm64"), ("Linux", "armv7l"), ("Windows", "AMD64")])
def test_another_platform_is_an_error(monkeypatch, system, machine) -> None:
    monkeypatch.setattr(tools_cli.platform, "system", lambda: system)
    monkeypatch.setattr(tools_cli.platform, "machine", lambda: machine)
    with pytest.raises(tools_cli.CommandError, match="unsupported platform"):
        tools_cli.current_platform()


@pytest.mark.parametrize("command", ["targets", "osv", "merge", "plan", "tools"])
def test_a_command_shows_its_own_program_name(command, capsys) -> None:
    with pytest.raises(SystemExit) as stop:
        cli.main([command, "--help"])
    assert stop.value.code == 0
    assert capsys.readouterr().out.startswith(f"usage: sca {command} ")


def test_the_github_adapter_puts_a_dir_on_the_path(tmp_path) -> None:
    target = tmp_path / "path"
    adapter = Path(__file__).parents[2] / "actions" / "_github" / "github_adapter.py"
    subprocess.run(
        [sys.executable, "-I", str(adapter), "path", "/opt/tools"],
        check=True,
        env={"GITHUB_PATH": str(target)},
    )
    assert target.read_text(encoding="utf-8") == "/opt/tools\n"


def key_of(tmp_path: Path, *extra: str) -> str:
    assert cli.main(["tools", "key", "--dir", str(tmp_path / "tools"), "--output-dir", str(tmp_path / "key"), *extra]) == 0
    written = json.loads((tmp_path / "key" / "outputs.json").read_text(encoding="utf-8"))
    assert written["command"] == "tools-key"
    return written["outputs"]["key"]


def test_the_cache_key_follows_the_pins_the_tools_and_the_platform(tmp_path, served, monkeypatch) -> None:
    both = key_of(tmp_path)
    assert both.startswith("sca-tools-linux-amd64-")
    assert key_of(tmp_path) == both
    assert key_of(tmp_path, "--tools", "trivy") != both
    other = pins.TOOLS["trivy"]
    monkeypatch.setitem(
        pins.TOOLS, "trivy", pins.Tool(other.url, other.arch, "v1.2.4", {"v1.2.4": other.sha256["v1.2.3"]}, other.member)
    )
    assert key_of(tmp_path) != both


def test_a_sha256_only_change_of_a_pin_is_a_new_key(tmp_path, served, monkeypatch) -> None:
    before = key_of(tmp_path)
    other = pins.TOOLS["trivy"]
    monkeypatch.setitem(
        pins.TOOLS, "trivy", pins.Tool(other.url, other.arch, "v1.2.3", {"v1.2.3": {SYSTEM: "0" * 64}}, other.member)
    )
    assert key_of(tmp_path) != before


def test_a_platform_change_is_a_new_key(tmp_path, served, monkeypatch) -> None:
    before = key_of(tmp_path)
    for tool in pins.TOOLS.values():  # the same pins for the other platform: only the platform differs
        tool.arch["linux-arm64"] = tool.arch[SYSTEM]
        tool.sha256[tool.default]["linux-arm64"] = tool.sha256[tool.default][SYSTEM]
    monkeypatch.setattr(tools_cli, "current_platform", lambda: "linux-arm64")
    after = key_of(tmp_path)
    assert after != before and after.startswith("sca-tools-linux-arm64-")


def key_of_status(tmp_path: Path, *extra: str) -> int:
    return cli.main(["tools", "key", "--dir", str(tmp_path / "tools"), "--output-dir", str(tmp_path / "key"), *extra])


def test_the_cache_key_needs_the_sha256_of_an_unpinned_trivy(tmp_path, served) -> None:
    assert key_of_status(tmp_path, "--trivy-version", "v9.9.9") == 2


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE])
def test_a_link_as_the_archive_member_is_refused(tmp_path, served, kind) -> None:
    data = make_tar(tmp_path / "links.tgz", {"README": b"x"}, {"trivy": (kind, "README")})
    pins.TOOLS["trivy"] = pins.Tool(
        url="https://example.test/links.tgz", arch={SYSTEM: "x"}, default="v1.0.0",
        sha256={"v1.0.0": {SYSTEM: digest(data)}}, member="trivy",
    )
    served[1]["https://example.test/links.tgz"] = data
    assert run(tmp_path, "--tools", "trivy") == 1
    assert "not a regular file" in outputs(tmp_path)["message"]
    assert not (tmp_path / BIN / "trivy").exists()


def test_a_stray_entry_never_reaches_the_bin_directory(tmp_path, served) -> None:
    assert run(tmp_path) == 0
    stray = tmp_path / DOWNLOADS / "evil"
    stray.write_bytes(b"#!evil\n")
    (tmp_path / BIN / "evil").write_bytes(b"#!evil\n")
    assert run(tmp_path) == 0
    assert sorted(p.name for p in (tmp_path / BIN).iterdir()) == ["osv-scanner", "trivy"]
    assert stray.exists()


def test_a_directory_where_a_file_is_expected_is_replaced(tmp_path, served) -> None:
    (tmp_path / DOWNLOADS / "osv").mkdir(parents=True)
    (tmp_path / DOWNLOADS / "osv" / "inner").write_bytes(b"x")
    (tmp_path / "tools" / "bin").write_bytes(b"a file where bin goes")
    assert run(tmp_path, "--tools", "osv-scanner") == 0
    assert (tmp_path / BIN / "osv-scanner").read_bytes() == b"#!osv\n"


def test_an_uppercase_trivy_sha256_is_accepted(tmp_path, served) -> None:
    _, files = served
    data = files["https://example.test/trivy_1.2.3.tar.gz"]
    files["https://example.test/trivy_9.9.9.tar.gz"] = data
    assert run(tmp_path, "--tools", "trivy", "--trivy-version", "v9.9.9", "--trivy-sha256", digest(data).upper()) == 0


def test_a_non_ascii_digit_is_not_a_version(tmp_path, served) -> None:
    assert run(tmp_path, "--trivy-version", "v١.2.3") == 2


def test_a_failed_install_still_writes_the_annotation(tmp_path, served) -> None:
    served[1]["https://example.test/osv"] = b"replaced"
    assert run(tmp_path, "--tools", "osv-scanner") == 1
    notes = json.loads((tmp_path / "out" / "annotations.json").read_text(encoding="utf-8"))
    assert [n["level"] for n in notes] == ["error"] and "sha256" in notes[0]["message"]


def test_a_download_is_retried_on_an_http_error(monkeypatch, tmp_path) -> None:
    calls = []

    def urlopen(url, timeout):
        calls.append(url)
        raise tools_cli.http.client.IncompleteRead(b"")

    monkeypatch.setattr(tools_cli.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(tools_cli.time, "sleep", lambda _: None)
    with pytest.raises(tools_cli.CommandError, match="cannot download"):
        tools_cli.fetch("https://example.test/x", tmp_path / "x")
    assert len(calls) == tools_cli.ATTEMPTS
