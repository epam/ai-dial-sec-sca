"""The one table of tool versions and checksums. Every sha256 is the one of the
project's official release checksums file, checked against the downloaded artifact;
the checksums file of a release is not trusted by itself at install time.
"""

from __future__ import annotations

from dataclasses import dataclass

PLATFORMS = ("linux-amd64", "linux-arm64")


@dataclass(frozen=True)
class Tool:
    url: str  # of the artifact; {tag} (vX.Y.Z), {version} (X.Y.Z), {arch}
    arch: dict[str, str]  # platform -> {arch} in the url
    default: str  # the tag installed unless another one is asked for
    sha256: dict[str, dict[str, str]]  # tag -> platform -> sha256 of the artifact
    member: str | None  # the binary in a tar.gz artifact; None: the artifact is the binary


TOOLS = {
    "trivy": Tool(
        url="https://github.com/aquasecurity/trivy/releases/download/{tag}/trivy_{version}_Linux-{arch}.tar.gz",
        arch={"linux-amd64": "64bit", "linux-arm64": "ARM64"},
        default="v0.75.0",
        sha256={
            "v0.75.0": {
                "linux-amd64": "c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f",
                "linux-arm64": "a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3",
            }
        },
        member="trivy",
    ),
    "osv-scanner": Tool(
        url="https://github.com/google/osv-scanner/releases/download/{tag}/osv-scanner_linux_{arch}",
        arch={"linux-amd64": "amd64", "linux-arm64": "arm64"},
        default="v2.7.0",
        sha256={
            "v2.7.0": {
                "linux-amd64": "160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b",
                "linux-arm64": "4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7",
            }
        },
        member=None,
    ),
    "oras": Tool(
        url="https://github.com/oras-project/oras/releases/download/{tag}/oras_{version}_linux_{arch}.tar.gz",
        arch={"linux-amd64": "amd64", "linux-arm64": "arm64"},
        default="v1.3.4",
        sha256={
            "v1.3.4": {
                "linux-amd64": "f27adb935022d94df8dc77719c322dda592c78a0d57a6f7dcdd8d900b248c454",
                "linux-arm64": "15702c6e3a4a56a8bd8ac5c17efdbcab56d9bada661ccbcf017f5b10c1d89399",
            }
        },
        member="oras",
    ),
    "crane": Tool(
        url="https://github.com/google/go-containerregistry/releases/download/{tag}/go-containerregistry_Linux_{arch}.tar.gz",
        arch={"linux-amd64": "x86_64", "linux-arm64": "arm64"},
        default="v0.22.1",
        sha256={
            "v0.22.1": {
                "linux-amd64": "0ab7a1d6932a213aed964ce97666c3077fe691c8606413674a8b3e0b9ec4cda0",
                "linux-arm64": "898c0cff975f898a33e8c4580bdafb0e7c02c7faa33374e946762f97c4ab7110",
            }
        },
        member="crane",
    ),
}
