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
        default="v0.76.2",
        sha256={
            "v0.76.2": {
                "linux-amd64": "bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf",
                "linux-arm64": "ab9d51f86e6a5fb936f605faff6b593ac51bc378fff4d3e8b9d58358b9c367c3",
            }
        },
        member="trivy",
    ),
    "osv-scanner": Tool(
        url="https://github.com/google/osv-scanner/releases/download/{tag}/osv-scanner_linux_{arch}",
        arch={"linux-amd64": "amd64", "linux-arm64": "arm64"},
        default="v2.7.1",
        sha256={
            "v2.7.1": {
                "linux-amd64": "fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8",
                "linux-arm64": "983d22fbad9724514e3fcc6acc83b5fa64c5ffa6b0d9f510028f22c1b223ff81",
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
