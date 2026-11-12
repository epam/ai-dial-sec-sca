"""Registry credentials of the scan commands: ``SCA_REGISTRY_USER`` and
``SCA_REGISTRY_PASSWORD``, used only for an image of ``--registry`` (a host)."""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Mapping
from pathlib import Path

from .context import UsageError

USER_ENV, PASSWORD_ENV = "SCA_REGISTRY_USER", "SCA_REGISTRY_PASSWORD"
# Docker Hub keeps its credentials under one historical key, whatever name the image has
HUB_AUTH_KEY = "https://index.docker.io/v1/"
AUTH_KEYS = {"docker.io": HUB_AUTH_KEY, "index.docker.io": HUB_AUTH_KEY}
# The variables that give a registry client credentials or a config of the machine
AMBIENT_ENV = (USER_ENV, PASSWORD_ENV, "DOCKER_CONFIG", "REGISTRY_AUTH_FILE")


def clean_env() -> dict[str, str]:
    """The process environment without registry credentials and Docker or Podman auth
    configuration: a subprocess gets credentials only from the environment it is given."""
    return {k: v for k, v in os.environ.items() if k not in AMBIENT_ENV}


def write_docker_config(directory: Path, host: str | None = None, credentials: tuple[str, str] | None = None) -> None:
    """A private ``DOCKER_CONFIG`` directory with a ``config.json`` that holds the one
    ``auths`` entry of ``host``, or none (anonymous). The file always exists: without
    it a client falls back to the Podman auth files of the machine."""
    directory.mkdir(mode=0o700, exist_ok=True)
    auths = {}
    if credentials and host:
        auth = base64.b64encode(":".join(credentials).encode()).decode()
        auths[AUTH_KEYS.get(host, host)] = {"auth": auth}
    fd = os.open(directory / "config.json", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"auths": auths}, f)


def is_host(value: str) -> bool:
    return "/" not in value and ("." in value or ":" in value or value == "localhost")


def check_registry(registry: str | None) -> None:
    if registry is not None and not is_host(registry):
        raise UsageError(f"--registry must be a host (a dot, a port or localhost), got {registry!r}")


def check_credentials(environ: Mapping[str, str] = os.environ) -> tuple[str, str] | None:
    """The ``(user, password)`` pair of the environment, ``None`` if neither is set."""
    user, password = environ.get(USER_ENV), environ.get(PASSWORD_ENV)
    if not (user or password):
        return None
    if not (user and password):
        raise UsageError(f"{USER_ENV} and {PASSWORD_ENV} are set together or not at all")
    if "," in user or "," in password:
        raise UsageError(f"{USER_ENV} and {PASSWORD_ENV} must not contain a comma: Trivy splits them on it")
    return user, password


def login(ref: str | None, registry: str | None) -> tuple[str, str] | None:
    """``(user, password)`` for an image of ``registry``, else ``None`` (anonymous)."""
    check_registry(registry)
    if not (ref and registry and ref.split("/", 1)[0] == registry):
        return None
    return check_credentials()
