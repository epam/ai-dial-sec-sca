"""Registry credentials of the scan commands: ``SCA_REGISTRY_USER`` and
``SCA_REGISTRY_PASSWORD``, used only for an image of ``--registry`` (a host)."""

from __future__ import annotations

import os

from .context import UsageError

USER_ENV, PASSWORD_ENV = "SCA_REGISTRY_USER", "SCA_REGISTRY_PASSWORD"


def is_host(value: str) -> bool:
    return "/" not in value and ("." in value or ":" in value or value == "localhost")


def check_registry(registry: str | None) -> None:
    if registry is not None and not is_host(registry):
        raise UsageError(f"--registry must be a host (a dot, a port or localhost), got {registry!r}")


def login(ref: str | None, registry: str | None) -> tuple[str, str] | None:
    """``(user, password)`` for an image of ``registry``, else ``None`` (anonymous)."""
    check_registry(registry)
    user, password = os.environ.get(USER_ENV), os.environ.get(PASSWORD_ENV)
    if not (ref and registry and ref.split("/", 1)[0] == registry and (user or password)):
        return None
    if not (user and password):
        raise UsageError(f"{USER_ENV} and {PASSWORD_ENV} are set together or not at all")
    if "," in user or "," in password:
        raise UsageError(f"{USER_ENV} and {PASSWORD_ENV} must not contain a comma: Trivy splits them on it")
    return user, password
