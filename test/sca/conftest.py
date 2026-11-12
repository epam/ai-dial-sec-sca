"""pytest configuration of the SCA tests."""

import pytest

RUN_ENV = {
    "SCA_RUN_HOST": "github.com",
    "SCA_RUN_REPO": "example/caller",
    "SCA_RUN_ID": "42",
    "SCA_RUN_URL": "https://github.com/example/caller/actions/runs/42",
    "SCA_RUN_EVENT": "workflow_dispatch",
    "SCA_RUN_ACTOR": "octocat",
}
OPTIONAL = ("SCA_RUN_ATTEMPT", "SCA_RUN_DEFAULT_BRANCH", "SCA_RUN_ENGINE_REF")


@pytest.fixture
def run_env(monkeypatch):
    """Sets the run context of a command (``SCA_RUN_*``): the defaults, then the
    ``changes`` of a call on top (``None`` unsets a variable).
    """

    def set_env(**changes):
        for name in (*RUN_ENV, *OPTIONAL):
            monkeypatch.delenv(name, raising=False)
        for name, value in {**RUN_ENV, **changes}.items():
            if value is not None:
                monkeypatch.setenv(name, value)

    set_env()
    return set_env
