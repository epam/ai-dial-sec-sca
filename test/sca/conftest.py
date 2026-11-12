"""pytest configuration of the SCA action tests."""

import sys
from pathlib import Path

ACTIONS = Path(__file__).resolve().parents[2] / "actions"

# the actions import the shared package as ``_sca_lib``, which their action.yml put
# on PYTHONPATH (the ``actions`` directory)
sys.path.insert(0, str(ACTIONS))
# the shared rules package, on PYTHONPATH of the actions that use it
sys.path.insert(0, str(ACTIONS / "sca_rules"))
# the action scripts import their sibling modules as they do when they run from
# their action directory
sys.path.insert(0, str(ACTIONS / "sca_query_osv"))
sys.path.insert(0, str(ACTIONS / "sca_resolve_targets"))
sys.path.insert(0, str(ACTIONS / "sca_merge_results"))

import pytest  # noqa: E402

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
