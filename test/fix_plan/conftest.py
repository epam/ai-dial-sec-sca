"""pytest configuration of the fix planner tests."""

import sys
from pathlib import Path

ACTIONS = Path(__file__).resolve().parents[2] / "actions"
for name in ("sca_fix_plan", "sca_rules", "sca_merge_results"):
    sys.path.insert(0, str(ACTIONS / name))
sys.path.insert(0, str(ACTIONS))  # _sca_lib, which the engine imports
