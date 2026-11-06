"""pytest configuration of the fix planner tests."""

import sys
from pathlib import Path

ACTIONS = Path(__file__).resolve().parents[2] / "actions"
for name in ("sca_fix_plan", "sca_rules"):
    sys.path.insert(0, str(ACTIONS / name))
