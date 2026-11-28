"""Gentle retries of the network: few attempts, long pauses."""

from __future__ import annotations

import sys
import time

PAUSES = (30, 90)  # seconds before the 2nd and the 3rd attempt


def pause(what: str, attempt: int, error: object) -> None:
    """Say why ``what`` is tried again and wait; ``attempt`` is the one that failed."""
    seconds = PAUSES[attempt - 1]
    print(f"{what}: attempt {attempt} of {len(PAUSES) + 1} failed ({error}), retry in {seconds} s", file=sys.stderr)
    time.sleep(seconds)
