"""
detector.py
-----------
Heuristic detector for automated brute-force tools (Hydra, Medusa,
custom scripts, etc). A human typing passwords by hand almost never
produces 4+ login attempts within a few seconds; scripted tools do,
consistently. We use that timing signature to flag an attacker EARLY,
even before they hit the normal fail-count thresholds.
"""

from config import THRESHOLDS
import database


def is_automated_tool(ip):
    """
    Returns True if `ip` has fired >= tool_detection_attempts requests
    within the tool_detection_window_sec window (a classic scripted
    brute-force pattern).
    """
    window = THRESHOLDS["tool_detection_window_sec"]
    threshold = THRESHOLDS["tool_detection_attempts"]

    timestamps = database.get_recent_attempt_timestamps(ip, window)
    return len(timestamps) >= threshold
