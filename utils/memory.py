"""
Memory Store helpers for SENTINEL AI.
Persists vulnerability/fix patterns to memory.json across sessions.
"""

import json
import os
import warnings
from typing import List, Dict


MEMORY_PATH = "memory.json"


def load_memory(path: str = MEMORY_PATH) -> List[Dict]:
    """
    Load memory records from disk.
    Creates the file with [] if it does not exist.
    Returns [] on missing file or JSON decode error.
    """
    if not os.path.exists(path):
        try:
            with open(path, "w") as f:
                json.dump([], f)
        except IOError:
            pass
        return []

    try:
        with open(path, "r") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            return []
    except (json.JSONDecodeError, IOError):
        return []


def save_memory(records: List[Dict], path: str = MEMORY_PATH) -> None:
    """
    Write records list to disk as JSON.
    Catches IOError and logs a warning without raising.
    """
    try:
        with open(path, "w") as f:
            json.dump(records, f, indent=2)
    except IOError as e:
        warnings.warn(f"[Memory] Could not save memory to {path}: {e}")


def summarize_memory(records: List[Dict]) -> str:
    """
    Return a short text summary of stored patterns for injection into the Hacker prompt.
    Returns empty string when records is empty.
    """
    if not records:
        return ""

    lines = [f"Found {len(records)} past vulnerability pattern(s) in memory:\n"]
    for i, rec in enumerate(records[-5:], 1):  # show last 5 patterns max
        vuln_type = rec.get("vulnerability_type", "Unknown")
        severity = rec.get("severity", "Unknown")
        pattern = rec.get("pattern", "")
        fix = rec.get("fix_strategy", "")
        lines.append(
            f"{i}. [{severity}] {vuln_type}\n"
            f"   Pattern: {pattern}\n"
            f"   Fix: {fix}"
        )
    return "\n".join(lines)
