"""
Hacker Agent — thinks like an attacker to find vulnerabilities.
"""

import re
from typing import Dict
from utils.groq_llm import call_llm
from utils.prompts import HACKER_ROLE, build_hacker_prompt

ERROR_PREFIX = "Error calling Groq API:"


def _parse_risk_score(text: str) -> int:
    """Extract RISK_SCORE from LLM output. Defaults to 50, clamped to [0, 100]."""
    match = re.search(r"RISK_SCORE\s*[:\-]?\s*(\d+)", text, re.IGNORECASE)
    if match:
        score = int(match.group(1))
        return max(0, min(100, score))
    return 50


def run_hacker(code: str, memory_summary: str = "") -> Dict:
    """
    Run the Hacker Agent on the provided code.

    Returns:
        {
            "vulnerability_report": str,
            "risk_score": int,          # 0-100
            "raw_output": str,
            "error": bool
        }
    """
    prompt = build_hacker_prompt(code, memory_summary)
    raw_output = call_llm(prompt, system_role=HACKER_ROLE)

    if raw_output.startswith(ERROR_PREFIX):
        return {
            "vulnerability_report": raw_output,
            "risk_score": 50,
            "raw_output": raw_output,
            "error": True,
        }

    risk_score = _parse_risk_score(raw_output)

    return {
        "vulnerability_report": raw_output,
        "risk_score": risk_score,
        "raw_output": raw_output,
        "error": False,
    }
