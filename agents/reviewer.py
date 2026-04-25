"""
Reviewer Agent — adversarial security auditor that tries to break the patch.
"""

import re
from typing import Dict
from utils.groq_llm import call_llm
from utils.prompts import REVIEWER_ROLE, build_reviewer_prompt

ERROR_PREFIX = "Error calling Groq API:"
VERDICT_SECURE = "SECURE"
VERDICT_VULNERABLE = "STILL VULNERABLE"


def _parse_verdict(text: str) -> str:
    """
    Extract verdict from LLM output.
    Returns exactly "SECURE" or "STILL VULNERABLE".
    Defaults to "STILL VULNERABLE" if ambiguous (conservative).
    """
    # Look for explicit VERDICT: line first
    match = re.search(r"VERDICT\s*[:\-]?\s*(SECURE|STILL VULNERABLE)", text, re.IGNORECASE)
    if match:
        raw = match.group(1).upper().strip()
        if raw == "SECURE":
            return VERDICT_SECURE
        return VERDICT_VULNERABLE

    # Fallback: scan for standalone keywords
    upper = text.upper()
    if "STILL VULNERABLE" in upper:
        return VERDICT_VULNERABLE
    if "SECURE" in upper:
        return VERDICT_SECURE

    return VERDICT_VULNERABLE  # conservative default


def _parse_confidence(text: str) -> int:
    """Extract CONFIDENCE_SCORE from LLM output. Defaults to 50, clamped to [0, 100]."""
    match = re.search(r"CONFIDENCE_SCORE\s*[:\-]?\s*(\d+)", text, re.IGNORECASE)
    if match:
        score = int(match.group(1))
        return max(0, min(100, score))
    return 50


def run_reviewer(original_code: str, patched_code: str, iteration: int = 1) -> Dict:
    """
    Run the Reviewer Agent to audit the patch.

    Returns:
        {
            "verdict": str,           # "SECURE" or "STILL VULNERABLE"
            "justification": str,
            "confidence_score": int,  # 0-100
            "raw_output": str,
            "error": bool
        }
    """
    prompt = build_reviewer_prompt(original_code, patched_code, iteration)
    raw_output = call_llm(prompt, system_role=REVIEWER_ROLE)

    if raw_output.startswith(ERROR_PREFIX):
        return {
            "verdict": VERDICT_VULNERABLE,
            "justification": raw_output,
            "confidence_score": 0,
            "raw_output": raw_output,
            "error": True,
        }

    verdict = _parse_verdict(raw_output)
    confidence_score = _parse_confidence(raw_output)

    # Extract justification (everything after JUSTIFICATION: label)
    just_match = re.search(
        r"JUSTIFICATION\s*[:\-]?\s*(.*?)(?:CONFIDENCE_SCORE|$)",
        raw_output,
        re.DOTALL | re.IGNORECASE,
    )
    justification = just_match.group(1).strip() if just_match else raw_output.strip()

    return {
        "verdict": verdict,
        "justification": justification,
        "confidence_score": confidence_score,
        "raw_output": raw_output,
        "error": False,
    }
