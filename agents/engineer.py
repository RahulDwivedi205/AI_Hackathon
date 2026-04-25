"""
Engineer Agent — generates secure patches for identified vulnerabilities.
"""

import re
from typing import Dict
from utils.groq_llm import call_llm
from utils.prompts import ENGINEER_ROLE, build_engineer_prompt

ERROR_PREFIX = "Error calling Groq API:"


def _extract_code_block(text: str, label: str) -> str:
    """
    Extract code between a labeled section and the next code fence.
    Falls back to the full text if parsing fails.
    """
    # Try to find labeled section like "PATCHED CODE:" followed by ```...```
    pattern = rf"{re.escape(label)}\s*\n```[^\n]*\n(.*?)```"
    match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1).strip()

    # Fallback: return the full raw output
    return text.strip()


def run_engineer(code: str, vulnerability_report: str) -> Dict:
    """
    Run the Engineer Agent to produce a secure patch.

    Returns:
        {
            "original_code": str,   # equals input code
            "patched_code": str,
            "fix_explanation": str,
            "raw_output": str,
            "error": bool
        }
    """
    prompt = build_engineer_prompt(code, vulnerability_report)
    raw_output = call_llm(prompt, system_role=ENGINEER_ROLE)

    if raw_output.startswith(ERROR_PREFIX):
        return {
            "original_code": code,
            "patched_code": code,
            "fix_explanation": raw_output,
            "raw_output": raw_output,
            "error": True,
        }

    patched_code = _extract_code_block(raw_output, "PATCHED CODE:")
    if patched_code == raw_output:
        # Try generic code block extraction as fallback
        blocks = re.findall(r"```[^\n]*\n(.*?)```", raw_output, re.DOTALL)
        if len(blocks) >= 2:
            patched_code = blocks[-1].strip()
        elif len(blocks) == 1:
            patched_code = blocks[0].strip()

    # Extract fix explanation
    explanation_match = re.search(
        r"FIX EXPLANATION:\s*(.*?)(?:$|\n\n)", raw_output, re.DOTALL | re.IGNORECASE
    )
    fix_explanation = explanation_match.group(1).strip() if explanation_match else ""

    return {
        "original_code": code,
        "patched_code": patched_code,
        "fix_explanation": fix_explanation,
        "raw_output": raw_output,
        "error": False,
    }
