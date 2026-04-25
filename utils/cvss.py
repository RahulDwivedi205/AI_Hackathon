"""
CVSS 3.1 Score Calculator for SENTINEL AI.
Uses the LLM to estimate CVSS vector components, then computes the numeric score.
"""

import logging
import re
from typing import Dict, Optional

from utils.groq_llm import call_llm

logger = logging.getLogger(__name__)

CVSS_ROLE = (
    "You are a certified security analyst specializing in CVSS 3.1 scoring. "
    "Given a vulnerability description, you estimate the CVSS 3.1 base vector components "
    "and output ONLY a valid JSON object. Be precise and conservative."
)

# CVSS 3.1 base metric weights
_AV  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC  = {"L": 0.77, "H": 0.44}
_PR  = {"N": 0.85, "L": 0.62, "H": 0.27}   # scope unchanged
_PR_C= {"N": 0.85, "L": 0.68, "H": 0.50}   # scope changed
_UI  = {"N": 0.85, "R": 0.62}
_S   = {"U": "unchanged", "C": "changed"}
_C   = {"N": 0.00, "L": 0.22, "H": 0.56}
_I   = {"N": 0.00, "L": 0.22, "H": 0.56}
_A   = {"N": 0.00, "L": 0.22, "H": 0.56}


def _iss(c: float, i: float, a: float) -> float:
    return 1 - (1 - c) * (1 - i) * (1 - a)


def _compute_cvss(av, ac, pr, ui, s, c, i, a) -> float:
    """Compute CVSS 3.1 base score from component letters."""
    try:
        iss = _iss(_C.get(c, 0), _I.get(i, 0), _A.get(a, 0))
        scope_changed = s == "C"
        pr_val = _PR_C.get(pr, 0.85) if scope_changed else _PR.get(pr, 0.85)

        if iss == 0:
            return 0.0

        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss

        exploitability = (
            8.22
            * _AV.get(av, 0.85)
            * _AC.get(ac, 0.77)
            * pr_val
            * _UI.get(ui, 0.85)
        )

        if impact <= 0:
            return 0.0

        if scope_changed:
            raw = min(1.08 * (impact + exploitability), 10)
        else:
            raw = min(impact + exploitability, 10)

        # Round up to 1 decimal
        import math
        return math.ceil(raw * 10) / 10
    except Exception:
        return 0.0


def calculate_cvss(vuln_type: str, explanation: str, severity: str) -> Dict:
    """
    Use LLM to estimate CVSS 3.1 vector for a vulnerability, then compute score.

    Returns:
        {
            "score": float,       # 0.0 – 10.0
            "vector": str,        # e.g. "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
            "rating": str,        # None/Low/Medium/High/Critical
        }
    """
    prompt = (
        f"Estimate the CVSS 3.1 base vector for this vulnerability.\n\n"
        f"Vulnerability Type: {vuln_type}\n"
        f"Severity: {severity}\n"
        f"Description: {explanation[:600]}\n\n"
        f"Respond ONLY in valid JSON with these exact keys and allowed values:\n"
        f'{{"AV": "N|A|L|P", "AC": "L|H", "PR": "N|L|H", '
        f'"UI": "N|R", "S": "U|C", "C": "N|L|H", "I": "N|L|H", "A": "N|L|H"}}'
    )

    raw = call_llm(prompt, system_role=CVSS_ROLE)

    # Defaults based on severity if LLM fails
    defaults = {
        "Critical": {"AV":"N","AC":"L","PR":"N","UI":"N","S":"U","C":"H","I":"H","A":"H"},
        "High":     {"AV":"N","AC":"L","PR":"N","UI":"N","S":"U","C":"H","I":"L","A":"N"},
        "Medium":   {"AV":"N","AC":"L","PR":"L","UI":"R","S":"U","C":"L","I":"L","A":"N"},
        "Low":      {"AV":"L","AC":"H","PR":"L","UI":"R","S":"U","C":"L","I":"N","A":"N"},
    }

    try:
        import json
        # Strip markdown fences
        clean = raw.strip()
        if "```" in clean:
            clean = clean.split("```")[1].split("```")[0]
            if clean.startswith("json"):
                clean = clean[4:]
        data = json.loads(clean.strip())
    except Exception:
        data = defaults.get(severity, defaults["Medium"])
        logger.warning("CVSS LLM parse failed for %s, using defaults", vuln_type)

    av = data.get("AV", "N")
    ac = data.get("AC", "L")
    pr = data.get("PR", "N")
    ui = data.get("UI", "N")
    s  = data.get("S",  "U")
    c  = data.get("C",  "L")
    i  = data.get("I",  "L")
    a  = data.get("A",  "N")

    score = _compute_cvss(av, ac, pr, ui, s, c, i, a)
    vector = f"AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

    if score == 0:
        rating = "None"
    elif score < 4.0:
        rating = "Low"
    elif score < 7.0:
        rating = "Medium"
    elif score < 9.0:
        rating = "High"
    else:
        rating = "Critical"

    return {"score": score, "vector": vector, "rating": rating}
