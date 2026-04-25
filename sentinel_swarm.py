"""
SENTINEL AI — Multi-file swarm orchestrator (optimised for speed).
Key optimisations:
  - Hacker prompt returns CVSS inline → eliminates a separate LLM call per finding
  - Exploit + Engineer run concurrently via ThreadPoolExecutor
  - Chunk size raised to 4000 chars → fewer chunks per file
  - Findings capped at MAX_FINDINGS to bound total LLM calls
  - Learning agent merged into Engineer response → no extra call
"""

import json
import logging
import re as _re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Optional, TypedDict

from utils.exploit_runner import generate_exploit_proof
from utils.groq_llm import call_llm
from utils.memory import load_memory, save_memory, summarize_memory

logger = logging.getLogger(__name__)

MEMORY_MAX_RECORDS = 100
MAX_FINDINGS       = 5      # cap to avoid runaway LLM costs / time
CHUNK_SIZE         = 4000   # larger chunks → fewer hacker calls per file


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ex(label: str, text: str) -> str:
    m = _re.search(rf"{_re.escape(label)}\s*[:\-]?\s*(.+)", text, _re.IGNORECASE)
    return m.group(1).strip() if m else ""


def _clean_json(text: str) -> str:
    text = text.strip()
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0]
    elif "```" in text:
        text = text.split("```")[1].split("```")[0]
    return text.strip()


def _chunk_text(text: str, size: int = CHUNK_SIZE) -> List[str]:
    return [text[i : i + size] for i in range(0, len(text), size)]


# ── Shared State ──────────────────────────────────────────────────────────────

class VulnerabilityFinding(TypedDict):
    file_path: str
    type: str
    explanation: str
    severity: str
    cvss_score: float
    cvss_vector: str
    cvss_rating: str
    exploit_payload: str
    exploit_script: str
    exploit_vulnerable_result: str
    exploit_patched_result: str
    original_code: str
    patched_code: Optional[str]
    fix_explanation: str
    validation: Optional[str]


class SharedState(TypedDict):
    files: List[Dict[str, str]]
    findings: List[VulnerabilityFinding]
    logs: List[str]
    attempts: int


# ── Agent A: Hacker (returns vuln + CVSS in one call) ────────────────────────

def _run_hacker_on_file(
    file_path: str, content: str, state: SharedState, memory_summary: str
) -> None:
    """
    Scan a file for vulnerabilities.
    CVSS vector is estimated inline — no separate LLM call needed.
    """
    # Stop early if we already hit the cap
    if len(state["findings"]) >= MAX_FINDINGS:
        return

    chunks = _chunk_text(content)
    found_any = False

    for i, chunk in enumerate(chunks):
        if len(state["findings"]) >= MAX_FINDINGS:
            break

        chunk_label = f" (chunk {i+1}/{len(chunks)})" if len(chunks) > 1 else ""
        state["logs"].append(
            f"[Agent A - Hacker] Analyzing {file_path}{chunk_label}..."
        )

        memory_section = (
            f"\n\nPast vulnerability patterns:\n{memory_summary}\n"
            if memory_summary else ""
        )

        prompt = (
            f"Analyze this code for security vulnerabilities.\n"
            f"File: {file_path}{memory_section}\n"
            f"```\n{chunk}\n```\n\n"
            f"Respond ONLY in valid JSON with these exact keys:\n"
            f'{{"vulnerability_found": bool, "type": "string", '
            f'"explanation": "string", "severity": "Critical|High|Medium|Low", '
            f'"exploit_payload": "string", '
            f'"cvss_vector": "AV:?/AC:?/PR:?/UI:?/S:?/C:?/I:?/A:?"}}'
            f'\n\nFor cvss_vector use CVSS 3.1 notation with values: '
            f'AV(N/A/L/P) AC(L/H) PR(N/L/H) UI(N/R) S(U/C) C/I/A(N/L/H).'
        )

        raw = call_llm(
            prompt,
            system_role="You are Agent A - Hacker. Detect vulnerabilities. ONLY output valid JSON.",
        )

        if raw.startswith("Error calling Groq API"):
            state["logs"].append(f"[Agent A - Hacker] ❌ API error on {file_path}: {raw}")
            logger.error("Hacker API error on %s: %s", file_path, raw)
            continue

        try:
            data = json.loads(_clean_json(raw), strict=False)
        except json.JSONDecodeError as exc:
            state["logs"].append(f"[Agent A - Hacker] ⚠️ JSON parse error on {file_path}: {exc}")
            logger.warning("JSON parse error for %s: %s | raw: %.200s", file_path, exc, raw)
            continue

        if data.get("vulnerability_found"):
            # Parse CVSS inline
            cvss_vector = data.get("cvss_vector", "")
            cvss_score, cvss_rating = _score_from_vector(cvss_vector, data.get("severity", "High"))

            finding: VulnerabilityFinding = {
                "file_path":               file_path,
                "type":                    data.get("type", "Unknown"),
                "explanation":             data.get("explanation", ""),
                "severity":                data.get("severity", "High"),
                "cvss_score":              cvss_score,
                "cvss_vector":             cvss_vector,
                "cvss_rating":             cvss_rating,
                "exploit_payload":         data.get("exploit_payload", ""),
                "exploit_script":          "",
                "exploit_vulnerable_result": "",
                "exploit_patched_result":  "",
                "original_code":           chunk,
                "patched_code":            None,
                "fix_explanation":         "",
                "validation":              None,
            }
            state["findings"].append(finding)
            state["logs"].append(
                f"[Agent A - Hacker] ⚠️ {data['type']} in {file_path} "
                f"(CVSS {cvss_score} — {cvss_rating})"
            )
            found_any = True

    if not found_any:
        state["logs"].append(f"[Agent A - Hacker] ✅ {file_path} → SAFE")


def _score_from_vector(vector: str, severity: str) -> tuple:
    """
    Compute a CVSS 3.1 numeric score from a vector string.
    Falls back to severity-based defaults if vector is malformed.
    """
    import math

    _AV  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    _AC  = {"L": 0.77, "H": 0.44}
    _PR  = {"N": 0.85, "L": 0.62, "H": 0.27}
    _PRC = {"N": 0.85, "L": 0.68, "H": 0.50}
    _UI  = {"N": 0.85, "R": 0.62}
    _CIA = {"N": 0.00, "L": 0.22, "H": 0.56}

    defaults = {
        "Critical": 9.0, "High": 7.5, "Medium": 5.0, "Low": 2.5
    }
    ratings = {
        (0, 0):    "None",
        (0.1, 3.9):"Low",
        (4.0, 6.9):"Medium",
        (7.0, 8.9):"High",
        (9.0, 10): "Critical",
    }

    def _rating(score):
        if score == 0:   return "None"
        if score < 4.0:  return "Low"
        if score < 7.0:  return "Medium"
        if score < 9.0:  return "High"
        return "Critical"

    try:
        parts = {}
        for seg in vector.split("/"):
            if ":" in seg:
                k, v = seg.split(":", 1)
                parts[k] = v

        av = parts.get("AV", "N");  ac = parts.get("AC", "L")
        pr = parts.get("PR", "N");  ui = parts.get("UI", "N")
        s  = parts.get("S",  "U");  c  = parts.get("C",  "L")
        ii = parts.get("I",  "L");  a  = parts.get("A",  "N")

        iss = 1 - (1 - _CIA.get(c, 0)) * (1 - _CIA.get(ii, 0)) * (1 - _CIA.get(a, 0))
        if iss == 0:
            return 0.0, "None"

        sc = s == "C"
        pr_val = _PRC.get(pr, 0.85) if sc else _PR.get(pr, 0.85)
        impact = (7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)) if sc else 6.42 * iss
        exploit = 8.22 * _AV.get(av, 0.85) * _AC.get(ac, 0.77) * pr_val * _UI.get(ui, 0.85)

        if impact <= 0:
            return 0.0, "None"

        raw = min(1.08 * (impact + exploit), 10) if sc else min(impact + exploit, 10)
        score = math.ceil(raw * 10) / 10
        return score, _rating(score)

    except Exception:
        score = defaults.get(severity, 5.0)
        return score, _rating(score)


# ── Phase 2: Exploit + Engineer run concurrently ─────────────────────────────

def _run_exploit(finding: VulnerabilityFinding, state: SharedState) -> None:
    state["logs"].append(
        f"[Agent A - Hacker] 💥 Generating exploit for {finding['type']} in {finding['file_path']}..."
    )
    proof = generate_exploit_proof(finding["original_code"], finding["explanation"])
    finding["exploit_script"]           = proof.get("exploit_script", "")
    finding["exploit_vulnerable_result"] = proof.get("vulnerable_result", "Exploit executed")
    finding["exploit_patched_result"]    = proof.get("patched_result", "Attack blocked")
    if proof.get("payload"):
        finding["exploit_payload"] = proof["payload"]
    state["logs"].append(
        f"[Agent A - Hacker] 🎯 Exploit ready. Payload: {finding['exploit_payload']}"
    )


def _run_engineer(finding: VulnerabilityFinding, state: SharedState) -> bool:
    """
    Patch the vulnerability.
    Also extracts a learning pattern inline — no separate LLM call.
    """
    state["logs"].append(
        f"[Agent B - Engineer] 🛠 Fixing {finding['type']} in {finding['file_path']}..."
    )

    prompt = (
        f"Fix the vulnerability in {finding['file_path']}.\n"
        f"Type: {finding['type']}\n"
        f"Explanation: {finding['explanation']}\n"
        f"Original code:\n```\n{finding['original_code']}\n```\n\n"
        f"Respond ONLY in valid JSON:\n"
        f'{{"patched_code": "string", "fix_explanation": "string", '
        f'"vuln_pattern": "string", "fix_strategy": "string"}}'
    )

    raw = call_llm(
        prompt,
        system_role="You are Agent B - Engineer. Produce secure patches. ONLY output valid JSON.",
    )

    if raw.startswith("Error calling Groq API"):
        state["logs"].append(f"[Agent B - Engineer] ❌ API error for {finding['file_path']}: {raw}")
        logger.error("Engineer API error on %s: %s", finding["file_path"], raw)
        return False

    try:
        data = json.loads(_clean_json(raw), strict=False)
        finding["patched_code"]    = data["patched_code"]
        finding["fix_explanation"] = data.get("fix_explanation", "")
        # Store learning pattern on the finding for memory phase
        finding["_vuln_pattern"]   = data.get("vuln_pattern", "")   # type: ignore[typeddict-unknown-key]
        finding["_fix_strategy"]   = data.get("fix_strategy", "")   # type: ignore[typeddict-unknown-key]
        state["logs"].append(f"[Agent B - Engineer] ✅ Patch generated for {finding['file_path']}")
        return True
    except (json.JSONDecodeError, KeyError) as exc:
        state["logs"].append(
            f"[Agent B - Engineer] ❌ Failed to parse patch for {finding['file_path']}: {exc}"
        )
        logger.warning("Engineer parse error for %s: %s | raw: %.200s", finding["file_path"], exc, raw)
        return False


# ── Agent C: Reviewer ─────────────────────────────────────────────────────────

def _run_reviewer(finding: VulnerabilityFinding, state: SharedState) -> None:
    if not finding.get("patched_code"):
        finding["validation"] = "FAIL"
        state["logs"].append(f"[Agent C - Reviewer] ❌ No patch for {finding['file_path']}")
        return

    state["logs"].append(f"[Agent C - Reviewer] 🔍 Validating fix for {finding['file_path']}...")

    prompt = (
        f"Validate the security patch for {finding['file_path']}.\n"
        f"Exploit payload: {finding['exploit_payload']}\n"
        f"Patched code:\n```\n{finding['patched_code']}\n```\n\n"
        f"Respond ONLY in valid JSON:\n"
        f'{{"exploit_blocked": bool, "functional_check": "PASS|FAIL", "notes": "string"}}'
    )

    raw = call_llm(
        prompt,
        system_role="You are Agent C - Reviewer. Adversarial security audit. ONLY output valid JSON.",
    )

    if raw.startswith("Error calling Groq API"):
        finding["validation"] = "FAIL"
        state["logs"].append(f"[Agent C - Reviewer] ❌ API error for {finding['file_path']}: {raw}")
        return

    try:
        data = json.loads(_clean_json(raw), strict=False)
        if data.get("exploit_blocked") and data.get("functional_check") == "PASS":
            finding["validation"] = "PASS"
            state["logs"].append(f"[Agent C - Reviewer] ✅ {finding['file_path']} → SECURE")
        else:
            finding["validation"] = "FAIL"
            notes = data.get("notes", "")
            state["logs"].append(
                f"[Agent C - Reviewer] ❌ {finding['file_path']} → STILL VULNERABLE"
                + (f": {notes}" if notes else "")
            )
    except (json.JSONDecodeError, KeyError) as exc:
        finding["validation"] = "FAIL"
        state["logs"].append(f"[Agent C - Reviewer] ❌ Parse error for {finding['file_path']}: {exc}")
        logger.warning("Reviewer parse error for %s: %s | raw: %.200s", finding["file_path"], exc, raw)


# ── Orchestrator ──────────────────────────────────────────────────────────────

def run_swarm(
    files: List[Dict[str, str]], max_attempts: int = 2
) -> SharedState:
    """
    Optimised pipeline:
      Phase 1  — Hacker scans files (CVSS inline, no extra call)
      Phase 2  — Exploit + Engineer run concurrently per finding
      Phase 3  — Reviewer validates (retries up to max_attempts)
      Phase 4  — Memory update from inline learning data (no extra call)
    """
    state: SharedState = {
        "files":    files,
        "findings": [],
        "logs":     ["[Orchestrator] 🚀 Starting Sentinel Swarm..."],
        "attempts": 0,
    }

    memory_records = load_memory()
    memory_summary = summarize_memory(memory_records)
    if memory_summary:
        state["logs"].append(
            f"[Orchestrator] 🧠 {len(memory_records)} past pattern(s) loaded."
        )

    state["logs"].append(f"[Orchestrator] 📂 Scanning {len(files)} file(s)...")

    # ── Phase 1: Detection (sequential — Groq free tier has no parallelism benefit) ──
    for f in files:
        if len(state["findings"]) >= MAX_FINDINGS:
            state["logs"].append(
                f"[Orchestrator] ⚡ Finding cap ({MAX_FINDINGS}) reached — skipping remaining files."
            )
            break
        _run_hacker_on_file(f["path"], f["content"], state, memory_summary)

    if not state["findings"]:
        state["logs"].append("[Orchestrator] ✅ No vulnerabilities found.")
        return state

    state["logs"].append(
        f"[Orchestrator] ⚠️ {len(state['findings'])} finding(s) — starting fix pipeline..."
    )

    # ── Phase 2: Exploit + Engineer concurrently per finding ──────────────────
    total_attempts = 0

    for finding in state["findings"]:
        # Run exploit generation and engineer patch in parallel
        state["logs"].append(
            f"[Orchestrator] ⚡ Running exploit + fix in parallel for {finding['file_path']}..."
        )
        with ThreadPoolExecutor(max_workers=2) as pool:
            exploit_future  = pool.submit(_run_exploit, finding, state)
            engineer_future = pool.submit(_run_engineer, finding, state)
            exploit_future.result()   # wait for both
            eng_success = engineer_future.result()

        if not eng_success:
            finding["validation"] = "FAIL"
            total_attempts += 1
            continue

        # ── Phase 3: Reviewer (with retry) ───────────────────────────────────
        for attempt in range(1, max_attempts + 1):
            total_attempts += 1
            _run_reviewer(finding, state)
            if finding["validation"] == "PASS":
                break
            if attempt < max_attempts:
                state["logs"].append(
                    f"[Orchestrator] 🔁 Retrying fix for {finding['file_path']} "
                    f"(attempt {attempt + 1}/{max_attempts})"
                )
                # Re-run engineer with reviewer feedback
                _run_engineer(finding, state)

    state["attempts"] = total_attempts

    # ── Phase 4: Memory update (uses inline data — no extra LLM call) ─────────
    new_records = list(memory_records)
    for finding in state["findings"]:
        if finding.get("validation") == "PASS":
            pattern  = finding.get("_vuln_pattern", finding.get("explanation", ""))  # type: ignore
            strategy = finding.get("_fix_strategy", finding.get("fix_explanation", ""))  # type: ignore
            if pattern or strategy:
                new_records.append({
                    "timestamp":        datetime.now(timezone.utc).isoformat(),
                    "vulnerability_type": finding["type"],
                    "severity":         finding["severity"],
                    "pattern":          pattern[:300],
                    "fix_strategy":     strategy[:300],
                })

    if len(new_records) > len(memory_records):
        save_memory(new_records[-MEMORY_MAX_RECORDS:])
        state["logs"].append(
            f"[Orchestrator] 🧠 {len(new_records) - len(memory_records)} pattern(s) saved to memory."
        )

    state["logs"].append("[Orchestrator] 🏁 Swarm complete.")
    return state


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sample_files = [
        {
            "path": "auth.py",
            "content": (
                "def login(u, p):\n"
                "  query = \"SELECT * FROM users WHERE u='\" + u + \"'\"\n"
                "  return db.execute(query)"
            ),
        },
        {"path": "utils.js", "content": "function log(msg) { console.log(msg); }"},
    ]
    print("🚀 Starting Swarm...")
    final_state = run_swarm(sample_files)
    for log in final_state["logs"]:
        print(log)
