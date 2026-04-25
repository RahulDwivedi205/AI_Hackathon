"""
SENTINEL AI — Multi-file swarm orchestrator.
Runs Hacker → Engineer → Reviewer per finding, with exploit generation.
"""

import json
import logging
import re as _re
from datetime import datetime, timezone
from typing import Dict, List, Optional, TypedDict

from utils.exploit_runner import generate_exploit_proof
from utils.groq_llm import call_llm
from utils.memory import load_memory, save_memory, summarize_memory

# Cap memory to avoid unbounded growth
MEMORY_MAX_RECORDS = 100


def _ex(label: str, text: str) -> str:
    """Extract a single-line value after a label from LLM text."""
    m = _re.search(rf"{_re.escape(label)}\s*[:\-]?\s*(.+)", text, _re.IGNORECASE)
    return m.group(1).strip() if m else ""

logger = logging.getLogger(__name__)

# ── Shared State ──────────────────────────────────────────────────────────────

class VulnerabilityFinding(TypedDict):
    file_path: str
    type: str
    explanation: str
    severity: str
    exploit_payload: str
    exploit_script: str
    exploit_vulnerable_result: str
    exploit_patched_result: str
    original_code: str
    patched_code: Optional[str]
    fix_explanation: str
    validation: Optional[str]  # "PASS" | "FAIL" | None


class SharedState(TypedDict):
    files: List[Dict[str, str]]
    findings: List[VulnerabilityFinding]
    logs: List[str]
    attempts: int


# ── Helpers ───────────────────────────────────────────────────────────────────

def _clean_json(text: str) -> str:
    text = text.strip()
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0]
    elif "```" in text:
        text = text.split("```")[1].split("```")[0]
    return text.strip()


def _chunk_text(text: str, size: int = 2000) -> List[str]:
    return [text[i : i + size] for i in range(0, len(text), size)]


# ── Agent A: Hacker ───────────────────────────────────────────────────────────

def _run_hacker_on_file(
    file_path: str, content: str, state: SharedState, memory_summary: str
) -> None:
    """Analyze a single file for vulnerabilities (chunked if large)."""
    chunks = _chunk_text(content)
    found_any = False

    for i, chunk in enumerate(chunks):
        chunk_label = f" (chunk {i+1}/{len(chunks)})" if len(chunks) > 1 else ""
        state["logs"].append(
            f"[Agent A - Hacker] Analyzing {file_path}{chunk_label}..."
        )

        memory_section = (
            f"\n\nPast vulnerability patterns for reference:\n{memory_summary}\n"
            if memory_summary
            else ""
        )

        prompt = (
            f"Analyze the following code for security vulnerabilities "
            f"(SQLi, XSS, path traversal, auth bypass, etc.).\n"
            f"File: {file_path}{memory_section}\n"
            f"```\n{chunk}\n```\n\n"
            f"Respond ONLY in valid JSON:\n"
            f'{{"vulnerability_found": bool, "type": "string", '
            f'"explanation": "string", "severity": "Critical|High|Medium|Low", '
            f'"exploit_payload": "string"}}'
        )

        system_role = (
            "You are Agent A - Hacker. Detect vulnerabilities. ONLY output valid JSON."
        )
        raw = call_llm(prompt, system_role=system_role)

        if raw.startswith("Error calling Groq API"):
            state["logs"].append(
                f"[Agent A - Hacker] ❌ API error on {file_path}: {raw}"
            )
            logger.error("Hacker API error on %s: %s", file_path, raw)
            continue

        try:
            data = json.loads(_clean_json(raw), strict=False)
        except json.JSONDecodeError as exc:
            state["logs"].append(
                f"[Agent A - Hacker] ⚠️ JSON parse error on {file_path}: {exc}"
            )
            logger.warning("JSON parse error for %s: %s | raw: %.200s", file_path, exc, raw)
            continue

        if data.get("vulnerability_found"):
            finding: VulnerabilityFinding = {
                "file_path": file_path,
                "type": data.get("type", "Unknown"),
                "explanation": data.get("explanation", ""),
                "severity": data.get("severity", "High"),
                "exploit_payload": data.get("exploit_payload", ""),
                "exploit_script": "",
                "exploit_vulnerable_result": "",
                "exploit_patched_result": "",
                "original_code": chunk,
                "patched_code": None,
                "fix_explanation": "",
                "validation": None,
            }
            state["findings"].append(finding)
            state["logs"].append(
                f"[Agent A - Hacker] ⚠️ {data['type']} detected in {file_path}!"
            )
            found_any = True

    if not found_any:
        state["logs"].append(f"[Agent A - Hacker] ✅ {file_path} → SAFE")


# ── Phase 2: Exploit Generation ───────────────────────────────────────────────

def _run_exploit(finding: VulnerabilityFinding, state: SharedState) -> None:
    """Generate exploit proof for a finding."""
    state["logs"].append(
        f"[Agent A - Hacker] 💥 Generating exploit for {finding['type']} "
        f"in {finding['file_path']}..."
    )
    proof = generate_exploit_proof(finding["original_code"], finding["explanation"])
    finding["exploit_script"] = proof.get("exploit_script", "")
    finding["exploit_vulnerable_result"] = proof.get(
        "vulnerable_result", "Exploit executed — data exfiltrated"
    )
    finding["exploit_patched_result"] = proof.get(
        "patched_result", "Attack blocked"
    )
    if proof.get("payload"):
        finding["exploit_payload"] = proof["payload"]
    state["logs"].append(
        f"[Agent A - Hacker] 🎯 Exploit ready. Payload: {finding['exploit_payload']}"
    )


# ── Agent B: Engineer ─────────────────────────────────────────────────────────

def _run_engineer(finding: VulnerabilityFinding, state: SharedState) -> bool:
    """Patch a vulnerability. Returns True on success."""
    state["logs"].append(
        f"[Agent B - Engineer] 🛠 Fixing {finding['type']} in {finding['file_path']}..."
    )

    prompt = (
        f"Fix the following vulnerability in {finding['file_path']}.\n"
        f"Vulnerability type: {finding['type']}\n"
        f"Explanation: {finding['explanation']}\n"
        f"Original code:\n```\n{finding['original_code']}\n```\n\n"
        f"Respond ONLY in valid JSON:\n"
        f'{{"patched_code": "string", "fix_explanation": "string"}}'
    )

    system_role = (
        "You are Agent B - Engineer. Produce secure patches. ONLY output valid JSON."
    )
    raw = call_llm(prompt, system_role=system_role)

    if raw.startswith("Error calling Groq API"):
        state["logs"].append(
            f"[Agent B - Engineer] ❌ API error for {finding['file_path']}: {raw}"
        )
        logger.error("Engineer API error on %s: %s", finding["file_path"], raw)
        return False

    try:
        data = json.loads(_clean_json(raw), strict=False)
        finding["patched_code"] = data["patched_code"]
        finding["fix_explanation"] = data.get("fix_explanation", "")
        state["logs"].append(
            f"[Agent B - Engineer] ✅ Patch generated for {finding['file_path']}"
        )
        return True
    except (json.JSONDecodeError, KeyError) as exc:
        state["logs"].append(
            f"[Agent B - Engineer] ❌ Failed to parse patch for "
            f"{finding['file_path']}: {exc}"
        )
        logger.warning(
            "Engineer parse error for %s: %s | raw: %.200s",
            finding["file_path"], exc, raw,
        )
        return False


# ── Agent C: Reviewer ─────────────────────────────────────────────────────────

def _run_reviewer(finding: VulnerabilityFinding, state: SharedState) -> None:
    """Validate the patch. Sets finding['validation'] to 'PASS' or 'FAIL'."""
    if not finding.get("patched_code"):
        finding["validation"] = "FAIL"
        state["logs"].append(
            f"[Agent C - Reviewer] ❌ No patch to validate for {finding['file_path']}"
        )
        return

    state["logs"].append(
        f"[Agent C - Reviewer] 🔍 Validating fix for {finding['file_path']}..."
    )

    prompt = (
        f"Validate the security patch for {finding['file_path']}.\n"
        f"Original exploit payload: {finding['exploit_payload']}\n"
        f"Patched code:\n```\n{finding['patched_code']}\n```\n\n"
        f"Respond ONLY in valid JSON:\n"
        f'{{"exploit_blocked": bool, "functional_check": "PASS|FAIL", '
        f'"notes": "string"}}'
    )

    system_role = (
        "You are Agent C - Reviewer. Adversarial security audit. ONLY output valid JSON."
    )
    raw = call_llm(prompt, system_role=system_role)

    if raw.startswith("Error calling Groq API"):
        finding["validation"] = "FAIL"
        state["logs"].append(
            f"[Agent C - Reviewer] ❌ API error for {finding['file_path']}: {raw}"
        )
        logger.error("Reviewer API error on %s: %s", finding["file_path"], raw)
        return

    try:
        data = json.loads(_clean_json(raw), strict=False)
        blocked = data.get("exploit_blocked", False)
        functional = data.get("functional_check", "FAIL")
        if blocked and functional == "PASS":
            finding["validation"] = "PASS"
            state["logs"].append(
                f"[Agent C - Reviewer] ✅ {finding['file_path']} → SECURE"
            )
        else:
            finding["validation"] = "FAIL"
            notes = data.get("notes", "")
            state["logs"].append(
                f"[Agent C - Reviewer] ❌ {finding['file_path']} → STILL VULNERABLE"
                + (f": {notes}" if notes else "")
            )
    except (json.JSONDecodeError, KeyError) as exc:
        finding["validation"] = "FAIL"
        state["logs"].append(
            f"[Agent C - Reviewer] ❌ Parse error for {finding['file_path']}: {exc}"
        )
        logger.warning(
            "Reviewer parse error for %s: %s | raw: %.200s",
            finding["file_path"], exc, raw,
        )


# ── Orchestrator ──────────────────────────────────────────────────────────────

def run_swarm(
    files: List[Dict[str, str]], max_attempts: int = 2
) -> SharedState:
    """
    Full multi-file swarm pipeline:
      1. Hacker scans every file
      2. Exploit generated per finding
      3. Engineer patches each finding
      4. Reviewer validates each patch (retries up to max_attempts)
      5. Learning agent stores patterns to memory
    """
    state: SharedState = {
        "files": files,
        "findings": [],
        "logs": ["[Orchestrator] 🚀 Starting Full Repo Analysis Swarm..."],
        "attempts": 0,
    }

    # Load memory for hacker context
    memory_records = load_memory()
    memory_summary = summarize_memory(memory_records)
    if memory_summary:
        state["logs"].append(
            f"[Orchestrator] 🧠 Loaded {len(memory_records)} past pattern(s) from memory."
        )

    state["logs"].append(f"[Orchestrator] 📂 Analyzing {len(files)} file(s)...")

    # ── Phase 1: Detection ────────────────────────────────────────────────────
    for f in files:
        _run_hacker_on_file(f["path"], f["content"], state, memory_summary)

    if not state["findings"]:
        state["logs"].append(
            "[Orchestrator] ✅ No vulnerabilities found in repository."
        )
        return state

    state["logs"].append(
        f"[Orchestrator] ⚠️ Found {len(state['findings'])} vulnerability finding(s)."
    )

    # ── Phase 2: Exploit Generation ───────────────────────────────────────────
    state["logs"].append("[Orchestrator] 💥 Generating exploit proofs...")
    for finding in state["findings"]:
        _run_exploit(finding, state)

    # ── Phase 3 & 4: Engineer + Reviewer (per finding, with retries) ─────────
    state["logs"].append("[Orchestrator] 🛠 Starting fix and validation phase...")
    total_attempts = 0

    for finding in state["findings"]:
        for attempt in range(1, max_attempts + 1):
            total_attempts += 1
            success = _run_engineer(finding, state)
            if not success:
                break
            _run_reviewer(finding, state)
            if finding["validation"] == "PASS":
                break
            if attempt < max_attempts:
                state["logs"].append(
                    f"[Orchestrator] 🔁 Retrying fix for {finding['file_path']} "
                    f"(attempt {attempt + 1}/{max_attempts})"
                )

    state["attempts"] = total_attempts

    # ── Phase 5: Learning Agent ───────────────────────────────────────────────
    new_records = list(memory_records)
    for finding in state["findings"]:
        if finding.get("validation") == "PASS" and finding.get("patched_code"):
            learn_prompt = (
                f"Extract a reusable security pattern.\n\n"
                f"Vulnerability: {finding['type']}\n"
                f"Explanation: {finding['explanation']}\n"
                f"Fix applied:\n```\n{finding['patched_code']}\n```\n\n"
                f"Respond with:\n"
                f"VULNERABILITY_TYPE: <name>\nSEVERITY: <level>\n"
                f"PATTERN: <1-2 sentences>\nFIX_STRATEGY: <1-2 sentences>"
            )
            raw = call_llm(
                learn_prompt,
                system_role=(
                    "You are a security knowledge distillation agent. "
                    "Extract concise, reusable patterns."
                ),
            )
            if not raw.startswith("Error calling Groq API"):
                new_records.append(
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "vulnerability_type": _ex("VULNERABILITY_TYPE", raw),
                        "severity": _ex("SEVERITY", raw),
                        "pattern": _ex("PATTERN", raw),
                        "fix_strategy": _ex("FIX_STRATEGY", raw),
                    }
                )

    if len(new_records) > len(memory_records):
        # Trim to cap before saving
        trimmed = new_records[-MEMORY_MAX_RECORDS:]
        save_memory(trimmed)
        state["logs"].append(
            f"[Orchestrator] 🧠 Stored {len(new_records) - len(memory_records)} "
            f"new pattern(s) to memory."
        )

    state["logs"].append("[Orchestrator] 🏁 Swarm execution complete.")
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
    print("🚀 Starting Agentic Multi-File Swarm...")
    final_state = run_swarm(sample_files)
    print("\n" + "=" * 50)
    for log in final_state["logs"]:
        print(log)
