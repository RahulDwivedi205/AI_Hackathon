"""
Orchestrator — controls the full 4-phase autonomous pipeline:
  Phase 1: Detection   (Context + Hacker)
  Phase 2: Exploit     (Exploit Runner)
  Phase 3: Fix         (Engineer)
  Phase 4: Validation  (Reviewer + re-exploit)
"""

import os
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

from utils.groq_llm import call_llm
from utils.memory import load_memory, save_memory, summarize_memory
from utils.prompts import (
    LEARNING_ROLE, build_learning_prompt,
    CONTEXT_ROLE, build_context_prompt,
)
from utils.exploit_runner import generate_exploit_proof
from agents.hacker import run_hacker
from agents.engineer import run_engineer
from agents.reviewer import run_reviewer

MAX_ITERATIONS = 5
VERDICT_SECURE = "SECURE"


# ── Logging helper ─────────────────────────────────────────────────────────────
def _log(cb, message, color="white", agent="Orchestrator"):
    if cb:
        cb(message, color, agent)


# ── Context Agent ──────────────────────────────────────────────────────────────
def run_context_agent(code: str, log_cb) -> str:
    _log(log_cb, "Analyzing code structure and identifying high-risk areas...", "cyan", "Context")
    summary = call_llm(build_context_prompt(code[:3000]), system_role=CONTEXT_ROLE)
    _log(log_cb, summary[:250] + "...", "cyan", "Context")
    return summary


# ── Learning Agent ─────────────────────────────────────────────────────────────
def run_learning_agent(vuln_report, patched_code, memory_records, log_cb):
    _log(log_cb, "Extracting vulnerability pattern for memory...", "green", "Learning")
    import re
    raw = call_llm(build_learning_prompt(vuln_report, patched_code), system_role=LEARNING_ROLE)
    if raw.startswith("Error calling Groq API:"):
        return memory_records

    def _ex(label, text):
        m = re.search(rf"{re.escape(label)}\s*[:\-]?\s*(.+)", text, re.IGNORECASE)
        return m.group(1).strip() if m else ""

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "vulnerability_type": _ex("VULNERABILITY_TYPE", raw),
        "severity": _ex("SEVERITY", raw),
        "pattern": _ex("PATTERN", raw),
        "fix_strategy": _ex("FIX_STRATEGY", raw),
    }
    updated = memory_records + [record]
    save_memory(updated)
    _log(log_cb, f"Pattern stored: [{record['severity']}] {record['vulnerability_type']}", "green", "Learning")
    return updated


# ── Main Pipeline ──────────────────────────────────────────────────────────────
def run_pipeline(
    code: str,
    log_callback: Optional[Callable[[str, str, str], None]] = None,
    phase_callback: Optional[Callable[[str, str], None]] = None,
) -> Dict:
    """
    4-phase autonomous security pipeline.

    phase_callback(phase_name, status) — "detecting"|"exploiting"|"fixing"|"validating",
                                          "running"|"success"|"failed"
    """
    logs: List[Dict] = []

    def log(msg, color="white", agent="Orchestrator"):
        logs.append({"agent": agent, "message": msg, "color": color})
        _log(log_callback, msg, color, agent)

    def phase(name, status):
        if phase_callback:
            phase_callback(name, status)

    log("SENTINEL AI pipeline initializing...", "white", "Orchestrator")

    # ── Load memory ────────────────────────────────────────────────────────────
    memory_records = load_memory()
    memory_summary = summarize_memory(memory_records)
    if memory_summary:
        log(f"Loaded {len(memory_records)} past pattern(s) from memory.", "green", "Orchestrator")

    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 1 — DETECTION
    # ══════════════════════════════════════════════════════════════════════════
    phase("detecting", "running")
    log("━━━ PHASE 1: DETECTION ━━━", "cyan", "Orchestrator")

    context_summary = run_context_agent(code, log_callback)

    log("Hacker Agent scanning for vulnerabilities...", "red", "Orchestrator")
    hacker_result = run_hacker(code, memory_summary)

    if hacker_result.get("error"):
        phase("detecting", "failed")
        log(f"Detection failed: {hacker_result['raw_output']}", "red", "Hacker")
        return _error_result(code, hacker_result["raw_output"], logs)

    log(f"Vulnerability detected. Risk Score: {hacker_result['risk_score']}/100", "red", "Hacker")
    log(hacker_result["vulnerability_report"][:400] + "...", "red", "Hacker")
    phase("detecting", "success")

    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 2 — EXPLOIT
    # ══════════════════════════════════════════════════════════════════════════
    phase("exploiting", "running")
    log("━━━ PHASE 2: EXPLOIT GENERATION ━━━", "yellow", "Orchestrator")
    log("Writing exploit script...", "yellow", "Hacker")

    exploit_proof = generate_exploit_proof(code, hacker_result["vulnerability_report"])

    log(f"Exploit script generated. Payload: {exploit_proof['payload']}", "yellow", "Hacker")
    log(f"Simulating exploit against vulnerable code...", "yellow", "Hacker")
    log(f"EXPLOIT RESULT: {exploit_proof['vulnerable_result'][:200]}", "red", "Hacker")
    log(f"PROOF: {exploit_proof['proof_of_exploit']}", "yellow", "Hacker")
    phase("exploiting", "success")

    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 3 — FIX (with iteration loop)
    # ══════════════════════════════════════════════════════════════════════════
    phase("fixing", "running")
    log("━━━ PHASE 3: SECURE FIX ━━━", "blue", "Orchestrator")

    # Keep the true original so the UI always shows the real vulnerable code,
    # even after multiple fix iterations.
    true_original_code = code
    current_code = code
    vulnerability_report = hacker_result["vulnerability_report"]
    engineer_result: Dict = {}
    reviewer_result: Dict = {}
    iteration = 0

    while iteration < MAX_ITERATIONS:
        iteration += 1
        log(f"Engineer Agent generating patch (iteration {iteration})...", "blue", "Engineer")

        engineer_result = run_engineer(current_code, vulnerability_report)

        if engineer_result.get("error"):
            log(f"Engineer error: {engineer_result['raw_output']}", "blue", "Engineer")
            phase("fixing", "failed")
            break

        log("Secure patch generated.", "blue", "Engineer")
        log(f"Fix explanation: {engineer_result.get('fix_explanation','')[:200]}", "blue", "Engineer")

        # ── PHASE 4 — VALIDATION ──────────────────────────────────────────────
        if iteration == 1:
            phase("fixing", "success")
            phase("validating", "running")
            log("━━━ PHASE 4: VALIDATION ━━━", "purple", "Orchestrator")

        log(f"Reviewer Agent auditing patch (iteration {iteration})...", "purple", "Reviewer")
        reviewer_result = run_reviewer(
            # Always compare against the true original so the reviewer has full context
            true_original_code,
            engineer_result["patched_code"],
            iteration,
        )

        if reviewer_result.get("error"):
            log(f"Reviewer error: {reviewer_result['raw_output']}", "purple", "Reviewer")
            break

        verdict    = reviewer_result["verdict"]
        confidence = reviewer_result["confidence_score"]
        log(f"Reviewer verdict: {verdict} | Confidence: {confidence}/100", "purple", "Reviewer")

        if verdict == VERDICT_SECURE:
            log("Re-running exploit against patched code...", "purple", "Reviewer")
            log(f"EXPLOIT BLOCKED: {exploit_proof['patched_result'][:200]}", "green", "Reviewer")
            log("Validation PASSED — system is secure.", "green", "Orchestrator")
            phase("validating", "success")
            break

        if iteration < MAX_ITERATIONS:
            log(f"Fix incomplete — retrying (iteration {iteration + 1})...", "yellow", "Orchestrator")
            vulnerability_report = (
                f"Previous report:\n{vulnerability_report}\n\n"
                f"Reviewer feedback (iteration {iteration}):\n{reviewer_result['justification']}"
            )
            # Feed the latest patch as input for the next engineer iteration
            current_code = engineer_result["patched_code"]
        else:
            log(f"Max iterations reached. Marking as Not Secure.", "yellow", "Orchestrator")
            phase("validating", "failed")

    # ── Learning Agent ─────────────────────────────────────────────────────────
    if engineer_result and not engineer_result.get("error"):
        memory_records = run_learning_agent(
            hacker_result["vulnerability_report"],
            engineer_result.get("patched_code", ""),
            memory_records,
            log_callback,
        )

    # ── Final result ───────────────────────────────────────────────────────────
    final_verdict = reviewer_result.get("verdict", "STILL VULNERABLE") if reviewer_result else "STILL VULNERABLE"
    final_status  = "Secure" if final_verdict == VERDICT_SECURE else "Not Secure"
    log(f"Pipeline complete. Final Status: {final_status}", "white", "Orchestrator")

    return {
        "code": code,
        "context_summary": context_summary,
        # Detection
        "vulnerability_report": hacker_result.get("vulnerability_report", ""),
        "risk_score": hacker_result.get("risk_score", 50),
        # Exploit
        "exploit_script": exploit_proof.get("exploit_script", ""),
        "exploit_payload": exploit_proof.get("payload", ""),
        "exploit_vulnerable_result": exploit_proof.get("vulnerable_result", ""),
        "exploit_patched_result": exploit_proof.get("patched_result", ""),
        "exploit_proof": exploit_proof.get("proof_of_exploit", ""),
        # Fix — always show the true original, not a mid-iteration version
        "original_code": true_original_code,
        "patched_code": engineer_result.get("patched_code", code) if engineer_result else code,
        "fix_explanation": engineer_result.get("fix_explanation", "") if engineer_result else "",
        # Validation
        "reviewer_verdict": final_verdict,
        "reviewer_justification": reviewer_result.get("justification", "") if reviewer_result else "",
        "confidence_score": reviewer_result.get("confidence_score", 0) if reviewer_result else 0,
        "iterations": iteration,
        # Meta
        "agent_logs": logs,
        "final_status": final_status,
        "error": False,
    }


def _error_result(code, message, logs):
    return {
        "code": code, "context_summary": "",
        "vulnerability_report": message, "risk_score": 0,
        "exploit_script": "", "exploit_payload": "",
        "exploit_vulnerable_result": "", "exploit_patched_result": "",
        "exploit_proof": "",
        "original_code": code, "patched_code": code, "fix_explanation": "",
        "reviewer_verdict": "STILL VULNERABLE", "reviewer_justification": "",
        "confidence_score": 0, "iterations": 0,
        "agent_logs": logs, "final_status": "Not Secure",
        "error": True, "error_message": message,
    }
