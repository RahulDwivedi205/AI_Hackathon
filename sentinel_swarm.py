import json
import time
import re
from typing import List, Dict, Optional, TypedDict
from utils.groq_llm import call_llm

# ── Shared State Definition ───────────────────────────────────────────────────

class VulnerabilityFinding(TypedDict):
    file_path: str
    type: str
    explanation: str
    severity: str
    exploit_payload: str
    original_code: str
    patched_code: Optional[str]
    validation: Optional[str]

class SharedState(TypedDict):
    files: List[Dict[str, str]]  # {path, content}
    findings: List[VulnerabilityFinding]
    logs: List[str]
    attempts: int

# ── Helpers ───────────────────────────────────────────────────────────────────

def clean_json(text: str) -> str:
    text = text.strip()
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0]
    elif "```" in text:
        text = text.split("```")[1].split("```")[0]
    return text.strip()

def chunk_text(text: str, size: int = 2000) -> List[str]:
    """Splits text into chunks of given size."""
    return [text[i:i + size] for i in range(0, len(text), size)]

# ── Agent A: Hacker ───────────────────────────────────────────────────────────

def run_hacker_on_file(file_path: str, content: str, state: SharedState):
    """Analyzes a single file (in chunks if necessary)."""
    chunks = chunk_text(content)
    file_status = "SAFE"
    
    for i, chunk in enumerate(chunks):
        chunk_info = f" (chunk {i+1}/{len(chunks)})" if len(chunks) > 1 else ""
        state["logs"].append(f"[Agent A - Hacker] Analyzing {file_path}{chunk_info}...")
        
        prompt = (
            f"Analyze the following code for security vulnerabilities (SQLi, XSS, etc.).\n"
            f"Code from file: {file_path}\n"
            f"```\n{chunk}\n```\n\n"
            f"Respond ONLY in valid JSON format with keys:\n"
            f"- vulnerability_found: bool\n"
            f"- type: string\n"
            f"- explanation: string\n"
            f"- severity: string (Critical/High/Medium/Low)\n"
            f"- exploit_payload: string"
        )
        
        system_role = "You are Agent A - Hacker. Detect vulnerabilities and generate exploits. ONLY output JSON."
        raw_response = call_llm(prompt, system_role=system_role)
        
        if "Error calling Groq API" in raw_response:
            state["logs"].append(f"[Agent A - Hacker] ❌ API Error on {file_path}")
            continue

        try:
            data = json.loads(clean_json(raw_response), strict=False)
            if data.get("vulnerability_found"):
                finding: VulnerabilityFinding = {
                    "file_path": file_path,
                    "type": data["type"],
                    "explanation": data["explanation"],
                    "severity": data.get("severity", "High"),
                    "exploit_payload": data["exploit_payload"],
                    "original_code": chunk,
                    "patched_code": None,
                    "validation": None
                }
                state["findings"].append(finding)
                state["logs"].append(f"[Agent A - Hacker] ⚠️ {data['type']} detected in {file_path}!")
                file_status = "VULNERABLE"
        except:
            continue

    if file_status == "SAFE":
        state["logs"].append(f"[Agent A - Hacker] {file_path} → SAFE")

# ── Agent B: Engineer ─────────────────────────────────────────────────────────

def run_engineer(finding: VulnerabilityFinding, state: SharedState):
    """Fixes a specific vulnerability finding."""
    state["logs"].append(f"[Agent B - Engineer] Fixing {finding['type']} in {finding['file_path']}...")
    
    prompt = (
        f"Fix the vulnerability in {finding['file_path']}.\n"
        f"Vulnerability: {finding['type']}\n"
        f"Explanation: {finding['explanation']}\n"
        f"Original Code Segment:\n```\n{finding['original_code']}\n```\n\n"
        f"Respond in JSON with keys: patched_code, fix_explanation."
    )
    
    system_role = "You are Agent B - Engineer. Provide secure patches. ONLY output JSON."
    raw_response = call_llm(prompt, system_role=system_role)
    
    try:
        data = json.loads(clean_json(raw_response), strict=False)
        finding["patched_code"] = data["patched_code"]
        state["logs"].append(f"[Agent B - Engineer] 🛠 Patch generated for {finding['file_path']}")
    except:
        state["logs"].append(f"[Agent B - Engineer] ❌ Failed to patch {finding['file_path']}")

# ── Agent C: Reviewer ─────────────────────────────────────────────────────────

def run_reviewer(finding: VulnerabilityFinding, state: SharedState):
    """Validates the patch for a specific finding."""
    if not finding["patched_code"]:
        finding["validation"] = "FAIL"
        return

    state["logs"].append(f"[Agent C - Reviewer] Validating fix for {finding['file_path']}...")
    
    prompt = (
        f"Validate the fix for {finding['file_path']}.\n"
        f"Original Exploit: {finding['exploit_payload']}\n"
        f"Patched Code:\n```\n{finding['patched_code']}\n```\n\n"
        f"Respond in JSON with keys: exploit_blocked (bool), functional_check (string: PASS/FAIL)."
    )
    
    system_role = "You are Agent C - Reviewer. Adversarial audit. ONLY output JSON."
    raw_response = call_llm(prompt, system_role=system_role)
    
    try:
        data = json.loads(clean_json(raw_response), strict=False)
        if data.get("exploit_blocked") and data.get("functional_check") == "PASS":
            finding["validation"] = "PASS"
            state["logs"].append(f"[Agent C - Reviewer] ✅ {finding['file_path']} → SECURE")
        else:
            finding["validation"] = "FAIL"
            state["logs"].append(f"[Agent C - Reviewer] ❌ {finding['file_path']} → STILL VULNERABLE")
    except:
        finding["validation"] = "FAIL"

# ── Orchestrator ──────────────────────────────────────────────────────────────

def run_swarm(files: List[Dict[str, str]], max_attempts: int = 2) -> SharedState:
    state: SharedState = {
        "files": files,
        "findings": [],
        "logs": ["[Orchestrator] Starting Full Repo Analysis Swarm..."],
        "attempts": 0
    }
    
    state["logs"].append(f"[Orchestrator] Analyzing {len(files)} files...")
    
    # 1. Hacker Phase (File by File)
    for f in files:
        run_hacker_on_file(f["path"], f["content"], state)
    
    if not state["findings"]:
        state["logs"].append("[Orchestrator] ✅ No vulnerabilities found in entire repository.")
        return state
    
    state["logs"].append(f"[Orchestrator] Found {len(state['findings'])} potential vulnerabilities.")
    
    # 2. Engineer & Reviewer Phase (per finding)
    for finding in state["findings"]:
        attempt = 0
        while attempt < max_attempts:
            attempt += 1
            run_engineer(finding, state)
            run_reviewer(finding, state)
            if finding["validation"] == "PASS":
                break
            state["logs"].append(f"[Orchestrator] 🔁 Retrying fix for {finding['file_path']} (Attempt {attempt+1})")
            
    state["logs"].append("[Orchestrator] Swarm execution complete.")
    return state

if __name__ == "__main__":
    # Test with a multi-file sample
    sample_files = [
        {"path": "auth.py", "content": "def login(u, p):\n  query = \"SELECT * FROM users WHERE u='\" + u + \"'\"\n  return db.execute(query)"},
        {"path": "utils.js", "content": "function log(msg) { console.log(msg); }"},
        {"path": "LargeFile.java", "content": "public class LargeFile { " + ("// padding\n" * 100) + " }"}
    ]
    
    print("🚀 Starting Agentic Multi-File Swarm...")
    final_state = run_swarm(sample_files)
    
    print("\n" + "="*50)
    print("📜 SWARM LOGS")
    print("="*50)
    for log in final_state["logs"]:
        print(log)
