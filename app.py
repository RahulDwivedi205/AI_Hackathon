"""
SENTINEL AI — Autonomous Repo-Aware Security Swarm
Production-grade Streamlit dashboard
"""

import logging
import os
import time
from typing import Dict, List

from dotenv import load_dotenv
load_dotenv()  # must run before any os.getenv checks

import streamlit as st

from utils.demo_code import DEMO_SAMPLES
from utils.github_fetch import fetch_code_from_url

logging.basicConfig(level=logging.INFO)

# ── Startup: fail fast if API key is missing ───────────────────────────────────
if not os.getenv("GROQ_API_KEY"):
    st.set_page_config(page_title="SENTINEL AI", page_icon="🛡", layout="wide")
    st.error(
        "**GROQ_API_KEY is not set.**\n\n"
        "Create a `.env` file in the project root with:\n"
        "```\nGROQ_API_KEY=your_key_here\n```\n"
        "Then restart the app."
    )
    st.stop()

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SENTINEL AI",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── CSS ────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* ── Base ── */
html, body,
[data-testid="stAppViewContainer"],
[data-testid="stMain"] {
    background: #0f1117 !important;
    color: #e2e8f0 !important;
}
[data-testid="stSidebar"] { background: #0a0d14 !important; }
#MainMenu, footer { visibility: hidden; }
section[data-testid="stMain"] > div { padding-top: 0.5rem; }

/* ── Neon header ── */
.sentinel-title {
    font-size: 2.8rem;
    font-weight: 900;
    letter-spacing: 0.06em;
    text-align: center;
    background: linear-gradient(90deg, #00d4ff 0%, #a855f7 50%, #00d4ff 100%);
    background-size: 200% auto;
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    animation: shimmer 3s linear infinite;
}
@keyframes shimmer { to { background-position: 200% center; } }
.sentinel-sub {
    text-align: center;
    color: #4a9eff;
    font-size: 0.78rem;
    letter-spacing: 0.28em;
    text-transform: uppercase;
    margin-bottom: 1.6rem;
}

/* ── Pipeline stepper ── */
.stepper {
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 0;
    margin: 1.2rem 0 1.8rem;
}
.step {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 6px;
    min-width: 110px;
}
.step-circle {
    width: 44px; height: 44px;
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.1rem;
    border: 2px solid #1e3a5f;
    background: #0d1117;
    color: #4a9eff;
    transition: all 0.4s ease;
}
.step-circle.active  { border-color: #00d4ff; box-shadow: 0 0 14px #00d4ff88; background: #0d2233; color: #00d4ff; }
.step-circle.success { border-color: #4ade80; box-shadow: 0 0 14px #4ade8066; background: #0d2218; color: #4ade80; }
.step-circle.failed  { border-color: #f87171; box-shadow: 0 0 14px #f8717166; background: #2d0d0d; color: #f87171; }
.step-label { font-size: 0.72rem; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; color: #64748b; }
.step-label.active  { color: #00d4ff; }
.step-label.success { color: #4ade80; }
.step-label.failed  { color: #f87171; }
.step-connector { width: 60px; height: 2px; background: #1e3a5f; margin-bottom: 20px; }
.step-connector.done { background: linear-gradient(90deg, #4ade80, #00d4ff); }

/* ── Terminal ── */
.terminal {
    background: #070a10;
    border: 1px solid #1e3a5f;
    border-radius: 10px;
    padding: 1rem 1.2rem;
    font-family: 'JetBrains Mono', 'Courier New', monospace;
    font-size: 0.8rem;
    line-height: 1.8;
    max-height: 420px;
    overflow-y: auto;
}
.terminal::-webkit-scrollbar { width: 4px; }
.terminal::-webkit-scrollbar-track { background: #0a0d14; }
.terminal::-webkit-scrollbar-thumb { background: #1e3a5f; border-radius: 2px; }

/* ── Cards ── */
.glass-card {
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(100,180,255,0.12);
    border-radius: 14px;
    padding: 1.2rem 1.4rem;
    margin-bottom: 1rem;
}
.card-label {
    font-size: 0.7rem;
    font-weight: 800;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    color: #4a9eff;
    margin-bottom: 0.7rem;
    display: flex;
    align-items: center;
    gap: 8px;
}

/* ── Risk bar ── */
.bar-wrap { background: #1e293b; border-radius: 999px; height: 8px; margin: 6px 0 4px; }
.bar-fill  { height: 8px; border-radius: 999px; transition: width 0.8s ease; }

/* ── Exploit result boxes ── */
.exploit-box {
    background: #1a0a0a;
    border: 1px solid #7f1d1d;
    border-radius: 8px;
    padding: 0.8rem 1rem;
    font-family: 'Courier New', monospace;
    font-size: 0.82rem;
    color: #fca5a5;
    white-space: pre-wrap;
    word-break: break-word;
}
.blocked-box {
    background: #0a1a0a;
    border: 1px solid #14532d;
    border-radius: 8px;
    padding: 0.8rem 1rem;
    font-family: 'Courier New', monospace;
    font-size: 0.82rem;
    color: #86efac;
    white-space: pre-wrap;
    word-break: break-word;
}

/* ── Status badge ── */
.status-secure {
    display: inline-flex; align-items: center; gap: 10px;
    background: #052e16; border: 1px solid #16a34a;
    border-radius: 10px; padding: 10px 20px;
    color: #4ade80; font-size: 1.3rem; font-weight: 900;
    box-shadow: 0 0 20px #4ade8033;
}
.status-vuln {
    display: inline-flex; align-items: center; gap: 10px;
    background: #2d0d0d; border: 1px solid #dc2626;
    border-radius: 10px; padding: 10px 20px;
    color: #f87171; font-size: 1.3rem; font-weight: 900;
    box-shadow: 0 0 20px #f8717133;
}

/* ── Demo button ── */
div[data-testid="stButton"] button[kind="secondary"] {
    background: linear-gradient(135deg, #7c3aed22, #0ea5e922) !important;
    border: 1px solid #7c3aed88 !important;
    color: #c084fc !important;
    font-weight: 700 !important;
}
</style>
""", unsafe_allow_html=True)

# ── SVG Icons ──────────────────────────────────────────────────────────────────
def svg(path_d, color="#4a9eff", size=18, extra=""):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" '
            f'viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="2" '
            f'stroke-linecap="round" stroke-linejoin="round" {extra}>{path_d}</svg>')

ICON = {
    "shield":  svg('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>', "#00d4ff", 30),
    "zap":     svg('<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>', "#facc15"),
    "radio":   svg('<circle cx="12" cy="12" r="2"/><path d="M4.93 4.93a10 10 0 0 0 0 14.14"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14"/><path d="M7.76 7.76a6 6 0 0 0 0 8.49"/><path d="M16.24 7.76a6 6 0 0 1 0 8.49"/>', "#4a9eff"),
    "bug":     svg('<rect x="8" y="6" width="8" height="14" rx="4"/><path d="M19 7l-3 2"/><path d="M5 7l3 2"/><path d="M19 12h-4"/><path d="M5 12h4"/><path d="M19 17l-3-2"/><path d="M5 17l3-2"/>', "#f87171"),
    "skull":   svg('<path d="M12 2a9 9 0 0 1 9 9c0 3.18-1.65 5.97-4.13 7.6L16 21H8l-.87-2.4A9 9 0 0 1 3 11a9 9 0 0 1 9-9z"/><line x1="9" y1="17" x2="9" y2="21"/><line x1="15" y1="17" x2="15" y2="21"/><circle cx="9" cy="11" r="1"/><circle cx="15" cy="11" r="1"/>', "#f87171"),
    "wrench":  svg('<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>', "#4d9eff"),
    "eye":     svg('<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>', "#c084fc"),
    "flag":    svg('<path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/>', "#4ade80"),
    "check":   svg('<polyline points="20 6 9 17 4 12"/>', "#4ade80", 20),
    "x":       svg('<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>', "#f87171", 20),
    "play":    svg('<polygon points="5 3 19 12 5 21 5 3"/>', "#4ade80"),
    "lock":    svg('<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>', "#4ade80"),
    "unlock":  svg('<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/>', "#f87171"),
    "link":    svg('<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>', "#94a3b8", 16),
    "cpu":     svg('<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/>', "#a855f7"),
}

def card_label(icon_key, text):
    return f'<div class="card-label">{ICON[icon_key]}<span>{text}</span></div>'

# ── Session state ──────────────────────────────────────────────────────────────
DEFAULTS = {
    "result": None, "logs": [],
    "phases": {"detecting": "idle", "exploiting": "idle", "fixing": "idle", "validating": "idle"},
    "running": False,
    "last_github_url": "",
}
for k, v in DEFAULTS.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ── Header ─────────────────────────────────────────────────────────────────────
st.markdown(
    f'<div style="display:flex;justify-content:center;align-items:center;gap:16px;padding-top:0.5rem;">'
    f'{ICON["shield"]}'
    f'<span class="sentinel-title">SENTINEL AI</span>'
    f'{ICON["shield"]}'
    f'</div>'
    f'<div class="sentinel-sub">Autonomous Repo-Aware Security Swarm</div>',
    unsafe_allow_html=True,
)

# ── Pipeline Stepper ───────────────────────────────────────────────────────────
PHASE_ICONS = {
    "detecting":  ("M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z", "#4a9eff"),
    "exploiting": ('<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>', "#f87171"),
    "fixing":     ('<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>', "#4d9eff"),
    "validating": ('<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>', "#c084fc"),
}
PHASE_LABELS = {"detecting": "Detect", "exploiting": "Exploit", "fixing": "Fix", "validating": "Validate"}

def render_stepper(phases):
    keys = list(PHASE_LABELS.keys())
    html = '<div class="stepper">'
    for i, key in enumerate(keys):
        status = phases.get(key, "idle")
        cls = status if status != "idle" else ""
        icon_path, _ = PHASE_ICONS[key]
        icon_color = "#4ade80" if status == "success" else "#f87171" if status == "failed" else "#00d4ff" if status == "running" else "#4a9eff"
        icon_svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" '
                    f'fill="none" stroke="{icon_color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
                    f'{icon_path}</svg>')
        html += (f'<div class="step">'
                 f'<div class="step-circle {cls}">{icon_svg}</div>'
                 f'<div class="step-label {cls}">{PHASE_LABELS[key]}</div>'
                 f'</div>')
        if i < len(keys) - 1:
            done_cls = "done" if phases.get(key) == "success" else ""
            html += f'<div class="step-connector {done_cls}"></div>'
    html += '</div>'
    return html

stepper_box = st.empty()
stepper_box.markdown(render_stepper(st.session_state.phases), unsafe_allow_html=True)

# ── Input section ──────────────────────────────────────────────────────────────
st.markdown(card_label("zap", "Target Input"), unsafe_allow_html=True)

col_input, col_demo = st.columns([3, 1])
with col_input:
    github_url = st.text_input(
        "GitHub Repository URL",
        placeholder="https://github.com/owner/repo",
    )
with col_demo:
    demo_choice = st.selectbox(
        "Demo Sample",
        options=["— select —"] + list(DEMO_SAMPLES.keys()),
        label_visibility="visible",
    )

raw_code = st.text_area(
    "Paste Code",
    placeholder="# Paste Python / JavaScript / TypeScript code here...",
    height=160,
)

col_run, col_demo_btn = st.columns([2, 1])
with col_run:
    run_btn = st.button("Run Analysis", type="primary", use_container_width=True)
with col_demo_btn:
    demo_btn = st.button("Run Demo Mode", type="secondary", use_container_width=True)

st.divider()

# ── Live Agent Feed ────────────────────────────────────────────────────────────
st.markdown(card_label("radio", "Live Agent Feed"), unsafe_allow_html=True)
feed_box = st.empty()

COLOR_MAP = {
    "red": "#ff4d4d", "blue": "#4d9eff", "purple": "#c084fc",
    "cyan": "#22d3ee", "green": "#4ade80", "yellow": "#facc15",
    "white": "#94a3b8",
}

def render_feed(logs):
    if not logs:
        feed_box.markdown(
            '<div class="terminal"><span style="color:#1e3a5f">// Waiting for analysis...</span></div>',
            unsafe_allow_html=True,
        )
        return
    lines = ""
    for e in logs:
        c   = COLOR_MAP.get(e.get("color", "white"), "#94a3b8")
        ag  = e.get("agent", "System")
        msg = e.get("message", "").replace("<", "&lt;").replace(">", "&gt;")
        lines += f'<span style="color:{c}">[{ag}]</span> <span style="color:#e2e8f0">{msg}</span><br>'
    feed_box.markdown(f'<div class="terminal">{lines}</div>', unsafe_allow_html=True)

render_feed(st.session_state.logs)

# ── Pipeline runner ────────────────────────────────────────────────────────────
def _update_phases_from_log(log_msg: str) -> None:
    """Drive the stepper state from swarm log messages."""
    p = st.session_state.phases
    if "Analyzing" in log_msg:
        p["detecting"] = "running"
    if "detected" in log_msg or "SAFE" in log_msg or "No vulnerabilities found" in log_msg:
        if p["detecting"] == "running":
            p["detecting"] = "success"
    if "vulnerability finding" in log_msg or "⚠️" in log_msg:
        p["detecting"] = "success"
    if "Generating exploit" in log_msg or "exploit proof" in log_msg.lower():
        p["exploiting"] = "running"
    if "Exploit ready" in log_msg or "exploit proofs" in log_msg.lower():
        p["exploiting"] = "success"
    if "Fixing" in log_msg or "fix and validation" in log_msg.lower():
        p["fixing"] = "running"
    if "Patch generated" in log_msg:
        p["fixing"] = "success"
    if "Validating" in log_msg or "Validat" in log_msg:
        p["validating"] = "running"
    if "→ SECURE" in log_msg or "Swarm execution complete" in log_msg:
        p["validating"] = "success"
    if "STILL VULNERABLE" in log_msg:
        p["validating"] = "failed"


def run_analysis(files_input: List[Dict[str, str]]) -> None:
    st.session_state.logs   = []
    st.session_state.result = None
    st.session_state.phases = {k: "idle" for k in PHASE_LABELS}

    from sentinel_swarm import run_swarm

    with st.spinner("Sentinel Swarm initializing multi-file analysis..."):
        try:
            final_state = run_swarm(files_input)
        except Exception as exc:
            st.error(f"Analysis failed: {exc}")
            logging.exception("run_swarm raised an exception")
            return

    # Stream logs into the UI feed with phase updates
    for log_msg in final_state["logs"]:
        color, agent = "white", "System"
        if "[Agent A" in log_msg:
            color, agent = "red", "Agent A - Hacker"
        elif "[Agent B" in log_msg:
            color, agent = "blue", "Agent B - Engineer"
        elif "[Agent C" in log_msg:
            color, agent = "green", "Agent C - Reviewer"
        elif "[Orchestrator]" in log_msg:
            color, agent = "purple", "Orchestrator"

        _update_phases_from_log(log_msg)

        display_msg = log_msg.split("] ", 1)[-1] if "] " in log_msg else log_msg
        st.session_state.logs.append(
            {"agent": agent, "message": display_msg, "color": color}
        )
        render_feed(st.session_state.logs)
        stepper_box.markdown(
            render_stepper(st.session_state.phases), unsafe_allow_html=True
        )
        time.sleep(0.15)

    # ── Build result dict from all findings ───────────────────────────────────
    findings: List[Dict] = final_state.get("findings", [])

    if findings:
        # Full vulnerability report covering every finding
        report_lines = []
        for f in findings:
            status_icon = "✅" if f.get("validation") == "PASS" else "⚠️"
            report_lines.append(
                f"### {status_icon} {f['type']} in `{f['file_path']}`\n"
                f"- **Severity:** {f['severity']}\n"
                f"- **Explanation:** {f['explanation']}\n"
                f"- **Validation:** {f.get('validation', 'N/A')}\n"
            )
        full_report = "\n".join(report_lines)

        all_pass = all(f.get("validation") == "PASS" for f in findings)

        # Risk score: highest severity drives the score
        severity_scores = {"Critical": 95, "High": 75, "Medium": 50, "Low": 25}
        risk = max(
            severity_scores.get(f.get("severity", "Low"), 25) for f in findings
        )

        # Use the first finding for the primary code/exploit display;
        # show a tab-style summary for multi-file repos in the report.
        primary = findings[0]

        # Aggregate exploit scripts from all findings
        all_scripts = "\n\n".join(
            f"# ── {f['file_path']} ({f['type']}) ──\n{f.get('exploit_script', '# N/A')}"
            for f in findings
        )

        st.session_state.result = {
            "findings": findings,
            "vulnerability_report": full_report,
            "risk_score": risk,
            # Exploit — primary finding
            "exploit_payload": primary.get("exploit_payload", "N/A"),
            "exploit_script": all_scripts,
            "exploit_vulnerable_result": primary.get(
                "exploit_vulnerable_result", "SUCCESS — target exploited"
            ),
            "exploit_patched_result": primary.get(
                "exploit_patched_result",
                "BLOCKED — attack rejected" if all_pass else "SUCCESS — still vulnerable",
            ),
            # Patch — primary finding
            "original_code": primary.get("original_code", ""),
            "patched_code": primary.get("patched_code") or "# Patch generation failed",
            "fix_explanation": primary.get("fix_explanation", ""),
            # Validation
            "reviewer_verdict": "SECURE" if all_pass else "STILL VULNERABLE",
            "reviewer_justification": (
                f"Validated {len(findings)} finding(s) across "
                f"{len({f['file_path'] for f in findings})} file(s). "
                + ("All patches passed adversarial review."
                   if all_pass
                   else f"{sum(1 for f in findings if f.get('validation') != 'PASS')} "
                        f"finding(s) still require attention.")
            ),
            "confidence_score": 95 if all_pass else 30,
            "iterations": final_state.get("attempts", 0),
            "final_status": "Secure" if all_pass else "Not Secure",
        }
    else:
        st.session_state.result = {
            "findings": [],
            "vulnerability_report": "✅ No vulnerabilities detected in the repository.",
            "risk_score": 0,
            "exploit_payload": "N/A",
            "exploit_script": "# No exploits generated",
            "exploit_vulnerable_result": "N/A",
            "exploit_patched_result": "N/A",
            "original_code": "# No vulnerable code found",
            "patched_code": "# No patch needed",
            "fix_explanation": "",
            "reviewer_verdict": "SECURE",
            "reviewer_justification": "All files analyzed and passed safety checks.",
            "confidence_score": 100,
            "iterations": 0,
            "final_status": "Secure",
        }

    # Mark any still-idle phases as success (clean up stepper)
    for phase_key in ("detecting", "exploiting", "fixing", "validating"):
        if st.session_state.phases[phase_key] == "idle":
            st.session_state.phases[phase_key] = "success"
    stepper_box.markdown(
        render_stepper(st.session_state.phases), unsafe_allow_html=True
    )

    st.rerun()

# ── Button handlers ────────────────────────────────────────────────────────────
if run_btn:
    files_input = []
    error_msg  = ""
    if github_url.strip():
        with st.spinner("Fetching entire repository tree..."):
            try:
                files_input = fetch_code_from_url(github_url.strip())
                st.session_state["last_github_url"] = github_url.strip()
            except Exception as e:
                error_msg = str(e)
    elif raw_code.strip():
        files_input = [{"path": "pasted_code.py", "content": raw_code.strip()}]
        st.session_state["last_github_url"] = ""  # not a repo scan
    else:
        error_msg = "Please provide a GitHub URL or paste code to analyze."

    if error_msg:
        st.error(error_msg)
    elif files_input:
        run_analysis(files_input)

if demo_btn:
    sample_key = demo_choice if demo_choice != "— select —" else list(DEMO_SAMPLES.keys())[0]
    st.session_state["last_github_url"] = ""  # demo is not a real repo
    run_analysis([{"path": "demo.py", "content": DEMO_SAMPLES[sample_key]}])

# ── Results ────────────────────────────────────────────────────────────────────
result = st.session_state.result
if not result:
    st.stop()

st.divider()

# ── SECTION 3 — Vulnerability Detection ───────────────────────────────────────
st.markdown(card_label("bug", "Vulnerability Detection"), unsafe_allow_html=True)

risk = result.get("risk_score", 0)
risk_color = "#ef4444" if risk >= 70 else "#f97316" if risk >= 40 else "#22c55e"

c1, c2, c3 = st.columns([1, 1, 3])
c1.metric("Risk Score", f"{risk}/100")
c2.metric("Iterations", result.get("iterations", 0))
with c3:
    st.markdown(
        f'<div style="margin-top:1.5rem;">'
        f'<div class="bar-wrap"><div class="bar-fill" style="width:{risk}%;background:{risk_color};"></div></div>'
        f'<span style="font-size:0.72rem;color:#64748b;">Risk Level</span>'
        f'</div>',
        unsafe_allow_html=True,
    )

with st.expander("Full Vulnerability Report", expanded=True):
    st.markdown(
        f'<div style="white-space:pre-wrap;font-size:0.86rem;color:#cbd5e1;line-height:1.7;">'
        f'{result.get("vulnerability_report","").replace("<","&lt;").replace(">","&gt;")}'
        f'</div>',
        unsafe_allow_html=True,
    )

st.divider()

# ── SECTION 4 — Exploit Output ─────────────────────────────────────────────────
st.markdown(card_label("skull", "Exploit Output"), unsafe_allow_html=True)

col_ep, col_es = st.columns([1, 2])
with col_ep:
    st.markdown(
        f'<div style="margin-bottom:6px;font-size:0.72rem;font-weight:700;letter-spacing:0.15em;color:#f87171;text-transform:uppercase;">Payload Used</div>'
        f'<div class="exploit-box">{result.get("exploit_payload","N/A").replace("<","&lt;")}</div>',
        unsafe_allow_html=True,
    )
with col_es:
    st.markdown(
        f'<div style="margin-bottom:6px;font-size:0.72rem;font-weight:700;letter-spacing:0.15em;color:#f87171;text-transform:uppercase;">Exploit Script</div>',
        unsafe_allow_html=True,
    )
    st.code(result.get("exploit_script", ""), language="python")

col_vr, col_pr = st.columns(2)
with col_vr:
    st.markdown(
        f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">'
        f'{ICON["unlock"]}<span style="color:#f87171;font-weight:700;font-size:0.82rem;">Against Vulnerable Code — EXPLOITED</span></div>'
        f'<div class="exploit-box">{result.get("exploit_vulnerable_result","").replace("<","&lt;").replace(">","&gt;")}</div>',
        unsafe_allow_html=True,
    )
with col_pr:
    st.markdown(
        f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">'
        f'{ICON["lock"]}<span style="color:#4ade80;font-weight:700;font-size:0.82rem;">Against Patched Code — BLOCKED</span></div>'
        f'<div class="blocked-box">{result.get("exploit_patched_result","").replace("<","&lt;").replace(">","&gt;")}</div>',
        unsafe_allow_html=True,
    )

if result.get("exploit_proof"):
    st.info(f"**Proof:** {result['exploit_proof']}")

st.divider()

# ── SECTION 5 — Patch View ─────────────────────────────────────────────────────
st.markdown(card_label("wrench", "Patch Applied"), unsafe_allow_html=True)

findings = result.get("findings", [])

if len(findings) > 1:
    # Multi-finding: show a tab per finding
    tab_labels = [
        f"{f['file_path'].split('/')[-1]} ({f['type']})" for f in findings
    ]
    tabs = st.tabs(tab_labels)
    for tab, f in zip(tabs, findings):
        with tab:
            col_orig, col_fix = st.columns(2)
            with col_orig:
                st.markdown(
                    f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">'
                    f'{ICON["unlock"]}<span style="color:#f87171;font-weight:700;font-size:0.82rem;">'
                    f'Original — Vulnerable</span></div>',
                    unsafe_allow_html=True,
                )
                st.code(f.get("original_code", ""), language="python")
            with col_fix:
                st.markdown(
                    f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">'
                    f'{ICON["lock"]}<span style="color:#4ade80;font-weight:700;font-size:0.82rem;">'
                    f'Patched — Secure</span></div>',
                    unsafe_allow_html=True,
                )
                st.code(
                    f.get("patched_code") or "# Patch generation failed",
                    language="python",
                )
            if f.get("fix_explanation"):
                st.info(f["fix_explanation"])
else:
    # Single finding: original layout
    col_orig, col_fix = st.columns(2)
    with col_orig:
        st.markdown(
            f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">'
            f'{ICON["unlock"]}<span style="color:#f87171;font-weight:700;font-size:0.82rem;">Original — Vulnerable</span></div>',
            unsafe_allow_html=True,
        )
        st.code(result.get("original_code", ""), language="python")

    with col_fix:
        st.markdown(
            f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">'
            f'{ICON["lock"]}<span style="color:#4ade80;font-weight:700;font-size:0.82rem;">Patched — Secure</span></div>',
            unsafe_allow_html=True,
        )
        st.code(result.get("patched_code", ""), language="python")

    if result.get("fix_explanation"):
        st.info(result["fix_explanation"])

st.divider()

# ── SECTION 6 — Reviewer Feedback ─────────────────────────────────────────────
st.markdown(card_label("eye", "Validation Result"), unsafe_allow_html=True)

verdict    = result.get("reviewer_verdict", "STILL VULNERABLE")
confidence = result.get("confidence_score", 0)

col_v, col_c, col_i = st.columns(3)
col_v.metric("Verdict", verdict)
col_c.metric("Fix Confidence", f"{confidence}%")
col_i.metric("Review Iterations", result.get("iterations", 0))

with st.expander("Reviewer Justification", expanded=False):
    st.markdown(
        f'<div style="white-space:pre-wrap;font-size:0.86rem;color:#c084fc;line-height:1.7;">'
        f'{result.get("reviewer_justification","").replace("<","&lt;").replace(">","&gt;")}'
        f'</div>',
        unsafe_allow_html=True,
    )

st.divider()

# ── SECTION 7 — Final Status ───────────────────────────────────────────────────
st.markdown(card_label("flag", "Final Status"), unsafe_allow_html=True)

final     = result.get("final_status", "Not Secure")
is_secure = final == "Secure"

col_s, col_c2, col_r = st.columns(3)

with col_s:
    badge_cls = "status-secure" if is_secure else "status-vuln"
    icon_svg  = ICON["check"] if is_secure else ICON["x"]
    st.markdown(
        f'<div class="{badge_cls}">{icon_svg} {final}</div>',
        unsafe_allow_html=True,
    )

with col_c2:
    st.metric("Fix Confidence", f"{result.get('confidence_score', 0)}%")

with col_r:
    st.metric("Risk Score", f"{result.get('risk_score', 0)}/100")

st.divider()

# ── SECTION 8 — Push Fixes to GitHub ──────────────────────────────────────────
st.markdown(card_label("link", "Push Fixes to GitHub"), unsafe_allow_html=True)

findings_for_push = result.get("findings", [])
passed_findings   = [f for f in findings_for_push if f.get("validation") == "PASS" and f.get("patched_code")]
source_url        = st.session_state.get("last_github_url", "")

if not source_url:
    st.info("ℹ️ Push to GitHub is only available when analysis was run on a GitHub repository URL.")
elif not passed_findings:
    st.warning("⚠️ No validated patches available to push. Re-run analysis on a GitHub repo and ensure fixes pass review.")
else:
    github_token = os.getenv("GITHUB_TOKEN", "")

    col_push_info, col_push_btn = st.columns([3, 1])
    with col_push_info:
        st.markdown(
            f'<div style="font-size:0.85rem;color:#94a3b8;padding-top:0.4rem;">'
            f'Ready to push <b style="color:#4ade80">{len(passed_findings)}</b> validated fix(es) '
            f'to <b style="color:#4a9eff">{source_url}</b> as a new branch + PR.'
            f'</div>',
            unsafe_allow_html=True,
        )
    with col_push_btn:
        push_btn = st.button(
            "🚀 Push & Open PR",
            type="primary",
            use_container_width=True,
            disabled=not github_token,
        )

    if not github_token:
        st.warning("⚠️ `GITHUB_TOKEN` is not set in your `.env` file. Add it to enable pushing.")

    if push_btn and github_token:
        from utils.github_push import push_fixes_to_github
        with st.spinner(f"Pushing {len(passed_findings)} fix(es) to GitHub and opening PR..."):
            push_result = push_fixes_to_github(
                github_url=source_url,
                findings=passed_findings,
                token=github_token,
            )

        if push_result["success"]:
            st.success(
                f"✅ **PR opened successfully!** "
                f"{push_result['files_pushed']} file(s) pushed to branch `{push_result['branch']}`."
            )
            st.markdown(
                f'<a href="{push_result["pr_url"]}" target="_blank" style="'
                f'display:inline-flex;align-items:center;gap:8px;'
                f'background:#052e16;border:1px solid #16a34a;border-radius:8px;'
                f'padding:10px 20px;color:#4ade80;font-weight:700;text-decoration:none;font-size:0.95rem;">'
                f'{ICON["link"]} View Pull Request on GitHub</a>',
                unsafe_allow_html=True,
            )
        else:
            st.error(f"❌ Push failed: {push_result['error']}")
