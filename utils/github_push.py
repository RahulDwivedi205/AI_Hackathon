"""
GitHub Push — creates a new branch, commits all patched files, and opens a PR.
Uses the GitHub REST API (no git CLI required).
"""

import base64
import logging
import os
import time
from typing import Dict, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

GITHUB_API_BASE = "https://api.github.com/repos"


def _headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json",
    }


def _get_default_branch(owner: str, repo: str, token: str) -> str:
    """Return the repo's default branch name (main / master / etc.)."""
    resp = requests.get(
        f"{GITHUB_API_BASE}/{owner}/{repo}",
        headers=_headers(token),
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json().get("default_branch", "main")


def _get_branch_sha(owner: str, repo: str, branch: str, token: str) -> str:
    """Return the latest commit SHA on a branch."""
    resp = requests.get(
        f"{GITHUB_API_BASE}/{owner}/{repo}/git/ref/heads/{branch}",
        headers=_headers(token),
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["object"]["sha"]


def _create_branch(
    owner: str, repo: str, new_branch: str, from_sha: str, token: str
) -> None:
    """Create a new branch from a given commit SHA."""
    resp = requests.post(
        f"{GITHUB_API_BASE}/{owner}/{repo}/git/refs",
        headers=_headers(token),
        json={"ref": f"refs/heads/{new_branch}", "sha": from_sha},
        timeout=10,
    )
    resp.raise_for_status()


def _get_file_sha(
    owner: str, repo: str, path: str, branch: str, token: str
) -> Optional[str]:
    """Get the blob SHA of an existing file (needed to update it). Returns None if not found."""
    resp = requests.get(
        f"{GITHUB_API_BASE}/{owner}/{repo}/contents/{path}",
        headers=_headers(token),
        params={"ref": branch},
        timeout=10,
    )
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json().get("sha")


def _commit_file(
    owner: str,
    repo: str,
    path: str,
    content: str,
    branch: str,
    commit_message: str,
    token: str,
    file_sha: Optional[str] = None,
) -> None:
    """Create or update a single file on a branch."""
    encoded = base64.b64encode(content.encode("utf-8")).decode("utf-8")
    payload: Dict = {
        "message": commit_message,
        "content": encoded,
        "branch": branch,
    }
    if file_sha:
        payload["sha"] = file_sha

    resp = requests.put(
        f"{GITHUB_API_BASE}/{owner}/{repo}/contents/{path}",
        headers=_headers(token),
        json=payload,
        timeout=15,
    )
    resp.raise_for_status()


def _create_pull_request(
    owner: str,
    repo: str,
    head_branch: str,
    base_branch: str,
    title: str,
    body: str,
    token: str,
) -> str:
    """Open a PR and return its HTML URL."""
    resp = requests.post(
        f"{GITHUB_API_BASE}/{owner}/{repo}/pulls",
        headers=_headers(token),
        json={
            "title": title,
            "body": body,
            "head": head_branch,
            "base": base_branch,
        },
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()["html_url"]


def push_fixes_to_github(
    github_url: str,
    findings: List[Dict],
    token: Optional[str] = None,
) -> Dict:
    """
    Push all PASS-validated patched files to a new branch and open a PR.

    Args:
        github_url: The original repo URL (e.g. https://github.com/owner/repo)
        findings:   List of VulnerabilityFinding dicts from the swarm
        token:      GitHub personal access token (falls back to GITHUB_TOKEN env var)

    Returns:
        {
            "success": bool,
            "pr_url": str,        # URL of the opened PR (on success)
            "branch": str,        # name of the created branch
            "files_pushed": int,  # number of files committed
            "error": str,         # error message (on failure)
        }
    """
    resolved_token = token or os.getenv("GITHUB_TOKEN")
    if not resolved_token:
        return {
            "success": False,
            "pr_url": "",
            "branch": "",
            "files_pushed": 0,
            "error": "GITHUB_TOKEN is not set. Add it to your .env file.",
        }

    # Parse owner/repo from URL
    import re
    match = re.match(
        r"^https?://(?:www\.)?github\.com/([^/]+)/([^/\s]+?)(?:\.git)?(?:/.*)?$",
        github_url.strip().rstrip("/"),
    )
    if not match:
        return {
            "success": False,
            "pr_url": "",
            "branch": "",
            "files_pushed": 0,
            "error": f"Could not parse GitHub URL: {github_url}",
        }

    owner, repo = match.group(1), match.group(2)

    # Only push findings that passed validation and have a patch
    patchable = [
        f for f in findings
        if f.get("validation") == "PASS" and f.get("patched_code")
    ]

    if not patchable:
        return {
            "success": False,
            "pr_url": "",
            "branch": "",
            "files_pushed": 0,
            "error": "No validated patches to push. Run analysis first and ensure fixes pass review.",
        }

    try:
        # Get default branch and its latest SHA
        default_branch = _get_default_branch(owner, repo, resolved_token)
        base_sha = _get_branch_sha(owner, repo, default_branch, resolved_token)

        # Create a new branch: sentinel-ai/fix-<timestamp>
        timestamp = int(time.time())
        new_branch = f"sentinel-ai/security-fixes-{timestamp}"
        _create_branch(owner, repo, new_branch, base_sha, resolved_token)
        logger.info("Created branch %s", new_branch)

        # Commit each patched file
        files_pushed = 0
        pr_body_lines = [
            "## 🛡 SENTINEL AI — Automated Security Fixes\n",
            "This PR was automatically generated by [SENTINEL AI](https://github.com/RahulDwivedi205/AI_Hackathon).\n",
            "### Fixes Applied\n",
        ]

        for finding in patchable:
            file_path = finding["file_path"]
            patched_code = finding["patched_code"]
            vuln_type = finding.get("type", "Unknown")
            severity = finding.get("severity", "Unknown")
            explanation = finding.get("fix_explanation") or finding.get("explanation", "")

            # Get existing file SHA (required for updates)
            file_sha = _get_file_sha(owner, repo, file_path, new_branch, resolved_token)

            commit_msg = f"fix({file_path}): patch {vuln_type} [{severity}] via SENTINEL AI"
            _commit_file(
                owner, repo, file_path, patched_code,
                new_branch, commit_msg, resolved_token, file_sha,
            )
            files_pushed += 1
            logger.info("Committed fix for %s", file_path)

            pr_body_lines.append(
                f"#### `{file_path}`\n"
                f"- **Vulnerability:** {vuln_type}\n"
                f"- **Severity:** {severity}\n"
                f"- **Fix:** {explanation[:300]}\n"
            )

            time.sleep(0.3)  # polite throttle

        # Open the PR
        pr_title = f"🛡 SENTINEL AI: {files_pushed} security fix(es)"
        pr_body = "\n".join(pr_body_lines)
        pr_url = _create_pull_request(
            owner, repo,
            head_branch=new_branch,
            base_branch=default_branch,
            title=pr_title,
            body=pr_body,
            token=resolved_token,
        )
        logger.info("PR opened: %s", pr_url)

        return {
            "success": True,
            "pr_url": pr_url,
            "branch": new_branch,
            "files_pushed": files_pushed,
            "error": "",
        }

    except requests.HTTPError as exc:
        msg = f"GitHub API error: {exc.response.status_code} — {exc.response.text[:300]}"
        logger.error(msg)
        return {"success": False, "pr_url": "", "branch": "", "files_pushed": 0, "error": msg}
    except Exception as exc:
        logger.exception("Unexpected error during push")
        return {"success": False, "pr_url": "", "branch": "", "files_pushed": 0, "error": str(exc)}
