import time
import os
import re
import requests
from typing import List, Dict, Tuple, Optional

SUPPORTED_EXTENSIONS = (".py", ".js", ".ts", ".java")
IGNORE_DIRS = ("node_modules", "dist", "build", ".git", "__pycache__")
MAX_FILES = 20
GITHUB_API_BASE = "https://api.github.com/repos"

# ── In-Memory Cache ────────────────────────────────────────────────────────────
REPO_CACHE: Dict[str, str] = {}

def get_headers(token: Optional[str] = None) -> Dict[str, str]:
    headers = {"Accept": "application/vnd.github.v3+json"}
    if not token:
        token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"
    return headers

def check_rate_limit(headers: Dict[str, str]):
    """Checks GitHub rate limit and warns if low."""
    try:
        response = requests.get("https://api.github.com/rate_limit", headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            remaining = data["resources"]["core"]["remaining"]
            if remaining < 10:
                print(f"⚠️ WARNING: GitHub API rate limit nearly exceeded ({remaining} remaining).")
            if remaining == 0:
                reset_time = data["resources"]["core"]["reset"]
                wait_sec = max(0, reset_time - time.time())
                raise RuntimeError(f"GitHub API rate limit exceeded. Resets in {int(wait_sec)} seconds.")
    except Exception:
        pass

def parse_github_url(url: str) -> Tuple[str, str]:
    url = url.strip().rstrip("/")
    pattern = r"^https?://(?:www\.)?github\.com/([^/]+)/([^/\s]+?)(?:\.git)?(?:/.*)?$"
    match = re.match(pattern, url)
    if not match:
        raise ValueError(f"Invalid GitHub URL: '{url}'")
    return match.group(1), match.group(2)

def fetch_repo_tree(owner: str, repo: str, token: Optional[str] = None) -> List[Dict]:
    """Fetches the full recursive tree of the repository."""
    headers = get_headers(token)
    check_rate_limit(headers)
    
    for branch in ["main", "master"]:
        api_url = f"{GITHUB_API_BASE}/{owner}/{repo}/git/trees/{branch}?recursive=1"
        response = requests.get(api_url, headers=headers, timeout=15)
        if response.status_code == 200:
            return response.json().get("tree", [])
    return []

def fetch_code_from_url(github_url: str) -> List[Dict[str, str]]:
    """
    Fetches all supported files from the repo and returns a list of {path, content}.
    """
    try:
        owner, repo = parse_github_url(github_url)
        tree = fetch_repo_tree(owner, repo)
        
        if not tree:
            raise RuntimeError(f"Could not fetch repository tree for {owner}/{repo}")

        files_to_fetch = []
        for item in tree:
            if item["type"] == "blob":
                path = item["path"]
                if any(path.endswith(ext) for ext in SUPPORTED_EXTENSIONS):
                    if not any(ignored in path for ignored in IGNORE_DIRS):
                        files_to_fetch.append(path)
            if len(files_to_fetch) >= MAX_FILES:
                break

        results = []
        headers = get_headers()
        for path in files_to_fetch:
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/{path}"
            resp = requests.get(raw_url, headers=headers, timeout=10)
            if resp.status_code != 200:
                raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/master/{path}"
                resp = requests.get(raw_url, headers=headers, timeout=10)
            
            if resp.status_code == 200:
                results.append({"path": path, "content": resp.text})
        
        return results

    except Exception as e:
        if "403" in str(e):
            raise RuntimeError("GitHub API rate limit exceeded. Please set GITHUB_TOKEN.")
        raise RuntimeError(f"Error fetching full repo: {str(e)}")
