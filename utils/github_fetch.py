"""
GitHub repository fetcher with rate-limit handling, caching, and request throttling.
"""

import logging
import os
import re
import time
from typing import Dict, List, Optional, Tuple

import requests

# Streamlit Cloud: pull GITHUB_TOKEN from st.secrets if not in env
try:
    import streamlit as _st
    if "GITHUB_TOKEN" in _st.secrets and not os.getenv("GITHUB_TOKEN"):
        os.environ["GITHUB_TOKEN"] = _st.secrets["GITHUB_TOKEN"]
except Exception:
    pass

logger = logging.getLogger(__name__)

SUPPORTED_EXTENSIONS = (".py", ".js", ".ts", ".java")
IGNORE_DIRS = ("node_modules", "dist", "build", ".git", "__pycache__", "vendor")
MAX_FILES = 20
GITHUB_API_BASE = "https://api.github.com/repos"
# Polite delay between raw-file fetches to avoid secondary rate limits
_FETCH_DELAY_SEC = 0.3

# ── In-memory cache (keyed by repo URL) ──────────────────────────────────────
_REPO_CACHE: Dict[str, List[Dict[str, str]]] = {}


def _get_headers(token: Optional[str] = None) -> Dict[str, str]:
    headers = {"Accept": "application/vnd.github.v3+json"}
    resolved_token = token or os.getenv("GITHUB_TOKEN")
    if resolved_token:
        headers["Authorization"] = f"token {resolved_token}"
    return headers


def _check_rate_limit(headers: Dict[str, str]) -> None:
    """Raise RuntimeError if the GitHub core rate limit is exhausted."""
    try:
        resp = requests.get(
            "https://api.github.com/rate_limit", headers=headers, timeout=5
        )
        if resp.status_code != 200:
            return
        data = resp.json()
        remaining = data["resources"]["core"]["remaining"]
        if remaining < 10:
            logger.warning(
                "GitHub API rate limit nearly exhausted (%d remaining).", remaining
            )
        if remaining == 0:
            reset_time = data["resources"]["core"]["reset"]
            wait_sec = max(0, int(reset_time - time.time()))
            raise RuntimeError(
                f"GitHub API rate limit exceeded. Resets in {wait_sec}s. "
                "Set GITHUB_TOKEN for a higher limit."
            )
    except RuntimeError:
        raise
    except Exception as exc:
        logger.debug("Rate-limit check failed (non-fatal): %s", exc)


def _parse_github_url(url: str) -> Tuple[str, str]:
    url = url.strip().rstrip("/")
    pattern = r"^https?://(?:www\.)?github\.com/([^/]+)/([^/\s]+?)(?:\.git)?(?:/.*)?$"
    match = re.match(pattern, url)
    if not match:
        raise ValueError(f"Invalid GitHub URL: '{url}'")
    return match.group(1), match.group(2)


def _fetch_repo_tree(
    owner: str, repo: str, headers: Dict[str, str]
) -> List[Dict]:
    """Return the recursive file tree, trying main then master branch."""
    for branch in ("main", "master"):
        api_url = (
            f"{GITHUB_API_BASE}/{owner}/{repo}/git/trees/{branch}?recursive=1"
        )
        try:
            resp = requests.get(api_url, headers=headers, timeout=15)
            if resp.status_code == 200:
                return resp.json().get("tree", [])
        except requests.RequestException as exc:
            logger.warning("Tree fetch failed for branch %s: %s", branch, exc)
    return []


def fetch_code_from_url(
    github_url: str, token: Optional[str] = None
) -> List[Dict[str, str]]:
    """
    Fetch up to MAX_FILES supported source files from a public GitHub repo.

    Returns a list of {"path": str, "content": str} dicts.
    Results are cached in-process by URL.
    """
    cache_key = github_url.strip()
    if cache_key in _REPO_CACHE:
        logger.info("Returning cached result for %s", cache_key)
        return _REPO_CACHE[cache_key]

    try:
        owner, repo = _parse_github_url(github_url)
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc

    headers = _get_headers(token)

    try:
        _check_rate_limit(headers)
    except RuntimeError:
        raise

    tree = _fetch_repo_tree(owner, repo, headers)
    if not tree:
        raise RuntimeError(
            f"Could not fetch repository tree for {owner}/{repo}. "
            "The repo may be empty, private, or the URL is incorrect."
        )

    # Collect eligible file paths (respecting MAX_FILES cap)
    files_to_fetch: List[str] = []
    for item in tree:
        if item.get("type") != "blob":
            continue
        path: str = item.get("path", "")
        if not any(path.endswith(ext) for ext in SUPPORTED_EXTENSIONS):
            continue
        if any(ignored in path for ignored in IGNORE_DIRS):
            continue
        files_to_fetch.append(path)
        if len(files_to_fetch) >= MAX_FILES:
            break

    if not files_to_fetch:
        raise RuntimeError(
            f"No supported source files ({', '.join(SUPPORTED_EXTENSIONS)}) "
            f"found in {owner}/{repo}."
        )

    results: List[Dict[str, str]] = []
    for path in files_to_fetch:
        content = _fetch_raw_file(owner, repo, path, headers)
        if content is not None:
            results.append({"path": path, "content": content})
        time.sleep(_FETCH_DELAY_SEC)  # polite throttle

    if not results:
        raise RuntimeError(f"Could not download any files from {owner}/{repo}.")

    _REPO_CACHE[cache_key] = results
    logger.info("Fetched %d file(s) from %s/%s.", len(results), owner, repo)
    return results


def _fetch_raw_file(
    owner: str, repo: str, path: str, headers: Dict[str, str]
) -> Optional[str]:
    """Try main then master branch for a raw file. Returns content or None."""
    for branch in ("main", "master"):
        url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                return resp.text
        except requests.RequestException as exc:
            logger.debug("Raw fetch failed for %s@%s: %s", path, branch, exc)
    logger.warning("Could not fetch %s from %s/%s.", path, owner, repo)
    return None
