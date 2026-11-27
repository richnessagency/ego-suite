"""GitHub API client and safe shallow-clone helper for EGO Suite."""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .config import DATA_DIR, ensure_directories

GITHUB_CONFIG_PATH = DATA_DIR / "github_config.json"
REPOS_DIR = DATA_DIR / "repos"


def _read_config() -> dict[str, Any]:
    if not GITHUB_CONFIG_PATH.exists():
        return {}
    try:
        return json.loads(GITHUB_CONFIG_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def get_github_status() -> dict[str, Any]:
    cfg = _read_config()
    if cfg.get("token") and cfg.get("username"):
        return {
            "connected": True,
            "username": cfg["username"],
            "avatar_url": cfg.get("avatar_url", ""),
        }
    return {"connected": False, "username": "", "avatar_url": ""}


def _gh_request(endpoint: str, token: str) -> Any:
    req = urllib.request.Request(
        f"https://api.github.com{endpoint}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "EGO-Suite/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def save_github_token(token: str) -> dict[str, Any]:
    ensure_directories()
    token = token.strip()
    if not token:
        raise ValueError("Token cannot be empty")
    user_info = _gh_request("/user", token)
    payload = {
        "token": token,
        "username": user_info.get("login", ""),
        "avatar_url": user_info.get("avatar_url", ""),
    }
    GITHUB_CONFIG_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.chmod(GITHUB_CONFIG_PATH, 0o600)
    return {
        "connected": True,
        "username": payload["username"],
        "avatar_url": payload["avatar_url"],
    }


def clear_github_token() -> None:
    if GITHUB_CONFIG_PATH.exists():
        GITHUB_CONFIG_PATH.unlink()


def list_user_repos() -> list[dict[str, Any]]:
    cfg = _read_config()
    token = cfg.get("token", "")
    if not token:
        return []
    repos = _gh_request("/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member", token)
    return [
        {
            "full_name": r["full_name"],
            "name": r["name"],
            "private": bool(r.get("private")),
            "default_branch": r.get("default_branch", "main"),
            "language": r.get("language") or "Unknown",
            "updated_at": r.get("updated_at", ""),
        }
        for r in repos
    ]


def clone_repo_for_scan(repo_full_name: str) -> Path:
    """Shallow-clone or refresh a GitHub repository safely without storing PAT in .git/config."""
    ensure_directories()
    REPOS_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = repo_full_name.replace("/", "__").replace("..", "")
    dest = REPOS_DIR / safe_name

    cfg = _read_config()
    token = cfg.get("token", "")
    repo_url = f"https://github.com/{repo_full_name}.git"

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"

    git_args = ["git"]
    if token:
        b64 = base64.b64encode(f"x-access-token:{token}".encode("utf-8")).decode("ascii")
        git_args.extend(["-c", f"http.extraHeader=AUTHORIZATION: basic {b64}"])

    if dest.exists() and (dest / ".git").exists():
        proc = subprocess.run(
            [*git_args, "-C", str(dest), "fetch", "--depth", "1", "origin"],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if proc.returncode == 0:
            subprocess.run(
                ["git", "-C", str(dest), "reset", "--hard", "FETCH_HEAD"],
                capture_output=True,
                check=False,
            )
            return dest
        shutil.rmtree(dest, ignore_errors=True)

    proc = subprocess.run(
        [*git_args, "clone", "--depth", "1", repo_url, str(dest)],
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"GitHub clone failed: {proc.stderr.strip()}")
    return dest

