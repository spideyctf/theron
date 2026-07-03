"""
GitHub API client for fetching repository contents, metadata, and creating issues.
"""

import base64
import os
import requests
from typing import Optional


class GitHubClient:
    """Lightweight GitHub API client using a Personal Access Token."""

    API_BASE = "https://api.github.com"

    def __init__(self, token: Optional[str] = None):
        self.token = token or os.environ.get("GITHUB_TOKEN")
        if not self.token:
            raise ValueError(
                "GitHub token required. Set GITHUB_TOKEN env var or pass token=."
            )
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "ai-sec-scanner",
        })

    def _get(self, endpoint: str, params: dict = None) -> dict:
        url = f"{self.API_BASE}{endpoint}"
        resp = self.session.get(url, params=params)
        if resp.status_code == 403 and "rate limit" in resp.text.lower():
            raise RuntimeError("GitHub API rate limit exceeded. Wait and retry.")
        resp.raise_for_status()
        return resp.json()

    def _get_raw(self, url: str) -> str:
        resp = self.session.get(url)
        resp.raise_for_status()
        return resp.text

    def list_user_repos(self, username: str) -> list:
        repos = []
        page = 1
        while True:
            data = self._get(f"/users/{username}/repos", params={"per_page": 100, "page": page})
            if not data:
                break
            repos.extend(data)
            page += 1
        return repos

    def list_org_repos(self, org: str) -> list:
        repos = []
        page = 1
        while True:
            data = self._get(f"/orgs/{org}/repos", params={"per_page": 100, "page": page, "type": "all"})
            if not data:
                break
            repos.extend(data)
            page += 1
        return repos

    def list_my_repos(self) -> list:
        repos = []
        page = 1
        while True:
            data = self._get("/user/repos", params={"per_page": 100, "page": page, "affiliation": "owner"})
            if not data:
                break
            repos.extend(data)
            page += 1
        return repos

    def get_repo_info(self, owner: str, repo: str) -> dict:
        return self._get(f"/repos/{owner}/{repo}")

    def get_default_branch(self, owner: str, repo: str) -> str:
        info = self.get_repo_info(owner, repo)
        return info.get("default_branch", "main")

    def get_tree(self, owner: str, repo: str, branch: str = None) -> list:
        if branch is None:
            branch = self.get_default_branch(owner, repo)
        data = self._get(f"/repos/{owner}/{repo}/git/trees/{branch}?recursive=1")
        return data.get("tree", [])

    def get_file_content(self, owner: str, repo: str, path: str, branch: str = None) -> str:
        if branch is None:
            branch = self.get_default_branch(owner, repo)
        url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
        return self._get_raw(url)

    def create_issue(self, owner: str, repo: str, title: str, body: str, labels: list = None) -> dict:
        payload = {"title": title, "body": body, "labels": labels or ["security", "ai-sec-scanner"]}
        resp = self.session.post(f"{self.API_BASE}/repos/{owner}/{repo}/issues", json=payload)
        resp.raise_for_status()
        return resp.json()

    def get_languages(self, owner: str, repo: str) -> dict:
        return self._get(f"/repos/{owner}/{repo}/languages")
