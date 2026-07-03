"""Utility helpers for file filtering and text processing."""

import os
import re
from typing import Set

DEFAULT_SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "dist",
    "build", ".next", "vendor", ".idea", ".vscode", "target",
    "coverage", ".cache", ".pytest_cache", ".mypy_cache",
}

SECURITY_RELEVANT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".yaml", ".yml", ".json",
    ".toml", ".env", ".cfg", ".ini", ".txt", ".md", ".xml", ".sh",
}

SECURITY_RELEVANT_BASENAMES = {
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "requirements.txt", "package.json", "pyproject.toml", "go.mod",
    "Pipfile", "SKILL.md", "AGENTS.md", "AGENT.md", "CLAUDE.md",
    "GUMMIE.md", "INSTRUCTIONS.md",
}


def should_scan_file(file_path: str, skip_dirs: Set[str] = None) -> bool:
    if skip_dirs is None:
        skip_dirs = DEFAULT_SKIP_DIRS
    for skip in skip_dirs:
        if skip in file_path:
            return False
    basename = os.path.basename(file_path)
    ext = "." + basename.rsplit(".", 1)[-1] if "." in basename else ""
    if ext in SECURITY_RELEVANT_EXTENSIONS:
        return True
    if basename in SECURITY_RELEVANT_BASENAMES:
        return True
    if basename.startswith("Dockerfile"):
        return True
    if basename.startswith(".env"):
        return True
    return False


def is_placeholder_value(value: str) -> bool:
    placeholders = ["your_", "your-", "placeholder", "example", "xxx", "change_me",
                    "insert", "replace", "todo", "fixme", "<", ">"]
    return any(ph in value.lower() for ph in placeholders)


def truncate_string(s: str, max_len: int = 200) -> str:
    if len(s) <= max_len:
        return s
    return s[:max_len - 3] + "..."


def sanitize_for_report(text: str) -> str:
    text = text.replace("\x00", "")
    lines = text.splitlines()
    return "\n".join(truncate_string(line, 500) for line in lines)
