"""Utility helpers for file filtering and text processing."""

import os
import re
import fnmatch
from typing import Set

DEFAULT_SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "dist",
    "build", ".next", "vendor", ".idea", ".vscode", "target",
    "coverage", ".cache", ".pytest_cache", ".mypy_cache", ".benchmark-cache",
}

SECURITY_RELEVANT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".yaml", ".yml", ".json",
    ".toml", ".env", ".cfg", ".ini", ".txt", ".md", ".xml", ".sh",
}

SECURITY_RELEVANT_BASENAMES = {
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "requirements.txt", "package.json", "pyproject.toml", "go.mod",
    "Pipfile", "Pipfile.lock", "SKILL.md", "AGENTS.md", "AGENT.md", "CLAUDE.md",
    "GUMMIE.md", "INSTRUCTIONS.md",
}


def should_scan_file(file_path: str, skip_dirs: Set[str] = None) -> bool:
    if skip_dirs is None:
        skip_dirs = DEFAULT_SKIP_DIRS
    for skip in skip_dirs:
        if skip in file_path.replace("\\", "/").split("/"):
            return False
    basename = file_path.replace("\\", "/").rsplit("/", 1)[-1]
    ext = "." + basename.rsplit(".", 1)[-1] if "." in basename else ""
    if ext in SECURITY_RELEVANT_EXTENSIONS:
        return True
    if basename in SECURITY_RELEVANT_BASENAMES:
        return True
    if basename.startswith("Dockerfile"):
        return True
    if basename == ".env" or basename.startswith(".env."):
        return True
    return False


def is_excluded(file_path: str, patterns) -> bool:
    """Exclude paths before reading or sending their dependency names to OSV."""
    path = file_path.replace("\\", "/")
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns or [])


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


def redact_secrets(text: str) -> str:
    """Mask credential-shaped values even in evidence for a different rule."""
    text = re.sub(r"(?:sk-(?:proj-|ant-)?[\w-]{20,}|gh[pors]_[\w]{30,}|hf_[\w]{30,}|AIza[\w-]{35}|AKIA[A-Z0-9]{16}|xox[baprs]-[\w-]{10,})", "[REDACTED]", text)
    return re.sub(r'''(?i)((?:[\w-]*(?:key|token|secret|password|credential)[\w-]*)["']?\s*[:=]\s*["'])([^"'\n]+)(["'])''', r"\1[REDACTED]\3", text)
