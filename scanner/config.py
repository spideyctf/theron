"""Small, repository-local configuration for Theron."""

from pathlib import Path
from typing import Any, Dict, Optional

import yaml


DEFAULT_CONFIG = {
    "modules": ["ai", "sast", "sca", "agentic"],
    "exclude": [],
    "accepted_fingerprints": [],
}

MODULES = {"ai", "sast", "sca", "agentic"}


def validate_modules(modules):
    if (not isinstance(modules, list) or not modules
            or any(not isinstance(module, str) or module not in MODULES for module in modules)
            or len(set(modules)) != len(modules)):
        raise ValueError("Select one or more unique modules: ai, sast, sca, agentic")
    return modules


def load_config(scan_root: str, config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load theron.yml when present. Invalid config is a user-facing error."""
    path = Path(config_path) if config_path else Path(scan_root) / "theron.yml"
    config = {key: list(value) if isinstance(value, list) else value for key, value in DEFAULT_CONFIG.items()}
    if not path.is_file():
        return config
    try:
        with path.open(encoding="utf-8") as handle:
            loaded = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"Could not read valid YAML from {path}") from exc
    if loaded is None:
        loaded = {}
    if not isinstance(loaded, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    for key in DEFAULT_CONFIG:
        if key in loaded:
            config[key] = loaded[key]
    validate_modules(config["modules"])
    for key in ("exclude", "accepted_fingerprints"):
        if not isinstance(config[key], list) or any(not isinstance(item, str) for item in config[key]):
            raise ValueError(f"{key} must be a list of strings")
    return config
