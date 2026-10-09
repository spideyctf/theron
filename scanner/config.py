"""Small, repository-local configuration for Theron."""

from pathlib import Path
from typing import Any, Dict, Optional

import yaml


DEFAULT_CONFIG = {
    "modules": ["ai", "sast", "sca", "agentic"],
    "exclude": [],
    "accepted_fingerprints": [],
}


def load_config(scan_root: str, config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load theron.yml when present. Invalid config is a user-facing error."""
    path = Path(config_path) if config_path else Path(scan_root) / "theron.yml"
    config = {key: list(value) if isinstance(value, list) else value for key, value in DEFAULT_CONFIG.items()}
    if not path.is_file():
        return config
    with path.open(encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    for key in DEFAULT_CONFIG:
        if key in loaded:
            config[key] = loaded[key]
    return config
