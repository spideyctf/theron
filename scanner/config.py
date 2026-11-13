"""Small, repository-local configuration for Theron."""

from pathlib import Path, PurePosixPath
from typing import Any, Dict, Optional

import yaml


DEFAULT_CONFIG = {
    "modules": ["ai", "sast", "sca", "agentic"],
    "exclude": [],
    "accepted_fingerprints": [],
    "correlation_enabled": True,
    "analysis_entrypoints": [],
}

MODULES = {"ai", "sast", "sca", "agentic"}


def validate_entrypoints(entries):
    if not isinstance(entries, list):
        raise ValueError('analysis_entrypoints must be a list')
    seen = set()
    for entry in entries:
        if (not isinstance(entry, dict) or not {'file','function','parameter','reason'} <= entry.keys()
                or entry.keys() - {'file','function','parameter','reason','type'}):
            raise ValueError('Each entrypoint requires file, function, parameter and reason')
        path = entry['file']
        if (not isinstance(path,str) or not path.endswith('.py') or '\\' in path or ':' in path
                or PurePosixPath(path).is_absolute() or any(p in {'','.', '..'} for p in path.split('/'))):
            raise ValueError('Entrypoint file must be a relative Python path without traversal')
        if (not isinstance(entry['function'],str) or not all(p.isidentifier() for p in entry['function'].split('.'))
                or not isinstance(entry['parameter'],str) or not entry['parameter'].isidentifier()
                or entry['parameter'] in {'self','cls'}):
            raise ValueError('Entrypoint function and parameter must be Python identifiers')
        if not isinstance(entry['reason'],str) or not entry['reason'].strip() or len(entry['reason'])>2000:
            raise ValueError('Entrypoint reason must be nonempty text of at most 2000 characters')
        if entry.get('type') not in (None,'bs4.element.Tag'):
            raise ValueError('Unsupported entrypoint type')
        key=(path,entry['function'],entry['parameter'])
        if key in seen:
            raise ValueError('Duplicate entrypoint parameter')
        seen.add(key)
    return entries


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
    validate_entrypoints(config['analysis_entrypoints'])
    if type(config['correlation_enabled']) is not bool:
        raise ValueError('correlation_enabled must be a boolean')
    for key in ("exclude", "accepted_fingerprints"):
        if not isinstance(config[key], list) or any(not isinstance(item, str) for item in config[key]):
            raise ValueError(f"{key} must be a list of strings")
    return config
