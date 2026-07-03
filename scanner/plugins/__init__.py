"""
Scanner plugin system — auto-discovery of scanner plugins.

Each scanner plugin implements the Scanner interface and registers itself
via the @register decorator. The engine discovers all plugins automatically.
"""

import importlib
import pkgutil
from typing import Dict, List, Optional


_REGISTRY: Dict[str, object] = {}


def register(scanner_cls):
    """Decorator to register a scanner plugin."""
    instance = scanner_cls()
    _REGISTRY[instance.name] = instance
    return scanner_cls


def discover_plugins() -> Dict:
    """Auto-discover all scanner plugins in this package."""
    import scanner.plugins as pkg
    for _, module_name, _ in pkgutil.iter_modules(pkg.__path__):
        if module_name == "__init__" or module_name == "base":
            continue
        importlib.import_module(f"scanner.plugins.{module_name}")
    return _REGISTRY


def ensure_plugins_loaded() -> Dict:
    """Ensure plugins are loaded. Reloads if registry is empty."""
    if not _REGISTRY:
        import scanner.plugins as pkg
        for _, module_name, _ in pkgutil.iter_modules(pkg.__path__):
            if module_name == "__init__" or module_name == "base":
                continue
            importlib.reload(importlib.import_module(f"scanner.plugins.{module_name}"))
    return _REGISTRY


def get_scanner(name: str):
    return _REGISTRY.get(name)


def get_all_scanners() -> List:
    return list(_REGISTRY.values())


def clear_registry():
    _REGISTRY.clear()
