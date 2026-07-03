"""
Rule loader — loads versioned YAML rule files from the rules/ directory.

Rules are organized as:
  rules/
    ai/v1/prompt_injection.yaml
    ai/v1/secret_exposure.yaml
    sast/v1/python.yaml
    ...

Each YAML file defines a rule_set with metadata and a list of rules.
Rules define patterns (regex), severity, CWE, recommendations, and references.
"""

import os
import re
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Optional


@dataclass
class Rule:
    """A single detection rule loaded from YAML."""
    id: str
    title: str
    severity: str
    category: str
    module: str
    pattern: str
    flags: int = 0
    cwe: Optional[str] = None
    confidence: str = "medium"
    description: str = ""
    recommendation: str = ""
    references: List[str] = field(default_factory=list)
    skip_in_comments: bool = False
    skip_if_contains: List[str] = field(default_factory=list)
    severity_overrides: List[dict] = field(default_factory=list)
    language: Optional[str] = None
    file_extensions: List[str] = field(default_factory=list)
    # For structural/JSON rules
    json_path: Optional[str] = None
    condition: Optional[str] = None
    key_match: Optional[str] = None
    value_condition: Optional[str] = None
    value_min_length: int = 0


@dataclass
class RuleSet:
    """A collection of rules from one YAML file."""
    name: str
    version: str
    category: str
    module: str
    description: str = ""
    rules: List[Rule] = field(default_factory=list)
    skip_files: List[str] = field(default_factory=list)
    skip_if_contains: List[str] = field(default_factory=list)
    target_files_exact: List[str] = field(default_factory=list)
    target_files_pattern: List[str] = field(default_factory=list)
    structural_rules: List[dict] = field(default_factory=list)


class RuleLoader:
    """Loads versioned rule files from the rules/ directory."""

    def __init__(self, rules_dir: str = None):
        if rules_dir is None:
            # Default: rules/ directory next to the scanner package
            rules_dir = Path(__file__).parent.parent / "rules"
        self.rules_dir = Path(rules_dir)
        self._cache: Dict[str, List[RuleSet]] = {}

    def load(self, module: str, version: str = "latest") -> List[RuleSet]:
        """Load all rule sets for a given module and version."""
        cache_key = f"{module}:{version}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        if version == "latest":
            version = self._get_latest_version(module)

        module_dir = self.rules_dir / module / version
        if not module_dir.exists():
            return []

        rule_sets = []
        for yaml_file in sorted(module_dir.glob("*.yaml")):
            with open(yaml_file) as f:
                data = yaml.safe_load(f)
            if data:
                rule_sets.append(self._parse_rule_set(data))

        self._cache[cache_key] = rule_sets
        return rule_sets

    def load_all(self) -> Dict[str, List[RuleSet]]:
        """Load rule sets for all modules."""
        result = {}
        if not self.rules_dir.exists():
            return result
        for module_dir in self.rules_dir.iterdir():
            if module_dir.is_dir() and not module_dir.name.startswith("."):
                result[module_dir.name] = self.load(module_dir.name)
        return result

    def _get_latest_version(self, module: str) -> str:
        module_dir = self.rules_dir / module
        if not module_dir.exists():
            return "v1"
        versions = sorted(
            [d.name for d in module_dir.iterdir() if d.is_dir() and d.name.startswith("v")],
            key=lambda v: int(v[1:]) if v[1:].isdigit() else 0,
        )
        return versions[-1] if versions else "v1"

    def _parse_rule_set(self, data: dict) -> RuleSet:
        rs = data.get("rule_set", data)
        # Rules can be nested under rule_set or at the top level
        rules_data = rs.get("rules", data.get("rules", []))
        # Skip files can also be at either level
        skip_files = rs.get("skip_files", data.get("skip_files", []))
        skip_if_contains = rs.get("skip_if_contains", data.get("skip_if_contains", []))
        target_files = rs.get("target_files", data.get("target_files", {}))
        structural_rules = rs.get("structural_rules", data.get("structural_rules", []))

        rules = []
        for r in rules_data:
            flags = 0
            flag_str = r.get("flags", "")
            if "IGNORECASE" in flag_str:
                flags |= re.IGNORECASE
            if "MULTILINE" in flag_str:
                flags |= re.MULTILINE
            if "DOTALL" in flag_str:
                flags |= re.DOTALL

            rules.append(Rule(
                id=r["id"],
                title=r["title"],
                severity=r["severity"],
                category=rs.get("category", r.get("category", "unknown")),
                module=rs.get("module", r.get("module", "unknown")),
                pattern=r["pattern"],
                flags=flags,
                cwe=r.get("cwe"),
                confidence=r.get("confidence", "medium"),
                description=r.get("description", ""),
                recommendation=r.get("recommendation", ""),
                references=r.get("references", []),
                skip_in_comments=r.get("skip_in_comments", False),
                skip_if_contains=r.get("skip_if_contains", []),
                severity_overrides=r.get("severity_overrides", []),
                language=rs.get("language"),
                file_extensions=rs.get("file_extensions", []),
            ))

        target_files = target_files if isinstance(target_files, dict) else {}
        return RuleSet(
            name=rs.get("name", "unknown"),
            version=rs.get("version", "1.0.0"),
            category=rs.get("category", "unknown"),
            module=rs.get("module", "unknown"),
            description=rs.get("description", ""),
            rules=rules,
            skip_files=skip_files or [],
            skip_if_contains=skip_if_contains or [],
            target_files_exact=target_files.get("exact", []),
            target_files_pattern=target_files.get("pattern", []),
            structural_rules=structural_rules or [],
        )
