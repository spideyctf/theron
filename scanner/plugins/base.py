"""
Base scanner plugin interface.

All scanner plugins implement this interface. The engine discovers plugins
automatically via the @register decorator and calls scan() on each.
"""

from abc import ABC, abstractmethod
from typing import List
from scanner.models import Finding, ScanContext


class Scanner(ABC):
    """Common interface all scanner plugins implement."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique scanner identifier (e.g. 'ai', 'sast', 'sca', 'agentic')."""
        pass

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def description(self) -> str:
        return ""

    @abstractmethod
    def scan(self, context: ScanContext) -> List[Finding]:
        """Run detection logic and return findings."""
        pass

    def supports_project(self, profile) -> bool:
        """Override to skip this scanner for certain project types."""
        return True

    # ── Shared utilities ────────────────────────────────────────────────

    @staticmethod
    def _get_lines(content: str, line_num: int, context: int = 2) -> str:
        """Extract a code snippet around a given line number."""
        lines = content.splitlines()
        start = max(0, line_num - 1 - context)
        end = min(len(lines), line_num + context)
        return "\n".join(f"{i+1}: {lines[i]}" for i in range(start, end))

    @staticmethod
    def _is_comment_line(line: str) -> bool:
        stripped = line.lstrip()
        return stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("/*")

    @staticmethod
    def _is_placeholder(line: str) -> bool:
        placeholders = [
            "your_", "your-", "placeholder", "example", "xxx", "change_me",
            "insert", "replace", "todo", "fixme", "<", ">",
            "put-your", "enter-your", "add-your",
        ]
        line_lower = line.lower()
        return any(ph in line_lower for ph in placeholders)

    def _apply_rule(self, rule, file_path: str, content: str, module_name: str) -> List[Finding]:
        """Apply a single regex rule to a file and return findings."""
        from scanner.models import Finding, Severity, Category

        findings = []
        lines = content.splitlines()
        compiled = None
        try:
            import re as _re
            compiled = _re.compile(rule.pattern, rule.flags)
        except _re.error:
            return findings

        for i, line in enumerate(lines, 1):
            match = compiled.search(line)
            if not match:
                continue

            # Skip comments if configured
            if rule.skip_in_comments and self._is_comment_line(line):
                continue

            # Skip placeholders — only check the matched text, not the whole line
            matched_text = match.group()
            if self._is_placeholder(matched_text):
                continue
            if rule.skip_if_contains and self._is_placeholder(matched_text):
                continue

            # Determine severity (with overrides)
            severity_str = rule.severity
            for override in (rule.severity_overrides or []):
                condition = override.get("condition", "")
                if "skill" in condition.lower() and any(
                    kw in file_path.lower() for kw in ["skill.md", "instructions", "agent", "prompt"]
                ):
                    severity_str = override.get("severity", severity_str)

            try:
                severity = Severity(severity_str)
            except ValueError:
                severity = Severity.MEDIUM

            try:
                category = Category(rule.category)
            except ValueError:
                category = Category.MISCONFIGURATION

            findings.append(Finding(
                title=rule.title,
                severity=severity,
                category=category,
                module=module_name,
                description=rule.description,
                file_path=file_path,
                line_number=i,
                code_snippet=self._get_lines(content, i),
                recommendation=rule.recommendation,
                cwe=rule.cwe,
                confidence=rule.confidence,
                rule_id=rule.id,
                references=rule.references,
            ))

        return findings
