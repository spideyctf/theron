"""
SAST (Static Application Security Testing) scanner plugin.

Performs pattern-based static analysis to detect:
- Command injection, eval/exec, path traversal, SSRF, SQL injection
- Insecure deserialization, weak random, XXE
- AI-specific taint: user input → LLM prompt, LLM output → code execution

Rules are loaded from rules/sast/v1/*.yaml, scoped by language.
"""

import re
from typing import List
from scanner.models import Finding, ScanContext, Severity, Category
from scanner.plugins.base import Scanner
from scanner.plugins import register


@register
class SASTScanner(Scanner):
    """Static analysis scanner for code vulnerabilities."""

    @property
    def name(self) -> str:
        return "sast"

    @property
    def description(self) -> str:
        return "Static analysis: command injection, eval, path traversal, SSRF, SQLi, deserialization, AI taint"

    SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build", ".next", "vendor"}

    def scan(self, context: ScanContext) -> List[Finding]:
        findings = []
        rule_sets = context.rule_loader.load("sast")
        profile = context.project_profile

        for rule_set in rule_sets:
            # Determine which files to scan based on language/extension scope
            for file_path, content in context.files.items():
                if any(skip in file_path for skip in self.SKIP_DIRS):
                    continue

                basename = file_path.rsplit("/", 1)[-1]
                ext = "." + basename.rsplit(".", 1)[-1] if "." in basename else ""

                # Default: scan code files
                if ext not in {".py", ".js", ".ts", ".jsx", ".tsx", ".yaml", ".yml"}:
                    continue

                for rule in rule_set.rules:
                    # If rule specifies file extensions, filter by them
                    if rule.file_extensions and ext not in rule.file_extensions:
                        continue
                    findings.extend(self._apply_rule(rule, file_path, content, self.name))

        return findings
