"""
AI Security scanner plugin.

Scans for:
- Prompt injection patterns in system prompts, instructions, and config
- Secret/API key exposure in code and config files
- Insecure model deployment (exposed endpoints, missing auth, pickle/torch.load)
- Data exfiltration risks (outbound calls to untrusted endpoints)
"""

import re
from typing import List
from scanner.models import Finding, ScanContext, Severity, Category
from scanner.plugins.base import Scanner
from scanner.plugins import register


@register
class AISecurityScanner(Scanner):
    """Scans for AI-specific security vulnerabilities."""

    @property
    def name(self) -> str:
        return "ai"

    @property
    def description(self) -> str:
        return "AI-specific security: prompt injection, secret exposure, insecure model deployment, data exfiltration"

    SCANABLE_EXTENSIONS = {
        ".py", ".js", ".ts", ".yaml", ".yml", ".json", ".toml",
        ".env", ".cfg", ".ini", ".txt", ".md",
    }

    SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build", ".next"}

    def scan(self, context: ScanContext) -> List[Finding]:
        findings = []
        rule_sets = context.rule_loader.load("ai")

        for rule_set in rule_sets:
            # Check skip files
            for file_path, content in context.files.items():
                if any(skip in file_path for skip in self.SKIP_DIRS):
                    continue

                basename = file_path.rsplit("/", 1)[-1]
                ext = "." + basename.rsplit(".", 1)[-1] if "." in basename else ""

                # Check if file matches rule set targets
                if rule_set.target_files_exact or rule_set.target_files_pattern:
                    matched = basename in rule_set.target_files_exact
                    if not matched:
                        for p in rule_set.target_files_pattern:
                            regex_p = p.replace("*", ".*").replace("?", ".")
                            if re.match(regex_p, basename, re.IGNORECASE):
                                matched = True
                                break
                    if not matched:
                        continue

                # Check extension filter
                if ext not in self.SCANABLE_EXTENSIONS and basename not in {"Dockerfile", "docker-compose.yml"}:
                    continue

                # Check skip files
                if any(basename == sf or file_path.endswith(sf) for sf in (rule_set.skip_files or [])):
                    continue

                for rule in rule_set.rules:
                    findings.extend(self._apply_rule(rule, file_path, content, self.name))

        return findings
