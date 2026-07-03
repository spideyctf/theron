"""
SCA (Software Composition Analysis) scanner plugin.

- Auto-generates SBOM (CycloneDX format) from dependency manifests
- Checks dependencies against the OSV.dev vulnerability database (live API)
- Flags AI/ML packages with known security risks for extra scrutiny
- NO hardcoded CVEs — all vulnerability data is fetched live from OSV.dev

Supported manifests: requirements.txt, package.json, pyproject.toml, go.mod, Pipfile
"""

import json
import re
import os
import requests
from typing import List, Tuple, Dict, Optional
from scanner.models import Finding, ScanContext, Severity, Category
from scanner.plugins.base import Scanner
from scanner.plugins import register


@register
class SCAScanner(Scanner):
    """SCA scanner with live OSV.dev vulnerability checking and SBOM generation."""

    @property
    def name(self) -> str:
        return "sca"

    @property
    def description(self) -> str:
        return "Software composition analysis: SBOM generation, live OSV.dev CVE checking, risky AI/ML package flagging"

    OSV_API = "https://api.osv.dev/v1"

    # AI/ML packages that warrant extra security scrutiny
    RISKY_AI_PACKAGES = {
        "langchain": "LangChain — review for prompt injection in chains/agents, tool use without sandboxing",
        "langchain-community": "LangChain community — third-party integrations may have untrusted tool definitions",
        "langchain-core": "LangChain core — review prompt templates and tool definitions",
        "langgraph": "LangGraph — review agent graph for unsafe tool execution paths",
        "llama-index": "LlamaIndex — review for prompt injection in query engines and data loaders",
        "llama-index-core": "LlamaIndex core — review data loaders and query engines",
        "crewai": "CrewAI — review agent tool definitions for injection vectors and unsafe operations",
        "autogen": "AutoGen — review for code execution agents without sandboxing",
        "pyautogen": "AutoGen — review for code execution agents without sandboxing",
        "transformers": "Transformers — verify model sources, check for pickle-based model loading",
        "torch": "PyTorch — verify model loading uses weights_only=True, check for pickle deserialization",
        "tensorflow": "TensorFlow — verify model sources, check for unsafe ops in saved models",
        "pickle": "Pickle — inherently unsafe deserialization, avoid for untrusted data",
        "shelve": "Shelve — uses pickle internally, unsafe for untrusted data",
        "dill": "Dill — extended pickle, unsafe for untrusted data",
    }

    def __init__(self):
        self._osv_cache: Dict[str, list] = {}

    def scan(self, context: ScanContext) -> List[Finding]:
        findings = []
        files = context.files

        # Parse all dependency manifests
        dependencies = self._parse_all_manifests(files)

        if not dependencies:
            findings.append(Finding(
                title="No Dependency Manifests Found",
                severity=Severity.INFO,
                category=Category.SCA,
                module=self.name,
                description="No dependency manifests (requirements.txt, package.json, pyproject.toml, go.mod) found. SCA could not be fully performed.",
                file_path="N/A",
                recommendation="Add a dependency manifest file to enable SCA scanning and SBOM generation.",
                confidence="high",
            ))
            return findings

        # Flag risky AI/ML packages
        for pkg_name, version, source_file in dependencies:
            for risky_pkg, reason in self.RISKY_AI_PACKAGES.items():
                if risky_pkg.lower() in pkg_name.lower():
                    findings.append(Finding(
                        title=f"Risky AI/ML Package: {pkg_name}",
                        severity=Severity.MEDIUM,
                        category=Category.SCA,
                        module=self.name,
                        description=f"Package '{pkg_name}' (version {version or 'unspecified'}) in {source_file} is flagged for AI security review. {reason}.",
                        file_path=source_file,
                        recommendation=f"Review usage of {pkg_name}. Ensure models are loaded from trusted sources, prompts are sanitized, and tool execution is sandboxed.",
                        cwe="CWE-1104",
                        confidence="high",
                    ))

        # Query OSV.dev for known vulnerabilities (LIVE — no hardcoded CVEs)
        vuln_findings = self._check_osv(dependencies)
        findings.extend(vuln_findings)

        return findings

    def generate_sbom(self, files: Dict[str, str], repo_name: str = "unknown") -> dict:
        """Generate a CycloneDX-format SBOM from dependency manifests."""
        from datetime import datetime

        dependencies = self._parse_all_manifests(files)
        components = []
        for pkg_name, version, source_file in dependencies:
            ecosystem = "pypi" if source_file in ("requirements.txt", "pyproject.toml", "Pipfile") else \
                        "npm" if source_file == "package.json" else \
                        "golang" if source_file == "go.mod" else "pypi"
            components.append({
                "type": "library",
                "name": pkg_name,
                "version": version or "unknown",
                "purl": f"pkg:{ecosystem}/{pkg_name}@{version}" if version else f"pkg:{ecosystem}/{pkg_name}",
                "bom-ref": f"{pkg_name}@{version or 'unknown'}",
                "properties": [{"name": "source_file", "value": source_file}],
            })

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "component": {"type": "application", "name": repo_name},
                "tools": [{"vendor": "ai-sec-scanner", "name": "ai-sec-scanner", "version": "0.1.0"}],
            },
            "components": components,
        }

    # ── Manifest Parsers ──────────────────────────────────────────────────

    def _parse_all_manifests(self, files: Dict[str, str]) -> List[Tuple[str, str, str]]:
        deps = []
        for file_path, content in files.items():
            basename = os.path.basename(file_path)
            if basename == "requirements.txt":
                deps.extend(self._parse_requirements(content, file_path))
            elif basename == "package.json":
                deps.extend(self._parse_package_json(content, file_path))
            elif basename == "pyproject.toml":
                deps.extend(self._parse_pyproject(content, file_path))
            elif basename == "go.mod":
                deps.extend(self._parse_go_mod(content, file_path))
            elif basename == "Pipfile":
                deps.extend(self._parse_pipfile(content, file_path))
        return deps

    def _parse_requirements(self, content: str, source: str) -> List[Tuple[str, str, str]]:
        deps = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = re.match(r"^([a-zA-Z0-9_.-]+)\s*([=<>!~]+\s*[\w.]+)?", line)
            if match:
                name = match.group(1)
                version = None
                if match.group(2):
                    version = re.sub(r"[=<>!~\s]+", "", match.group(2))
                deps.append((name, version, source))
        return deps

    def _parse_package_json(self, content: str, source: str) -> List[Tuple[str, str, str]]:
        deps = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return deps
        for section in ["dependencies", "devDependencies", "peerDependencies"]:
            for name, version in data.get(section, {}).items():
                clean = version.lstrip("^~>=<")
                deps.append((name, clean, source))
        return deps

    def _parse_pyproject(self, content: str, source: str) -> List[Tuple[str, str, str]]:
        deps = []
        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()
            if "dependencies" in stripped and "[" in stripped:
                in_deps = True
                continue
            if in_deps:
                if stripped.startswith("]"):
                    in_deps = False
                    continue
                match = re.match(r'''["']([a-zA-Z0-9_.-]+)\s*([=<>!~]+[\w.]+)?["']''', stripped)
                if match:
                    name = match.group(1)
                    version = re.sub(r"[=<>!~\s]+", "", match.group(2)) if match.group(2) else None
                    deps.append((name, version, source))
        return deps

    def _parse_go_mod(self, content: str, source: str) -> List[Tuple[str, str, str]]:
        deps = []
        in_require = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped == "require (":
                in_require = True
                continue
            if in_require and stripped == ")":
                in_require = False
                continue
            if stripped.startswith("require ") or in_require:
                parts = stripped.replace("require ", "").split()
                if len(parts) >= 2:
                    deps.append((parts[0], parts[1], source))
        return deps

    def _parse_pipfile(self, content: str, source: str) -> List[Tuple[str, str, str]]:
        deps = []
        in_section = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped in ("[packages]", "[dev-packages]"):
                in_section = True
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                in_section = False
                continue
            if in_section and "=" in stripped:
                match = re.match(r'^([a-zA-Z0-9_.-]+)\s*=\s*["\']?([\w.*]+)', stripped)
                if match:
                    deps.append((match.group(1), match.group(2).replace("*", ""), source))
        return deps

    # ── OSV.dev Live Vulnerability Checking ────────────────────────────────

    def _check_osv(self, dependencies: List[Tuple[str, str, str]]) -> List[Finding]:
        """Query OSV.dev API for known vulnerabilities. No hardcoded CVEs."""
        findings = []
        for pkg_name, version, source_file in dependencies:
            if not version or version == "unknown":
                continue
            cache_key = f"{pkg_name}@{version}"
            if cache_key in self._osv_cache:
                vulns = self._osv_cache[cache_key]
            else:
                vulns = self._query_osv(pkg_name, version)
                self._osv_cache[cache_key] = vulns

            for vuln in vulns:
                severity = self._osv_severity_to_finding(vuln)
                vid = vuln.get("id", "unknown")
                summary = vuln.get("summary", vuln.get("details", "No details available"))
                if isinstance(summary, str) and len(summary) > 300:
                    summary = summary[:300] + "..."

                findings.append(Finding(
                    title=f"Vulnerable Dependency: {pkg_name}@{version} — {vid}",
                    severity=severity,
                    category=Category.SCA,
                    module=self.name,
                    description=f"Package '{pkg_name}' version {version} in {source_file} has known vulnerability {vid}: {summary}",
                    file_path=source_file,
                    recommendation=f"Upgrade {pkg_name} to a patched version. See https://osv.dev/vulnerability/{vid} for details.",
                    cwe="CWE-1104",
                    confidence="high",
                    references=[f"https://osv.dev/vulnerability/{vid}"],
                ))
        return findings

    def _query_osv(self, package: str, version: str) -> list:
        """Query the OSV.dev API for a specific package version."""
        for ecosystem in ["PyPI", "npm", "Go"]:
            payload = {
                "package": {"name": package, "ecosystem": ecosystem},
                "version": version,
            }
            try:
                resp = requests.post(f"{self.OSV_API}/query", json=payload, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("vulns", [])
            except (requests.RequestException, requests.Timeout):
                continue
        return []

    @staticmethod
    def _osv_severity_to_finding(vuln: dict) -> Severity:
        """Map OSV severity to our Severity enum."""
        db_specific = vuln.get("database_specific", {})
        if "severity" in db_specific:
            sev = db_specific["severity"].upper()
            if "CRITICAL" in sev:
                return Severity.CRITICAL
            if "HIGH" in sev:
                return Severity.HIGH
            if "MEDIUM" in sev or "MODERATE" in sev:
                return Severity.MEDIUM
            if "LOW" in sev:
                return Severity.LOW
        # Check severity array
        for s in vuln.get("severity", []):
            score = s.get("score", "")
            if "CVSS" in score:
                try:
                    # Try to extract CVSS base score
                    parts = score.split("/")
                    for p in parts:
                        if p.startswith("AV:"):
                            pass
                    # Use type as fallback
                    if s.get("type") == "CVSS_V3":
                        return Severity.HIGH
                except Exception:
                    pass
        # Check affected ranges for severity hints
        for affected in vuln.get("affected", []):
            ec = affected.get("ecosystem_specific", {})
            if "severity" in ec:
                sev = ec["severity"].upper()
                if "CRITICAL" in sev:
                    return Severity.CRITICAL
                if "HIGH" in sev:
                    return Severity.HIGH
                if "MEDIUM" in sev or "MODERATE" in sev:
                    return Severity.MEDIUM
                if "LOW" in sev:
                    return Severity.LOW
        return Severity.HIGH  # Default — unclassified vulns are treated as HIGH
