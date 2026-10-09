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
from urllib.parse import quote
try:
    import tomllib
except ImportError:
    tomllib = None
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
        self._osv_cache.clear()
        for source, content in files.items():
            basename = os.path.basename(source)
            if basename in {"package.json", "package-lock.json", "npm-shrinkwrap.json", "Pipfile.lock"} or (tomllib is not None and basename in {"pyproject.toml", "Pipfile"}):
                try:
                    data = tomllib.loads(content) if basename in {"pyproject.toml", "Pipfile"} else json.loads(content)
                    if not isinstance(data, dict):
                        raise ValueError("Expected object")
                except (ValueError, TypeError):
                    findings.append(Finding(
                        title="Dependency manifest could not be parsed", severity=Severity.INFO, category=Category.SCA,
                        module=self.name, description="Dependency checks for this malformed manifest were skipped.",
                        file_path=source, recommendation="Fix the manifest syntax and scan again.",
                        confidence="high", rule_id="SCA-PARSE-001"))

        # Parse all dependency manifests
        dependencies = self._parse_all_manifests(files)

        if not dependencies:
            findings.append(Finding(
                title="No Dependency Declarations Parsed",
                severity=Severity.INFO,
                category=Category.SCA,
                module=self.name,
                description="No dependency declarations could be parsed from supported manifests. SCA coverage is incomplete, not a clean bill of health.",
                file_path="N/A",
                recommendation="Add a dependency manifest file to enable SCA scanning and SBOM generation.",
                confidence="high",
            ))
            return findings

        # Package presence is not evidence of a vulnerability.
        for pkg_name, version, source_file in dependencies if context.config.get("include_experimental") else []:
            for risky_pkg, reason in self.RISKY_AI_PACKAGES.items():
                if risky_pkg.lower() == pkg_name.lower():
                    findings.append(Finding(
                        title=f"Risky AI/ML Package: {pkg_name}",
                        severity=Severity.MEDIUM,
                        category=Category.SCA,
                        module=self.name,
                        description=f"Package '{pkg_name}' (version {version or 'unspecified'}) in {source_file} is flagged for AI security review. {reason}.",
                        file_path=source_file,
                        recommendation=f"Review usage of {pkg_name}. Ensure models are loaded from trusted sources, prompts are sanitized, and tool execution is sandboxed.",
                        cwe="CWE-1104",
                        confidence="low", maturity="experimental", rule_id="SCA-PACKAGE-REVIEW",
                    ))

        # Query OSV.dev for known vulnerabilities (LIVE — no hardcoded CVEs)
        unresolved = sorted({source for _, version, source in dependencies if not self._exact_version(version)})
        for source in unresolved:
            findings.append(Finding(
                title="Unresolved dependency versions", severity=Severity.INFO, category=Category.SCA,
                module=self.name, description="Some declarations are ranges or unpinned. They remain in the SBOM but were not checked as installed versions.",
                file_path=source, recommendation="Commit a supported lockfile or exact version pins for reliable advisory matching.",
                confidence="high", rule_id="SCA-UNRESOLVED-001"))
        vuln_findings = self._check_osv(dependencies)
        findings.extend(vuln_findings)

        return findings

    def generate_sbom(self, files: Dict[str, str], repo_name: str = "unknown") -> dict:
        """Generate a CycloneDX-format SBOM from dependency manifests."""
        from datetime import datetime, timezone

        dependencies = self._parse_all_manifests(files)
        components = []
        seen = set()
        for pkg_name, version, source_file in dependencies:
            ecosystem = {"PyPI": "pypi", "npm": "npm", "Go": "golang"}[self._ecosystem(source_file)]
            exact = self._exact_version(version)
            purl = f"pkg:{ecosystem}/{quote(pkg_name, safe='/')}" + (f"@{quote(exact, safe='')}" if exact else "")
            if purl in seen:
                continue
            seen.add(purl)
            component = {
                "type": "library",
                "name": pkg_name,
                "purl": purl,
                "bom-ref": purl,
                "properties": [{"name": "source_file", "value": source_file},
                               {"name": "theron:version_status", "value": "exact" if exact else "unresolved"},
                               {"name": "theron:declared_version", "value": version or "unspecified"}],
            }
            if exact:
                component["version"] = exact
            components.append(component)

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "component": {"type": "application", "name": repo_name},
                "tools": [{"vendor": "Theron", "name": "Theron", "version": "1.0.0"}],
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
            elif basename in {"package-lock.json", "npm-shrinkwrap.json", "Pipfile.lock"}:
                deps.extend(self._parse_lock(content, file_path))
        locked = {(os.path.dirname(source), self._ecosystem(source), name) for name, version, source in deps
                  if os.path.basename(source) in {"package-lock.json", "npm-shrinkwrap.json", "Pipfile.lock"}}
        return list(dict.fromkeys((name, version, source) for name, version, source in deps
                    if os.path.basename(source) in {"package-lock.json", "npm-shrinkwrap.json", "Pipfile.lock"}
                    or (os.path.dirname(source), self._ecosystem(source), name) not in locked))

    @staticmethod
    def _ecosystem(source):
        basename = os.path.basename(source)
        return "npm" if basename in {"package.json", "package-lock.json", "npm-shrinkwrap.json"} else "Go" if basename == "go.mod" else "PyPI"

    @staticmethod
    def _exact_version(version):
        if not isinstance(version, str):
            return None
        version = version.strip()
        if version.startswith("==") and not version.startswith("==="):
            version = version[2:].strip()
        return version if re.fullmatch(r"v?\d+(?:\.\d+)+(?:[-+._][A-Za-z0-9.-]+)?", version) else None

    def _parse_lock(self, content, source):
        try:
            data = json.loads(content)
            if not isinstance(data, dict):
                return []
            deps = []
            if os.path.basename(source) == "Pipfile.lock":
                for section in ("default", "develop"):
                    entries = data.get(section, {})
                    if isinstance(entries, dict):
                        for name, entry in entries.items():
                            if isinstance(entry, dict):
                                deps.append((name, entry.get("version"), source))
            elif isinstance(data.get("packages"), dict):
                for path, entry in data["packages"].items():
                    if path and "node_modules/" in path and isinstance(entry, dict) and not entry.get("link"):
                        name = entry.get("name") or path.rsplit("node_modules/", 1)[-1]
                        deps.append((name, entry.get("version"), source))
            else:
                def walk(entries):
                    if not isinstance(entries, dict):
                        return
                    for name, entry in entries.items():
                        if isinstance(entry, dict):
                            deps.append((name, entry.get("version"), source))
                            walk(entry.get("dependencies", {}))
                walk(data.get("dependencies", {}))
            return deps
        except (ValueError, TypeError):
            return []

    def _parse_requirements(self, content: str, source: str) -> List[Tuple[str, str, str]]:
        deps = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = re.match(r"^([a-zA-Z0-9_.-]+)(?:\[[^\]]+\])?\s*(.*)", line)
            if match:
                name = match.group(1)
                version = match.group(2).split(";", 1)[0].split(" #", 1)[0].split(" --hash", 1)[0].strip() or None
                deps.append((name, version, source))
        return deps

    def _parse_package_json(self, content: str, source: str) -> List[Tuple[str, str, str]]:
        deps = []
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, TypeError):
            return deps
        if not isinstance(data, dict):
            return deps
        for section in ["dependencies", "devDependencies", "peerDependencies"]:
            entries = data.get(section, {})
            if isinstance(entries, dict):
                for name, version in entries.items():
                    deps.append((name, version if isinstance(version, str) else None, source))
        return deps

    def _parse_pyproject(self, content: str, source: str) -> List[Tuple[str, str, str]]:
        deps = []
        if tomllib is not None:
            try:
                data = tomllib.loads(content)
            except ValueError:
                return deps
            project = data.get("project", {})
            if not isinstance(project, dict):
                return deps
            entries = project.get("dependencies", [])
            optional = project.get("optional-dependencies", {})
            if not isinstance(entries, list):
                return deps
            entries = entries.copy()
            if isinstance(optional, dict):
                for group in optional.values():
                    if isinstance(group, list):
                        entries.extend(group)
            return self._parse_requirements("\n".join(value for value in entries if isinstance(value, str)), source)
        # shortcut: Python <3.11 supports multiline PEP 621 entries only, upgrade for full TOML parsing.
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
                match = re.match(r'''["']([a-zA-Z0-9_.-]+)(?:\[[^\]]+\])?\s*([^"']*)["']''', stripped)
                if match:
                    name = match.group(1)
                    version = match.group(2).split(";", 1)[0].strip() or None
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
                    # Replacements can change the effective package identity/version.
                    deps.append((parts[0], None if re.search(r"(?m)^\s*replace\s", content) else parts[1], source))
        return deps

    def _parse_pipfile(self, content: str, source: str) -> List[Tuple[str, str, str]]:
        deps = []
        if tomllib is not None:
            try:
                data = tomllib.loads(content)
            except ValueError:
                return deps
            for section in ("packages", "dev-packages"):
                entries = data.get(section, {})
                if isinstance(entries, dict):
                    for name, entry in entries.items():
                        version = entry.get("version") if isinstance(entry, dict) else entry
                        deps.append((name, version if isinstance(version, str) else None, source))
            return deps
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
                match = re.match(r'^([a-zA-Z0-9_.-]+)\s*=\s*["\']([^"\']+)["\']', stripped)
                if match:
                    deps.append((match.group(1), match.group(2), source))
        return deps

    # ── OSV.dev Live Vulnerability Checking ────────────────────────────────

    def _check_osv(self, dependencies: List[Tuple[str, str, str]]) -> List[Finding]:
        """Query OSV.dev API for known vulnerabilities. No hardcoded CVEs."""
        findings = []
        for pkg_name, version, source_file in dependencies:
            version = self._exact_version(version)
            if not version:
                continue
            ecosystem = self._ecosystem(source_file)
            cache_key = f"{ecosystem}:{pkg_name}@{version}"
            if cache_key in self._osv_cache:
                vulns = self._osv_cache[cache_key]
            else:
                try:
                    vulns = self._query_osv(pkg_name, version, ecosystem)
                except (requests.RequestException, ValueError, TypeError):
                    findings.append(Finding(
                        title="Dependency advisory lookup unavailable", severity=Severity.INFO, category=Category.SCA,
                        module=self.name, description=f"Could not check {pkg_name}@{version} in {ecosystem}. This is not a clean vulnerability result.",
                        file_path=source_file, recommendation="Retry when the advisory service is available.",
                        confidence="high", rule_id="SCA-LOOKUP-001"))
                    continue
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
                    description=f"Declared exact {ecosystem} package '{pkg_name}' version {version} in {source_file} matches advisory {vid}: {summary}. Application reachability and exploitability have not been verified.",
                    file_path=source_file,
                    recommendation=f"Upgrade {pkg_name} to a patched version. See https://osv.dev/vulnerability/{vid} for details.",
                    cwe="CWE-1104",
                    confidence="high",
                    rule_id=f"SCA-{vid}",
                    references=[f"https://osv.dev/vulnerability/{vid}"],
                ))
        return findings

    def _query_osv(self, package: str, version: str, ecosystem: str) -> list:
        """Query the OSV.dev API for a specific package version."""
        payload = {"package": {"name": package, "ecosystem": ecosystem}, "version": version}
        resp = requests.post(f"{self.OSV_API}/query", json=payload, timeout=(5, 15))
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict) or not isinstance(data.get("vulns", []), list):
            raise ValueError("Malformed advisory response")
        if any(not isinstance(vuln, dict) or not isinstance(vuln.get("id"), str) for vuln in data.get("vulns", [])):
            raise ValueError("Malformed advisory entry")
        return [vuln for vuln in data.get("vulns", []) if isinstance(vuln, dict) and not vuln.get("withdrawn")]

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
        # shortcut: CVSS vectors are not scored; use advisory severity metadata or provisional MEDIUM.
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
        return Severity.MEDIUM  # Unknown advisory severity is not evidence of high impact.
