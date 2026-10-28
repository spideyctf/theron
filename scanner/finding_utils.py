"""Finding normalization shared by local and GitHub scans."""

import fnmatch
import hashlib
import re
from typing import Iterable, List, Optional

from scanner.models import Finding, Category, Severity


def finding_scope(path):
    parts = path.replace("\\", "/").lower().split("/")
    if any(part in {"tests", "test", "fixtures", "__tests__", "testdata"} for part in parts) or parts[-1].startswith("test_") or parts[-1].endswith(("_test.py", ".test.tsx", ".test.ts", ".spec.ts")):
        return "test"
    if any(part in {"examples", "example", "demo", "demos", "samples"} for part in parts):
        return "example"
    if parts[-1] in {"skill.md", "agents.md", "agent.md", "claude.md", "instructions.md"}:
        return "application"
    if any(part in {"docs", "documentation"} for part in parts) or parts[-1].endswith(".md"):
        return "documentation"
    return "application"


def partition_findings(result):
    """Keep non-application detections inspectable without counting them as production alerts."""
    result.context_findings = [finding for finding in result.findings if finding.scope != "application"]
    result.findings = [finding for finding in result.findings if finding.scope == "application"]


def fingerprint(finding: Finding) -> str:
    """Create a deterministic ID based on evidence, not a report's ordering."""
    evidence = re.sub(r"\s+", " ", finding.code_snippet or finding.title).strip()
    origin = "".join(f"{step.get('file_path')}:{step.get('line_number')}" for step in finding.trace if step.get('role') == 'source')
    payload = "\x1f".join((finding.rule_id or finding.title, finding.file_path, evidence, origin))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


def normalize_findings(findings: Iterable[Finding], config: Optional[dict] = None) -> List[Finding]:
    config = config or {}
    excluded = config.get("exclude", []) or []
    accepted = set(config.get("accepted_fingerprints", []) or [])
    seen, result = set(), []
    for finding in findings:
        if any(fnmatch.fnmatch(finding.file_path, pattern) for pattern in excluded):
            continue
        finding.scope = finding_scope(finding.file_path)
        origins = [finding_scope(step.get("file_path", "")) for step in finding.trace if step.get("role") == "source"]
        if finding.scope == "application" and any(scope != "application" for scope in origins):
            finding.scope = next(scope for scope in origins if scope != "application")
        if finding.category == Category.SECRET_EXPOSURE:
            already_classified = finding.evidence_kind == "credential-pattern-unverified"
            finding.evidence_kind = "credential-pattern-unverified"
            finding.confidence = "medium"
            finding.title = finding.title.replace("Exposed ", "Possible exposed ")
            if "unverified" not in finding.title:
                finding.title += " (unverified)"
            if not already_classified:
                finding.description = "A provider-shaped credential pattern was found at this location. Validity and actual use have not been verified."
            finding.recommendation = "If this value is a real credential, revoke or rotate it and remove it from source. For a deliberate fixture, keep it clearly labeled as synthetic."
            if finding.severity == Severity.CRITICAL:
                finding.severity = Severity.HIGH
        elif finding.severity == Severity.INFO:
            finding.evidence_kind = "coverage-notice"
        finding.fingerprint = finding.fingerprint or fingerprint(finding)
        finding.status = "existing" if finding.fingerprint in accepted else "new"
        if finding.fingerprint not in seen:
            seen.add(finding.fingerprint)
            result.append(finding)
    return result


def coverage_finding(path: str, reason: str) -> Finding:
    return Finding(title="File analysis skipped", severity=Severity.INFO, category=Category.SAST,
                   module="coverage", description=reason + " Scan coverage is incomplete for this file.",
                   file_path=path, recommendation="Resolve the limitation and scan again.",
                   confidence="high", rule_id="SCAN-COVERAGE-001")
