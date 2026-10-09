"""Finding normalization shared by local and GitHub scans."""

import fnmatch
import hashlib
import re
from typing import Iterable, List, Optional

from scanner.models import Finding, Category, Severity


def fingerprint(finding: Finding) -> str:
    """Create a deterministic ID based on evidence, not a report's ordering."""
    evidence = re.sub(r"\s+", " ", finding.code_snippet or finding.title).strip()
    payload = "\x1f".join((finding.rule_id or finding.title, finding.file_path, evidence))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


def normalize_findings(findings: Iterable[Finding], config: Optional[dict] = None) -> List[Finding]:
    config = config or {}
    excluded = config.get("exclude", []) or []
    accepted = set(config.get("accepted_fingerprints", []) or [])
    seen, result = set(), []
    for finding in findings:
        if any(fnmatch.fnmatch(finding.file_path, pattern) for pattern in excluded):
            continue
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
