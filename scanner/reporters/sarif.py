"""SARIF reporter — outputs SARIF 2.1.0 format for GitHub code scanning."""

import json
from scanner.models import ScanResult, Severity


SEVERITY_TO_SARIF = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


def generate_sarif_report(result: ScanResult) -> str:
    rules = []
    rule_indices = {}
    for finding in result.findings:
        rule_id = finding.rule_id or finding.cwe or finding.category.value
        if rule_id not in rule_indices:
            rule_indices[rule_id] = len(rules)
            rules.append({
                "id": rule_id,
                "name": finding.category.value,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{(finding.cwe or '').replace('CWE-', '')}.html" if finding.cwe else "",
                "defaultConfiguration": {"level": SEVERITY_TO_SARIF.get(finding.severity, "warning")},
            })

    results = []
    for finding in result.findings:
        rule_id = finding.rule_id or finding.cwe or finding.category.value
        results.append({
            "ruleId": rule_id,
            "ruleIndex": rule_indices[rule_id],
            "level": SEVERITY_TO_SARIF.get(finding.severity, "warning"),
            "message": {"text": finding.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file_path},
                    "region": {"startLine": finding.line_number or 1} if finding.line_number else {},
                }
            }],
            "properties": {
                "severity": finding.severity.value,
                "category": finding.category.value,
                "module": finding.module,
                "confidence": finding.confidence,
                "recommendation": finding.recommendation,
            },
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ai-sec-scanner",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/aryaman-futane/ai-sec-scanner",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def save_sarif_report(result: ScanResult, output_path: str):
    with open(output_path, "w") as f:
        f.write(generate_sarif_report(result))
