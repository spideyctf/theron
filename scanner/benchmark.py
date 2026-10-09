"""Evaluate labelled PySASTBench pairs as text, without importing their code."""

import argparse
import ast
import csv
import hashlib
import json
from pathlib import Path

from scanner.models import ProjectProfile, ScanContext, Severity
from scanner.plugins.sast import SASTScanner
from scanner.rule_loader import RuleLoader


def target_span(content, position):
    """Locate a qualified function name; missing targets are errors, not negatives."""
    tree = ast.parse(content)
    def walk(nodes, prefix=""):
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = prefix + node.name
                if name == position:
                    return node.lineno, node.end_lineno
                found = walk(node.body, name + ".")
                if found:
                    return found
    return walk(tree.body)


def evaluate(dataset, experimental=False):
    root = Path(dataset).resolve()
    manifest = root / "SyntheticDataset.csv"
    with manifest.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    scanner, loader = SASTScanner(), RuleLoader()
    groups, cases = {}, []
    for row in rows:
        case, cwe, position = row["TestCase"].strip(), row["CWE Type"].strip(), row["Vul Position"].strip()
        if not case or not cwe.isdigit() or Path(case).name != case or any(c in case for c in "/\\"):
            raise ValueError("Invalid benchmark case identifier")
        group = groups.setdefault(cwe, {"tp": 0, "fn": 0, "fp": 0, "tn": 0, "errors": 0})
        for variant in ("vul", "fix"):
            path = root / "SyntheticDataset" / cwe / f"{case}_{variant}.py"
            record = {"case": case, "cwe": cwe, "variant": variant, "target": position}
            try:
                if not path.resolve().is_relative_to(root):
                    raise ValueError("Benchmark file escapes dataset directory")
                content = path.read_text(encoding="utf-8-sig")
                record["source_sha256"] = hashlib.sha256(content.encode()).hexdigest()
                span = target_span(content, position)
                if span is None and variant == "vul":
                    raise ValueError("Labelled function not found")
                if span is None:
                    span = (1, len(content.splitlines()))
                    record["fixed_target_scope"] = "whole file: labelled function removed or renamed"
                ctx = ScanContext(files={path.name: content}, repo_info={}, project_profile=ProjectProfile(),
                                  rule_loader=loader, config={"include_experimental": experimental})
                findings = [finding for finding in scanner.scan(ctx) if finding.severity != Severity.INFO]
                # CWE-78 (OS command injection) is a child of the corpus's CWE-77 label.
                accepted_cwes = {f"CWE-{cwe}"} | ({"CWE-78"} if cwe == "77" else set())
                matched = [finding for finding in findings if finding.cwe in accepted_cwes
                           and finding.line_number and span[0] <= finding.line_number <= span[1]]
                bucket = ("tp" if matched else "fn") if variant == "vul" else ("fp" if matched else "tn")
                group[bucket] += 1
                record.update(outcome=bucket, matched_rules=sorted({f.rule_id for f in matched}),
                              total_alerts=len(findings), unrelated_alerts=len(findings) - len(matched))
            except (OSError, SyntaxError, ValueError) as exc:
                group["errors"] += 1
                record.update(outcome="error", error=str(exc))
            cases.append(record)
    def metrics(counts):
        tp, fp, fn, tn = (counts[key] for key in ("tp", "fp", "fn", "tn"))
        return {**counts, "precision": tp / (tp + fp) if tp + fp else None,
                "recall": tp / (tp + fn) if tp + fn else None,
                "false_positive_rate": fp / (fp + tn) if fp + tn else None}
    totals = {key: sum(group[key] for group in groups.values()) for key in ("tp", "fn", "fp", "tn", "errors")}
    head = root / ".git" / "HEAD"
    revision = None
    if head.is_file():
        revision = head.read_text().strip()
        if revision.startswith("ref: "):
            ref = root / ".git" / revision[5:]
            revision = ref.read_text().strip() if ref.resolve().is_relative_to(root / ".git") and ref.is_file() else None
    return {"dataset": "PySASTBench synthetic", "dataset_revision": revision,
            "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
            "experimental": experimental, "label_matching": "CWE/function span; removed or renamed fixed targets use whole-file CWE matching; CWE-78 matches CWE-77",
            "summary": metrics(totals), "by_cwe": {cwe: metrics(group) for cwe, group in groups.items()},
            "fixed_file_alerts": {
                "files_with_any_alert": sum(case.get("total_alerts", 0) > 0 for case in cases if case["variant"] == "fix"),
                "total_alerts": sum(case.get("total_alerts", 0) for case in cases if case["variant"] == "fix"),
                "outside_label_match": sum(case.get("unrelated_alerts", 0) for case in cases if case["variant"] == "fix"),
            },
            "cases": cases, "limitations": [
                "Synthetic labels are accepted as supplied, not independently verified.",
                "Fixed variants may contain unrelated issues; matching is limited to the labelled CWE/function.",
                "Informational notices do not count as vulnerability alerts.",
                "No real-world CVEs, AI flows, SCA, or SBOM accuracy are evaluated here."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True, help="Path to a separately downloaded PySASTBench checkout")
    parser.add_argument("--output", required=True, help="JSON result file")
    parser.add_argument("--include-experimental", action="store_true")
    args = parser.parse_args()
    result = evaluate(args.dataset, args.include_experimental)
    Path(args.output).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"summary": result["summary"], "by_cwe": result["by_cwe"]}, indent=2))
    if result["summary"]["errors"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
