"""Static-only OWASP BenchmarkPython evaluation; never executes corpus applications.

Protocol and split assignments are explicit artifacts. Defaults preserve all categories,
including unsupported ones. This is our adapter, not the official OWASP scorecard.
"""
import argparse
import ast
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time

from scanner.models import ProjectProfile, ScanContext, Severity
from scanner.plugins.sast import SASTScanner
from scanner.rule_loader import RuleLoader
from scanner import python_analysis


PROTOCOL = "theron-owasp-v3"
SEED = "theron-2026-11-12-v1"
# Pinned rule-semantic mappings, declared before validation/test evaluation. Bandit
# labels weak hashes as general cryptography CWE-327, whereas OWASP uses CWE-328.
# Do not silently score those true detections as unsupported. Imports are not sinks.
BANDIT_CWES = {'B102': 'CWE-94', 'B307': 'CWE-94', 'B303': 'CWE-328',
               'B324': 'CWE-328', 'B311': 'CWE-330'}
BANDIT_CWES.update({f'B{i}': 'CWE-611' for i in range(313, 321)})


def sha(data):
    return hashlib.sha256(data).hexdigest()


class FamilyNormalizer(ast.NodeTransformer):
    """Group constant/name-renamed variants without consulting vulnerability labels.

Not a semantic clone detector: the residual similarity threat must be disclosed.
"""
    def visit_Constant(self, node):
        return ast.Constant(value="constant")

    def visit_Name(self, node):
        return ast.Name(id="identifier", ctx=node.ctx)

    def visit_arg(self, node):
        return ast.arg(arg="argument", annotation=self.visit(node.annotation) if node.annotation else None)

    def visit_FunctionDef(self, node):
        node.name = "function"
        return self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        node.name = "class"
        return self.generic_visit(node)

    def visit_Attribute(self, node):
        node.attr = re.sub(r"BenchmarkTest\d+", "test", node.attr)
        return self.generic_visit(node)


def family_digest(content):
    tree = ast.parse(content)
    # Drop module/function docstrings, which otherwise create superficial families.
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant) and isinstance(node.body[0].value.value, str):
                node.body.pop(0)
    return sha(ast.dump(FamilyNormalizer().visit(tree), include_attributes=False).encode())


def git_revision(root):
    result = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else None


def prepare(root):
    root = Path(root)
    labels = root / "expectedresults-0.1.csv"
    cases = []
    for row in csv.reader(labels.read_text(encoding="utf-8-sig").splitlines()):
        if not row or row[0].startswith("#"):
            continue
        name, category, vulnerable, cwe = (cell.strip() for cell in row[:4])
        if not re.fullmatch(r"BenchmarkTest\d+", name) or vulnerable not in {"true", "false"} or not cwe.isdigit():
            raise ValueError("Malformed OWASP label")
        path = f"testcode/{name}.py"
        raw = (root / path).read_bytes()
        family = family_digest(raw.decode("utf-8-sig"))
        routes = set(re.findall(r"/benchmark/([^/]+)/BenchmarkTest[0-9]+", raw.decode('utf-8-sig')))
        if len(routes) != 1:
            raise ValueError("Expected one route-template family per case")
        cases.append(dict(case=name, path=path, category=category, cwe=f"CWE-{cwe}",
                          vulnerable=vulnerable == "true", source_sha256=sha(raw), ast_family=family,
                          route_family=next(iter(routes))))
    if len({c['case'] for c in cases}) != len(cases):
        raise ValueError("Duplicate case labels")
    # This case was inspected during dataset suitability review, before split creation.
    # Keep its entire normalized family in development and record that exception.
    # Connected components keep both upstream route templates and exact normalized
    # AST duplicates together. Hashing individual generated files is too permissive.
    parents = {c['route_family']: c['route_family'] for c in cases}
    def find(key):
        while parents[key] != key:
            key = parents[key]
        return key
    first = {}
    for case in cases:
        previous = first.setdefault(case['ast_family'], case['route_family'])
        a, b = sorted((find(previous), find(case['route_family'])))
        parents[b] = a
    members = defaultdict(set)
    for route in parents:
        members[find(route)].add(route)
    for case in cases:
        family = sha('|'.join(sorted(members[find(case['route_family'])])).encode())
        case['family'] = family
    inspected = next((c['family'] for c in cases if c['case'] == "BenchmarkTest00001"), None)
    # Balance case counts without breaking a family or consulting detector outcomes.
    # Only 24 coarse templates exist, so random per-group buckets can give an 8-case test set.
    sizes = Counter(c['family'] for c in cases)
    assignments = {inspected: 'development'} if inspected else {}
    used = Counter(development=sizes.get(inspected, 0), validation=0, test=0)
    targets = dict(development=len(cases)*.6, validation=len(cases)*.2, test=len(cases)*.2)
    for family in sorted(sizes, key=lambda f: (-sizes[f], sha(f'{SEED}:{f}'.encode()))):
        if family in assignments:
            continue
        split = max(targets, key=lambda s: targets[s] - used[s])
        assignments[family] = split
        used[split] += sizes[family]
    for case in cases:
        case['split'] = assignments[case['family']]
    return dict(protocol=PROTOCOL, seed=SEED, dataset="OWASP BenchmarkPython", revision=git_revision(root),
                labels_sha256=sha(labels.read_bytes()), license="GPL-3.0 (upstream; code not redistributed)",
                grouping="Connected components of upstream route templates and normalized AST duplicates; groups never span splits",
                inspected_before_split=["BenchmarkTest00001"], cases=cases,
                support_sha256={p.relative_to(root).as_posix(): sha(p.read_bytes()) for p in sorted((root / 'helpers').rglob('*.py'))},
                counts=dict(Counter(c['split'] for c in cases)), families=len({c['family'] for c in cases}))


def load_files(root, manifest, split):
    root = Path(root)
    if sha((root / "expectedresults-0.1.csv").read_bytes()) != manifest['labels_sha256']:
        raise ValueError("Dataset labels changed")
    selected = [c for c in manifest['cases'] if c['split'] == split]
    if not selected:
        raise ValueError("Empty evaluation split")
    files = {}
    expected = {c['path']: c['source_sha256'] for c in selected} | manifest['support_sha256']
    for path, expected_sha in expected.items():
        target = (root / path).resolve()
        if not target.is_relative_to(root.resolve()) or not target.is_file():
            raise ValueError("Unsafe or missing dataset file")
        raw = target.read_bytes()
        if sha(raw) != expected_sha:
            raise ValueError(f"Dataset source changed: {path}")
        files[path] = raw.decode('utf-8-sig')
    return files, selected


def rates(s):
    tp, fn, fp, tn = (s.get(k, 0) for k in ('tp', 'fn', 'fp', 'tn'))
    return dict(tp=tp, fn=fn, fp=fp, tn=tn, errors=s.get('errors', 0),
                precision=tp/(tp+fp) if tp+fp else None,
                recall=tp/(tp+fn) if tp+fn else None,
                f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None,
                false_positive_rate=fp/(fp+tn) if fp+tn else None)


def evaluate(root, manifest, split, ablation=None, bandit_json=None, semgrep_json=None):
    files, cases = load_files(root, manifest, split)
    start = time.perf_counter()
    errors, notices = [], []
    if bandit_json and semgrep_json:
        raise ValueError('Choose one external baseline report')
    if semgrep_json:
        raw = json.loads(Path(semgrep_json).read_text(encoding='utf-8-sig'))
        alerts = []
        for finding in raw['results']:
            match = re.search(r'(testcode|helpers)/[^/]+\.py$', finding['path'].replace('\\', '/'))
            if not match:
                continue
            metadata = finding.get('extra', {}).get('metadata', {})
            cwes = set(re.findall(r'CWE-\d+', json.dumps(metadata.get('cwe', []))))
            # The same weak-hash category normalization used for Bandit, scoped
            # to hashing rule IDs instead of treating every CWE-327 cipher as a hash.
            if 'CWE-327' in cwes and re.search(r'(insecure|weak).*(hash|md5|sha1)', finding['check_id'], re.I):
                cwes.add('CWE-328')
            alerts.append(dict(file_path=match.group(), line_number=finding['start']['line'],
                               cwes=sorted(cwes), cwe=next(iter(sorted(cwes)), None), rule_id=finding['check_id']))
        for error in raw.get('errors', []):
            path = error.get('path') or ''
            if path:
                errors.append(path.replace('\\', '/').rsplit('/', 1)[-1])
            notices.append({'type': str(error.get('type', 'unknown')), 'file_path': path,
                            'level': str(error.get('level', 'unknown'))})
        engine = 'semgrep'
    elif bandit_json:
        raw = json.loads(Path(bandit_json).read_text(encoding='utf-8-sig'))
        alerts = []
        for finding in raw['results']:
            match = re.search(r'(testcode|helpers)/[^/]+\.py$', finding['filename'].replace('\\', '/'))
            if not match:
                continue
            reported = f"CWE-{finding.get('issue_cwe', {}).get('id')}"
            alerts.append(dict(file_path=match.group(), line_number=finding['line_number'],
                               cwe=BANDIT_CWES.get(finding['test_id'], reported),
                               reported_cwe=reported, rule_id=finding['test_id']))
        # A file with a baseline parse error must not become a true negative.
        errors = [e['filename'].replace('\\', '/').rsplit('/', 1)[-1] for e in raw.get('errors', [])]
        engine = 'bandit'
    else:
        ctx = ScanContext(files=files, repo_info={}, project_profile=ProjectProfile(), rule_loader=RuleLoader(),
                          config={'analysis_disabled_features': [ablation] if ablation else []})
        findings = SASTScanner().scan(ctx)
        notices = [f.to_dict() for f in findings if f.severity == Severity.INFO]
        alerts = [f.to_dict() for f in findings if f.severity != Severity.INFO]
        errors = [Path(f.file_path).name for f in findings if f.rule_id == 'PY-PARSE-001']
        engine = 'theron'
    groups = defaultdict(Counter)
    outcomes = []
    for case in cases:
        file_alerts = [a for a in alerts if a['file_path'] == case['path']]
        # Exact CWE, plus the documented child used by Bandit's weak-random rule.
        accepted = {case['cwe']} | ({'CWE-338'} if case['cwe'] == 'CWE-330' else set())
        matched = [a for a in file_alerts if accepted.intersection(a.get('cwes', [a['cwe']]))]
        outcome = ('tp' if matched else 'fn') if case['vulnerable'] else ('fp' if matched else 'tn')
        if Path(case['path']).name in errors:
            outcome = 'errors'
        groups[case['cwe']][outcome] += 1
        outcomes.append(dict(case=case['case'], cwe=case['cwe'], family=case['family'], vulnerable=case['vulnerable'],
                             outcome=outcome, matched_rules=sorted({a['rule_id'] for a in matched}),
                             file_alerts=len(file_alerts), unmatched_alerts=len(file_alerts)-len(matched)))
    total = sum(groups.values(), Counter())
    return dict(protocol=PROTOCOL, split=split, engine=engine, ablation=ablation,
                dataset_revision=manifest['revision'], scanner_revision=git_revision(Path(__file__).parent.parent),
                analyzer_sha256=sha(Path(python_analysis.__file__).read_bytes()),
                adapter_sha256=sha(Path(__file__).read_bytes()),
                elapsed_seconds=round(time.perf_counter()-start, 4),
                timing_scope='JSON scoring only' if bandit_json or semgrep_json else 'SAST collection already loaded; analysis and scoring',
                summary=rates(total), by_cwe={k: rates(v) for k,v in sorted(groups.items())},
                coverage_notices=notices, total_alerts=len(alerts), cases=outcomes,
                bandit_rule_mappings=BANDIT_CWES if bandit_json else None,
                baseline_report_sha256=sha(Path(bandit_json or semgrep_json).read_bytes()) if bandit_json or semgrep_json else None,
                matching='Labelled file + exact CWE; CWE-338 accepted under parent CWE-330. Unmatched alerts retained.',
                limitations=['Synthetic corpus; not real-world validation or the official OWASP scorecard.',
                             'Normalized AST grouping reduces but cannot eliminate template similarity across splits.',
                             'File/CWE matching can count an unrelated defect with the same CWE; manual adjudication remains needed.',
                             'All labelled categories included, including unsupported categories; not alert-level precision.'])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dataset', required=True)
    p.add_argument('--manifest', required=True)
    p.add_argument('--prepare', action='store_true')
    p.add_argument('--split', choices=['development', 'validation', 'test'], default='development')
    p.add_argument('--output')
    p.add_argument('--ablation', choices=['interprocedural', 'local_imports', 'sanitizers'])
    p.add_argument('--bandit-json')
    p.add_argument('--semgrep-json')
    p.add_argument('--stage-dir', help='Write exactly one split plus shared helpers for external static tools, then exit')
    args = p.parse_args()
    if args.prepare:
        manifest = prepare(args.dataset)
        Path(args.manifest).write_text(json.dumps(manifest, indent=2)+'\n', encoding='utf-8')
        print(json.dumps({k:v for k,v in manifest.items() if k not in {'cases', 'support_sha256'}}, indent=2))
    else:
        manifest = json.loads(Path(args.manifest).read_text())
        if args.stage_dir:
            target = Path(args.stage_dir)
            if target.exists() and any(target.iterdir()):
                p.error('Stage directory must be empty to prevent stale cross-split files')
            files, _ = load_files(args.dataset, manifest, args.split)
            for name, content in files.items():
                path = target / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding='utf-8')
            print(f'Staged {len(files)} files for {args.split}')
            return
        if not args.output:
            p.error('--output required for evaluation')
        result = evaluate(args.dataset, manifest, args.split, args.ablation, args.bandit_json, args.semgrep_json)
        Path(args.output).write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
        print(json.dumps({'engine':result['engine'], 'split':args.split, 'summary':result['summary']}, indent=2))


if __name__ == '__main__':
    main()
