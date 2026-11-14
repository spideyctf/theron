"""Application source observations for advisory triage; never exploit confirmation."""
import ast
import hashlib
from pathlib import PurePosixPath
from scanner.correlation_tools import distribution_claims, canonical, resolve
from scanner.finding_utils import finding_scope

# Explicit import-name contracts, not authenticated distribution ownership.
IMPORT_NAMES = {'python-dotenv': 'dotenv', 'python-docx': 'docx', 'pyyaml': 'yaml',
                'pillow': 'PIL', 'beautifulsoup4': 'bs4'}


def annotate_usage(findings, files):
    advisory_findings = [f for f in findings if f.dependency]
    if not advisory_findings:
        return
    claims = distribution_claims(files)
    paths = sorted(p for p in files if p.endswith('.py'))
    parsed, failures, observations = 0, [], []
    for path in paths[:200]:
        try:
            tree = ast.parse(files[path], filename=path)
        except (SyntaxError, RecursionError):
            failures.append(path)
            continue
        parsed += 1
        bindings = {}
        import_lines = {}
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    bindings[alias.asname or alias.name.split('.')[0]] = alias.name if alias.asname else alias.name.split('.')[0]
                    import_lines[alias.asname or alias.name.split('.')[0]] = node.lineno
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                for alias in node.names:
                    if alias.name != '*':
                        bindings[alias.asname or alias.name] = node.module + '.' + alias.name
                        import_lines[alias.asname or alias.name] = node.lineno
        imports = [(name, value, import_lines[name]) for name, value in bindings.items()]
        # Any observed reassignment blocks a binding, even when path/scope uncertain.
        writes = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del))}
        writes.update(n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)) and node not in tree.body:
                writes.update(a.asname or a.name.split('.')[0] for a in node.names)
            if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
                root=node.value
                while isinstance(root, ast.Attribute):root=root.value
                if isinstance(root, ast.Name):writes.add(root.id)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                writes.update(a.arg for a in node.args.posonlyargs + node.args.args + node.args.kwonlyargs)
                if node.args.vararg:writes.add(node.args.vararg.arg)
                if node.args.kwarg:writes.add(node.args.kwarg.arg)
        calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                root = node.func
                while isinstance(root, ast.Attribute):root = root.value
                if isinstance(root, ast.Name) and root.id not in writes:
                    symbol = resolve(node.func, bindings)
                    if symbol:calls.append(dict(symbol=symbol, file_path=path, line_number=node.lineno, scope=finding_scope(path)))
        observations.append((path, imports, calls))
    for finding in advisory_findings:
        dependency = finding.dependency
        package = canonical(dependency['package'])
        roots = [root for root, owners in claims.items() if len(owners) == 1 and
                 canonical(owners[0]['package']) == package and owners[0]['version'] == dependency['version']]
        basis = 'collected_distribution_record_claim'
        if not roots:
            candidate = IMPORT_NAMES.get(package, package)
            roots = [candidate] if candidate.isidentifier() else []
            basis = 'documented_import_name_contract' if package in IMPORT_NAMES else 'same_name_import_candidate'
        imports, calls = [], []
        shadowed = []
        for root in roots:
            if any(PurePosixPath(p).stem.casefold() == root.casefold() or root.casefold() in [part.casefold() for part in PurePosixPath(p).parts[:-1]] for p in paths):
                shadowed.append(root)
                continue
            for path, declarations, observed_calls in observations:
                for _, name, line in declarations:
                    if name.split('.')[0] == root:
                        imports.append(dict(file_path=path, line_number=line, symbol=name, scope=finding_scope(path)))
                calls.extend(c for c in observed_calls if c['symbol'].split('.')[0] == root)
        app_calls = [c for c in calls if c['scope'] == 'application']
        app_imports = [i for i in imports if i['scope'] == 'application']
        status = 'direct_api_call_observed' if app_calls else 'import_only_observed' if app_imports else 'no_direct_usage_observed'
        if not roots or shadowed:status = 'module_ownership_unresolved'
        evidence_paths = {i['file_path'] for i in imports + calls}
        dependency['application_review'] = dict(status=status, attribution_basis=basis,
            imports=imports[:64], calls=calls[:64], imports_observed=len(imports), calls_observed=len(calls),
            evidence_truncated=len(imports)>64 or len(calls)>64, shadowed_roots=shadowed,
            coverage=dict(python_files=len(paths), parsed=parsed, parse_failures=failures, file_limit=200,
                          truncated=len(paths)>200),
            source_text_sha256={p:hashlib.sha256(files[p].encode()).hexdigest() for p in sorted(evidence_paths)},
            affected_behavior_verified=False, vulnerability_confirmed=False,
            limitations=['Imports and syntactic calls do not prove startup, branch feasibility or affected-function use.',
                         'No direct usage observed does not exclude transitive dependencies, callbacks, dynamic imports or other deployments.',
                         'Import-name contracts and record claims do not authenticate ownership or installation.',
                         'These are bounded source observations, not runtime tests or independent vulnerability labels.'])
