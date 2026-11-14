"""Pinned real-source compatibility pilot; never imports or executes target code."""
import base64
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import time
from unittest.mock import patch

import requests
from scanner.correlation import CONFIG_NAMES, correlate
from scanner.finding_utils import normalize_findings, partition_findings
from scanner.models import ProjectProfile, ScanContext, ScanResult
from scanner.plugins.sast import SASTScanner
from scanner.plugins.sca import SCAScanner
from scanner.rule_loader import RuleLoader

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs/evaluation/real-correlation-2026-11-15'
CACHE = ROOT / '.benchmark-cache/real-correlation-2026-11-15'
FREEZE = 'b8ec32f'


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def collect():
    records = json.loads((CACHE / 'fetch-receipts.json').read_text())
    files, receipts = {}, []
    for record in records:
        receipt = {k: record[k] for k in ('repository', 'revision', 'path', 'sha', 'size', 'status')}
        try:
            if record['status'] != 'fetched':
                raise ValueError(record.get('error', 'fetch failed'))
            raw = base64.b64decode((CACHE / 'blobs' / (record['sha'] + '.b64')).read_text(), validate=False)
            assert len(raw) == record['size'], 'size mismatch'
            assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == record['sha'], 'blob mismatch'
            source = raw.decode('utf-8-sig')
            receipt.update(status='verified', sha256=hashlib.sha256(raw).hexdigest())
            files.setdefault(record['repository'], {})[record['path']] = source
        except (ValueError, AssertionError, OSError, UnicodeError) as exc:
            receipt.update(status='error', error=str(exc))
        receipts.append(receipt)
    write(OUT / 'source-receipts.json', receipts)
    return files, receipts


def main():
    subprocess.run(['git', 'diff', '--exit-code', FREEZE, '--', 'scanner'], cwd=ROOT, check=True, capture_output=True)
    files_by_repo, receipts = collect()
    selection = json.loads((OUT / 'selection.json').read_text())
    results, transport = [], []
    original_post = requests.post

    def recorded_post(url, **kwargs):
        row = dict(url=url, payload=kwargs.get('json'), queried_at=datetime.now(timezone.utc).isoformat())
        try:
            response = original_post(url, **kwargs)
            row.update(status_code=response.status_code, body=response.json())
            return response
        except Exception as exc:
            row['error'] = str(exc)
            raise
        finally:
            transport.append(row)

    for row in selection['records']:
        if row['selection_status'] != 'selected':
            continue
        name = row['repository']
        started = time.perf_counter()
        files = files_by_repo.get(name, {})
        record = dict(repository=name, revision=row['revision'], expected_files=len(row['files']), collected_files=len(files))
        try:
            assert len(files) == len(row['files']), 'incomplete collection; scan not treated as complete'
            context = ScanContext(files, {}, ProjectProfile(), RuleLoader(), {})
            sast = SASTScanner().scan(context)
            sca = SCAScanner()
            before = len(transport)
            with patch('scanner.plugins.sca.requests.post', recorded_post):
                dependencies = sca.scan(context)
            record['osv_transport_records'] = list(range(before, len(transport)))
            declarations = sca._parse_all_manifests(files)
            record['declarations'] = [dict(name=n, declared_version=v, source=p, exact_version=sca._exact_version(v)) for n, v, p in declarations]
            original = ScanResult(repo_full_name=name, branch=row['revision'], commit_sha=row['revision'], files_scanned=len(files),
                                  modules_run=['sast', 'sca'], findings=normalize_findings(sast + dependencies))
            partition_findings(original)
            baseline = [f.to_dict() for f in original.findings + original.context_findings]
            disabled = deepcopy(original)
            correlate(disabled, files, enabled=False)
            assert [f.to_dict() for f in disabled.findings + disabled.context_findings] == baseline
            modes = {}
            for mode in ('code_only', 'dependency_only', 'code_dependency', 'combined'):
                result = deepcopy(original)
                modules = {'sast', 'coverage'} if mode == 'code_only' else {'sca'} if mode == 'dependency_only' else {'sast', 'coverage', 'sca'}
                result.findings = [f for f in result.findings if f.module in modules]
                result.context_findings = [f for f in result.context_findings if f.module in modules]
                result.modules_run = sorted(modules)
                inputs = {p: s for p, s in files.items() if mode == 'combined' or Path(p).name not in CONFIG_NAMES}
                if mode == 'code_only':
                    inputs = {p: s for p, s in inputs.items() if p.endswith('.py')}
                elif mode == 'dependency_only':
                    inputs = {p: s for p, s in inputs.items() if not p.endswith('.py')}
                correlate(result, inputs)
                modes[mode] = dict(groups=result.correlation_groups, resolutions=result.correlation_resolutions,
                                   application_findings=len(result.findings), context_findings=len(result.context_findings),
                                   vulnerability_findings=result.summary['vulnerability_findings'])
                if mode == 'combined':
                    assert [f.to_dict() for f in result.findings + result.context_findings] == baseline
                    assert result.summary['vulnerability_findings'] == disabled.summary['vulnerability_findings']
            record.update(status='complete', modes=modes, correlation_preserves_findings=True,
                          findings=[{k: f.to_dict().get(k) for k in ('fingerprint', 'rule_id', 'file_path', 'line_number', 'severity', 'scope', 'module', 'title')} for f in original.findings + original.context_findings])
        except Exception as exc:
            record.update(status='error', error=f'{type(exc).__name__}: {exc}')
        record['seconds'] = round(time.perf_counter() - started, 3)
        results.append(record)
        print(name, record['status'], record['seconds'], flush=True)
        write(OUT / 'osv-responses.json', transport)
        write(OUT / 'results.json', dict(implementation_revision=FREEZE, evaluated_at=datetime.now(timezone.utc).isoformat(),
            driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), records=results,
            ablations='Same frozen normalized SAST/SCA findings projected by module; only correlation inputs vary. No repeated live OSV requests.',
            independent_labels=False, review_benefit_measured=False, target_code_executed=False))
    assert len(results) == len(selection['selected'])
    assert all(r['status'] == 'complete' for r in results), 'incomplete repositories retained in results'


if __name__ == '__main__':
    main()
