"""Development-exposed Office Word replay with its original uv lock; not a holdout."""
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

from scanner.correlation import correlate
from scanner.finding_utils import normalize_findings, partition_findings
from scanner.models import ProjectProfile, ScanContext, ScanResult
from scanner.plugins.sast import SASTScanner
from scanner.plugins.sca import SCAScanner
from scanner.rule_loader import RuleLoader

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / '.benchmark-cache/real-correlation-2026-11-15/blobs'
OUT = ROOT / 'docs/evaluation/lock-entrypoints-development-2026-11-15'
REPO = 'GongRzhe/Office-Word-MCP-Server'
LOCK_SHA = 'baa64d413c5a190c8c6dbef30754b59195612c31'


def write(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def main():
    selection = json.loads((ROOT / 'docs/evaluation/real-correlation-2026-11-15/selection.json').read_text())
    row = next(r for r in selection['records'] if r['repository'] == REPO)
    inputs = row['files'] + [dict(path='uv.lock', sha=LOCK_SHA, size=85820)]
    files, receipts = {}, []
    for item in inputs:
        raw = base64.b64decode((CACHE / (item['sha'] + '.b64')).read_text())
        assert len(raw) == item['size']
        assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == item['sha']
        files[item['path']] = raw.decode('utf-8-sig')
        receipts.append(dict(path=item['path'], git_blob_sha=item['sha'], sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw)))
    OUT.mkdir(parents=True, exist_ok=True)
    scanner = SCAScanner()
    transport = []
    original = scanner._query_osv

    def query(name, version, ecosystem):
        record = dict(package=name, version=version, ecosystem=ecosystem, queried_at=datetime.now(timezone.utc).isoformat())
        try:
            records = original(name, version, ecosystem)
            record.update(status='complete', records=records)
            return records
        except Exception as exc:
            record.update(status='error', error=str(exc))
            raise
        finally:
            transport.append(record)

    scanner._query_osv = query
    context = ScanContext(files, {}, ProjectProfile(), RuleLoader(), {})
    print('Running source-only development replay and live OSV lock-inventory queries', flush=True)
    findings = SASTScanner().scan(context) + scanner.scan(context)
    result = ScanResult(repo_full_name=REPO, branch=row['revision'], commit_sha=row['revision'],
        files_scanned=len(files), modules_run=['sast', 'sca'], findings=normalize_findings(findings))
    partition_findings(result)
    before = [f.to_dict() for f in result.findings + result.context_findings]
    correlate(result, files)
    assert before == [f.to_dict() for f in result.findings + result.context_findings]
    transport.sort(key=lambda r: (r['ecosystem'], r['package'], r['version']))
    write('osv-records.json', transport)
    write('source-receipts.json', dict(repository=REPO, revision=row['revision'], records=receipts))
    write('results.json', dict(implementation_revision=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        development_exposed=True, independent_labels=False, target_code_executed=False,
        note='Lock-inventory advisory candidates, not confirmed application vulnerabilities. Original machine-specific MCP launch remains unresolved.',
        query_count=len(transport), completed_queries=sum(r['status']=='complete' for r in transport),
        advisory_candidates=sum(bool(f.dependency) for f in result.findings + result.context_findings),
        correlation_preserves_findings=True, result=result.to_dict(), sbom=scanner.generate_sbom(files, REPO)))
    print('Queries:', len(transport), 'completed:', sum(r['status']=='complete' for r in transport),
          'advisory candidates:', sum(bool(f.dependency) for f in result.findings + result.context_findings), flush=True)
    assert all(r['status'] == 'complete' for r in transport), 'OSV failures retained; not a complete dependency result'


if __name__ == '__main__':
    main()
