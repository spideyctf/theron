"""Frozen static final-test probes; never import target applications."""
import argparse
import base64
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import subprocess

from scanner.finding_utils import normalize_findings
from scanner.models import ProjectProfile, ScanContext
from scanner.plugins.sast import SASTScanner
from scanner.realworld_audit import check_freeze, snippet_digest
from scanner.rule_loader import RuleLoader
from scripts.evaluate_real_validation import reference_matches

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs/evaluation/final-validation-2026-11-13'
CACHE = ROOT / '.benchmark-cache/final-realcode'
FREEZE = '4c166e0b179e1ff10a3a432e2bd439765b601a81'


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def checked_path(root, relative):
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError('Path outside declared cache')
    return path


def snapshot_key(row):
    return '/'.join(row[k] for k in ['cve_id', 'role', 'revision', 'path'])


def cases():
    if subprocess.run(['git', 'diff', '--quiet', FREEZE, '--', 'scanner', 'rules'], cwd=ROOT).returncode:
        raise ValueError('Final detector changed; preserve the frozen run')
    ledger = ROOT / 'docs/evaluation/realworld-2026-11-12'
    inputs = {n: read(ledger/n) for n in ['inputs.json', 'queries.json', 'github-metadata.json', 'prior-unit-index.json', 'manifest.json']}
    if not check_freeze(ledger, inputs):
        raise ValueError('Original metadata changed')
    selected = [c for c in inputs['manifest.json']['cases'] if c['partition'] == 'test']
    selection = read(OUT/'selection.json')
    if selection['case_ids'] != [c['cve_id'] for c in selected] or len(selected) != 9:
        raise ValueError('Final membership changed')
    return selected


def stage():
    selected = cases()
    downloaded = read(ROOT/'.benchmark-cache/final-test-downloads.json')
    expected = {(c['cve_id'], l['role'], l['resolution']['sha'], l['path']): c
                for c in selected for l in c['locations']}
    actual = {(r['cve_id'], r['role'], r['revision'], r['path']) for r in downloaded}
    if set(expected) != actual or len(downloaded) != len(actual):
        raise ValueError('All and only declared snapshots required')
    receipts = []
    for row in downloaded:
        record = {k: row[k] for k in ['cve_id', 'repository', 'role', 'revision', 'path']}
        case = expected[(row['cve_id'], row['role'], row['revision'], row['path'])]
        if case['repository'] != row['repository']:
            raise ValueError('Repository differs from manifest')
        record['url'] = row.get('url')
        try:
            if 'error' in row:
                raise ValueError(row['error'])
            if row['encoding'] != 'base64':
                raise ValueError('Expected original base64 transport')
            raw = base64.b64decode(''.join(row['content_base64'].split()), validate=True)
            blob_sha = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            if blob_sha != row['github_blob_sha']:
                raise ValueError('Git blob bytes differ from connector receipt')
            record.update(source_sha256=hashlib.sha256(raw).hexdigest(), github_blob_sha=blob_sha, bytes=len(raw))
            path = checked_path(CACHE/'stage', snapshot_key(row))
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists() and path.read_bytes() != raw:
                raise ValueError('Existing staged bytes changed')
            path.write_bytes(raw)
            lines = raw.decode('utf-8-sig').splitlines()
            record['units'] = [dict(start_line=l['start_line'], end_line=l['end_line'],
                expected_sha256=l['snippet_sha256'],
                actual_sha256=snippet_digest('\n'.join(lines[l['start_line']-1:l['end_line']])))
                for l in case['locations'] if (l['role'], l['resolution']['sha'], l['path']) == (row['role'], row['revision'], row['path'])]
            record['function_hashes_match'] = all(u['expected_sha256'] == u['actual_sha256'] for u in record['units'])
            if not record['function_hashes_match']:
                record['label_error'] = 'Declared function hash differs from pinned source'
        except (ValueError, OSError, UnicodeError) as exc:
            record['error'] = type(exc).__name__ + ': ' + str(exc)
        receipts.append(record)
    write(OUT/'source-exposure.json', dict(implementation_revision=FREEZE, original_partition='test',
        first_exposure_after_protocol_commit='d0b186e', source_now_exposed=True,
        target_code_executed=False, records=receipts))
    print('Staged snapshots:', len(receipts), 'retrieval errors:', sum('error' in r for r in receipts),
          'label errors:', sum('label_error' in r for r in receipts), flush=True)


def compact(f):
    return {k: f.to_dict()[k] for k in ['file_path', 'line_number', 'rule_id', 'cwe', 'severity',
        'confidence', 'maturity', 'evidence_kind', 'trace', 'fingerprint']}


def summarize(records):
    result = dict(snapshots=len(records), scanner_errors=sum(len(r.get('scanner_errors', [])) for r in records),
                  input_errors=sum('error' in r for r in records), label_errors=sum('label_error' in r for r in records),
                  whole_file_alerts=sum(len(r.get('alerts', [])) for r in records))
    for role, name in [('vul_func', 'vulnerable'), ('fix_func', 'patched')]:
        groups = defaultdict(list)
        for r in records:
            if r['role'] == role:
                groups[r['cve_id']].append(r)
        eligible = {c: rows for c, rows in groups.items()
                    if all(not any(k in r for k in ['error', 'label_error']) for r in rows)}
        matched = sorted(c for c, rows in eligible.items() if any(r.get('reference_matches') for r in rows))
        result[name] = dict(total_cases=len(groups), hash_verified_cases=len(eligible),
            reference_match_cases=matched, reference_match_count=len(matched),
            no_reference_match_count=len(eligible)-len(matched),
            excluded_error_cases=sorted(set(groups)-set(eligible)))
    return result


def evaluate():
    selected = {c['cve_id']: c for c in cases()}
    exposure = read(OUT/'source-exposure.json')['records']
    sources = {}
    for r in exposure:
        if 'error' not in r:
            raw = checked_path(CACHE/'stage', snapshot_key(r)).read_bytes()
            if hashlib.sha256(raw).hexdigest() != r['source_sha256']:
                raise ValueError('Frozen input bytes changed')
            sources[snapshot_key(r)] = raw.decode('utf-8-sig')
    for mode in ['isolated', 'grouped']:
        groups = defaultdict(dict)
        for r in exposure:
            if snapshot_key(r) in sources:
                group = (r['cve_id'], r['role'], r['revision'], r['path'] if mode == 'isolated' else '')
                groups[group][r['path']] = sources[snapshot_key(r)]
        alerts = {}
        for (cve, role, revision, _), files in groups.items():
            fs = normalize_findings(SASTScanner().scan(ScanContext(files, {}, ProjectProfile(), RuleLoader(), {})))
            for path in files:
                alerts['/'.join([cve, role, revision, path])] = [compact(f) for f in fs if f.file_path == path]
        records = []
        for r in exposure:
            row = dict(r)
            row['alerts'] = alerts.get(snapshot_key(r), [])
            row['scanner_errors'] = [a for a in row['alerts'] if a['rule_id'] == 'PY-PARSE-001']
            if not any(k in row for k in ['error', 'label_error']):
                row['reference_matches'] = [a for u in row['units'] for a in reference_matches(
                    row['alerts'], selected[r['cve_id']]['cwes'], u['start_line'], u['end_line'])]
            else:
                row['reference_matches'] = None
            records.append(row)
        report = dict(implementation_revision=FREEZE, mode=mode, partition='test', records=records,
            external_upstream_labels=True, independent_alert_adjudication=False, target_code_executed=False,
            interpretation='Original CWE/function-span proxy; patched role is not a clean-file label. Not alert-level precision or independently adjudicated real-world accuracy.',
            summary=summarize(records))
        write(OUT/('theron-'+mode+'.json'), report)
        print(mode, report['summary'], flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['stage', 'evaluate'])
    args = parser.parse_args()
    (stage if args.action == 'stage' else evaluate)()
