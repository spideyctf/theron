"""Probe a declared development sample as static text, never import target code.

This records alerts, not research accuracy or independently validated labels.
Sources live under CACHE/CVE/ROLE/REPOSITORY_PATH at the manifest revisions.
"""
import argparse
import hashlib
import json
from pathlib import Path

from scanner.python_analysis import analyze_python
from scanner.realworld_audit import snippet_digest


def probe(manifest, selected_ids, cache_root):
    cases = {c['cve_id']: c for c in manifest['cases']}
    if not selected_ids or len(selected_ids) != len(set(selected_ids)):
        raise ValueError('Select a nonempty unique development sample')
    selected = [cases[cve] for cve in selected_ids]
    if any(c['partition'] != 'development' for c in selected):
        raise ValueError('This probe permits only the frozen development partition')
    root = Path(cache_root).resolve()
    records = []
    for case in selected:
        for role in ['vul_func', 'fix_func']:
            paths = sorted({l['path'] for l in case['locations'] if l['role'] == role})
            for path in paths:
                source_path = (root/case['cve_id']/role/path).resolve()
                if not source_path.is_relative_to(root):
                    raise ValueError('Source path escapes cache')
                record = dict(cve_id=case['cve_id'],role=role,path=path,
                              revisions=sorted({l['resolution']['sha'] for l in case['locations'] if l['role']==role and l['path']==path}))
                try:
                    source = source_path.read_text(encoding='utf-8')
                    record['source_sha256'] = hashlib.sha256(source.encode()).hexdigest()
                    lines = source.splitlines()
                    for location in case['locations']:
                        if location['role'] == role and location['path'] == path:
                            span = '\n'.join(lines[location['start_line']-1:location['end_line']])
                            if snippet_digest(span) != location['snippet_sha256']:
                                raise ValueError('Declared function span/hash differs from cached source')
                    record['declared_function_hashes_match'] = True
                    record['modes'] = {}
                    for mode, experimental in [('default',False), ('experimental',True)]:
                        findings = analyze_python(path, source, module='sast', include_experimental=experimental)
                        record['modes'][mode] = [dict(rule_id=f.rule_id,cwe=f.cwe,line_number=f.line_number,
                                                       confidence=f.confidence,maturity=f.maturity,
                                                       evidence_kind=f.evidence_kind,trace=f.trace) for f in findings]
                except (OSError, UnicodeError, ValueError) as error:
                    record['error'] = type(error).__name__
                records.append(record)
    return dict(membership_sha256=manifest['membership_sha256'],selected_ids=selected_ids,
                matching='Raw per-file alerts; source-to-sink target adjudication is recorded separately',
                independent_labels=False,scorable_cases=0,records=records)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest',required=True)
    p.add_argument('--selection',required=True,help='JSON list of development CVE identifiers')
    p.add_argument('--cache-root',required=True)
    p.add_argument('--output',required=True)
    args=p.parse_args()
    result=probe(json.loads(Path(args.manifest).read_text()),json.loads(Path(args.selection).read_text()),args.cache_root)
    import scanner.python_analysis as detector
    result['detector_source_sha256']=hashlib.sha256(Path(detector.__file__).read_text(encoding='utf-8').encode()).hexdigest()
    Path(args.output).write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'files':len(result['records']),'errors':sum('error' in r for r in result['records']),
                      'detector_source_sha256':result['detector_source_sha256']}))


if __name__=='__main__':
    main()
