"""Frozen reference-span probes; upstream repair roles are not SAST ground truth."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import urllib.request

from scanner.models import ProjectProfile, ScanContext, Severity
from scanner.plugins.sast import SASTScanner
from scanner.realworld_audit import check_freeze, snippet_digest
from scanner.rule_loader import RuleLoader

FREEZE='bb9fb3092011aec3c5de0af4b28dea9fdc2b4715'
ROOT=Path(__file__).resolve().parents[1]


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def reference_matches(findings,cwes,start,end):
    return [f for f in findings if f['cwe'] in cwes and f['line_number'] is not None
            and start <= f['line_number'] <= end and f['evidence_kind'] != 'coverage-notice']


def validation_cases():
    if subprocess.run(['git','diff','--quiet',FREEZE,'--','scanner','rules'],cwd=ROOT).returncode:
        raise ValueError('Frozen implementation changed')
    ledger=ROOT/'docs/evaluation/realworld-2026-11-12'
    inputs={n:read(ledger/n) for n in ['inputs.json','queries.json','github-metadata.json','prior-unit-index.json','manifest.json']}
    if not check_freeze(ledger,inputs):
        raise ValueError('Original metadata freeze changed')
    return {c['cve_id']:c for c in inputs['manifest.json']['cases'] if c['partition']=='validation'}


def evaluate(cache,exposure):
    cases=validation_cases()
    if set(cases) != {r['cve_id'] for r in exposure['records']}:
        raise ValueError('All and only validation cases must be included')
    records=[]
    for record in exposure['records']:
        c=cases[record['cve_id']]
        locations=[l for l in c['locations'] if l['path']==record['path'] and l['role']==record['role'] and l['resolution']['sha']==record['revision']]
        if not locations:
            raise ValueError('Snapshot is not in frozen validation metadata')
        result={k:record[k] for k in ['cve_id','repository','role','revision','path']}
        result.update(cwes=c['cwes'],labels='Upstream reference metadata; not independently adjudicated',units=[])
        try:
            if 'error' in record:
                raise ValueError(record['error'])
            path=(cache/record['cve_id']/record['role']/record['revision']/record['path']).resolve()
            if not path.is_relative_to(cache):
                raise ValueError('Source outside cache')
            raw=path.read_bytes()
            if hashlib.sha256(raw).hexdigest()!=record['source_sha256']:
                raise ValueError('Cached bytes changed')
            code=raw.decode('utf-8-sig'); lines=code.splitlines()
            result['source_sha256']=record['source_sha256']
            for l in locations:
                if snippet_digest('\n'.join(lines[l['start_line']-1:l['end_line']]))!=l['snippet_sha256']:
                    raise ValueError('Declared function hash differs')
            findings=SASTScanner().scan(ScanContext({record['path']:code},{},ProjectProfile(),RuleLoader(),{}))
            result['alerts']=[dict(rule_id=f.rule_id,cwe=f.cwe,line_number=f.line_number,
                                   confidence=f.confidence,maturity=f.maturity,evidence_kind=f.evidence_kind,
                                   severity=f.severity.value,trace=f.trace) for f in findings]
            result['coverage_notices']=sum(f.severity==Severity.INFO for f in findings)
            result['function_hashes_match']=True
            for l in locations:
                matched=reference_matches(result['alerts'],c['cwes'],l['start_line'],l['end_line'])
                result['units'].append(dict(start_line=l['start_line'],end_line=l['end_line'],
                                             snippet_sha256=l['snippet_sha256'],reference_span_matches=matched))
        except (OSError,UnicodeError,ValueError) as e:
            result['error']=type(e).__name__+': '+str(e)
        records.append(result)
    return dict(implementation_revision=FREEZE,partition='validation',cases=len(cases),snapshots=len(records),
                independent_labels=False,final_test_source_opened=False,records=records,
                snapshot_errors=sum('error' in r for r in records),
                snapshots_with_coverage_notices=sum(r.get('coverage_notices',0)>0 for r in records),
                vulnerable_reference_match_cases=sorted({r['cve_id'] for r in records if r['role']=='vul_func'
                                                         and any(u['reference_span_matches'] for u in r['units'])}),
                fixed_reference_match_cases=sorted({r['cve_id'] for r in records if r['role']=='fix_func'
                                                    and any(u['reference_span_matches'] for u in r['units'])}),
                interpretation='Reference-span observations only. No real-world recall/precision or clean patched-file claims. Full-file static probes lack repository/caller context. No tuning after source exposure in this freeze.')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cache',default=str(ROOT/'.benchmark-cache/research-validation'))
    p.add_argument('--output',default=str(ROOT/'docs/evaluation/research-repair-2026-11-13/real-validation.json'))
    p.add_argument('--fetch',action='store_true',help='Fetch missing pinned validation files, verifying published byte hashes')
    args=p.parse_args()
    exposure=read(ROOT/'docs/evaluation/research-repair-2026-11-13/validation-exposure.json')
    if args.fetch:
        cases=validation_cases()
        cache=Path(args.cache).resolve()
        for r in exposure['records']:
            c=cases.get(r['cve_id'])
            if not c or r['repository']!=c['repository'] or not any(
                    l['path']==r['path'] and l['role']==r['role'] and l['resolution']['sha']==r['revision'] for l in c['locations']):
                raise ValueError('Only declared validation source can be fetched')
            path=(cache/r['cve_id']/r['role']/r['revision']/r['path']).resolve()
            if not path.is_relative_to(cache):
                raise ValueError('Source outside cache')
            if path.exists():
                continue
            url=f"https://raw.githubusercontent.com/{r['repository']}/{r['revision']}/{r['path']}"
            raw=urllib.request.urlopen(url,timeout=30).read(2_000_001)
            if len(raw)>2_000_000 or hashlib.sha256(raw).hexdigest()!=r['source_sha256']:
                raise ValueError('Downloaded bytes differ from published snapshot')
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(raw)
    result=evaluate(Path(args.cache).resolve(),exposure)
    Path(args.output).write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k!='records'},indent=2))


if __name__=='__main__':
    main()
