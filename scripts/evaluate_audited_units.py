"""Evaluate exposed developer-audited units, without executing target code."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import subprocess
import urllib.request

from scanner.benchmark import evaluate as tuning_evaluate
from scanner.models import ProjectProfile,ScanContext
from scanner.owasp_benchmark import evaluate as synthetic_evaluate
from scanner.plugins.sast import SASTScanner
from scanner.realworld_audit import check_freeze
from scanner.rule_loader import RuleLoader

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'docs/evaluation/unit-audit-2026-11-13'
FREEZE='54110a461b770cc2734585475381a4c99362b1b9'


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def write(path,value):
    path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')


def compact(f):
    return dict(file_path=f.file_path,line_number=f.line_number,cwe=f.cwe,rule_id=f.rule_id,
                maturity=f.maturity,confidence=f.confidence,evidence_kind=f.evidence_kind,trace=f.trace)


def matches_unit(alert,unit):
    return (alert['file_path']==unit['path'] and alert['line_number']==unit['sink_line']
            and alert['cwe']==unit['cwe'] and alert['evidence_kind']=='static-flow'
            and any(x.get('role')=='source' for x in alert['trace']))


def checked_source(cache,row):
    path=(cache/row['cve_id']/row['role']/row['revision']/row['path']).resolve()
    if not path.is_relative_to(cache.resolve()):
        raise ValueError('Source outside declared cache')
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=row['source_sha256']:
        raise ValueError('Source bytes changed')
    return raw.decode('utf-8-sig')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--skip-synthetic',action='store_true',help='Reuse already-written synthetic results; run audited units only')
    p.add_argument('--fetch-context',action='store_true',help='Fetch missing four pinned package-context files; never run them')
    args=p.parse_args()
    if subprocess.run(['git','diff','--quiet',FREEZE,'--','scanner','rules'],cwd=ROOT).returncode:
        raise ValueError('Detector/rules differ from freeze')
    ledger=ROOT/'docs/evaluation/realworld-2026-11-12'
    inputs={n:read(ledger/n) for n in ['inputs.json','queries.json','github-metadata.json','prior-unit-index.json','manifest.json']}
    if not check_freeze(ledger,inputs):
        raise ValueError('Original metadata changed')
    cases={c['cve_id']:c for c in inputs['manifest.json']['cases'] if c['partition']=='validation'}
    exposure=read(ROOT/'docs/evaluation/research-repair-2026-11-13/validation-exposure.json')['records']
    if set(cases)!={r['cve_id'] for r in exposure}:
        raise ValueError('All and only exposed validation cases are required')
    records=[]
    groups=defaultdict(dict)
    for row in exposure:
        if not any(l['role']==row['role'] and l['path']==row['path'] and l['resolution']['sha']==row['revision'] for l in cases[row['cve_id']]['locations']):
            raise ValueError('Source is not a declared snapshot')
        groups[(row['cve_id'],row['role'],row['revision'])][row['path']]=checked_source(ROOT/'.benchmark-cache/research-validation',row)
    audit=read(OUT/'audit.json')
    for name in ['audit.json','context-exposure.json']:
        frozen=json.loads(subprocess.check_output(['git','show',FREEZE+':docs/evaluation/unit-audit-2026-11-13/'+name],cwd=ROOT,text=True))
        if frozen!=read(OUT/name):
            raise ValueError('Frozen audit/context selection changed')
    units=next(c for c in audit['cases'] if c['cve_id']=='CVE-2021-4315')['units']
    for (cve,role,revision),files in groups.items():
        findings=SASTScanner().scan(ScanContext(files,{},ProjectProfile(),RuleLoader(),{}))
        alerts=[compact(f) for f in findings]
        records.append(dict(cve_id=cve,role=role,revision=revision,files=list(files),alerts=alerts))
    observed=[]
    for u in units:
        row=next(r for r in records if r['cve_id']=='CVE-2021-4315' and r['role']==u['role'] and r['revision']==u['revision'])
        source=next(r for r in exposure if r['cve_id']=='CVE-2021-4315' and r['role']==u['role'])
        if source['source_sha256']!=u['source_sha256']:
            raise ValueError('Audited source identity differs')
        findings=[a for a in row['alerts'] if matches_unit(a,u)]
        observed.append(dict(unit=u,matched_alerts=findings))
    ablations=[]
    for (cve,role,revision),files in groups.items():
        if cve!='CVE-2021-4315':
            continue
        fs=SASTScanner().scan(ScanContext(files,{},ProjectProfile(),RuleLoader(),{'analysis_disabled_features':['interprocedural']}))
        ablations.append(dict(role=role,disabled='interprocedural',alerts=[compact(f) for f in fs]))
    write(OUT/'real-development.json',dict(implementation_revision=FREEZE,independent_labels=False,
           final_test_source_opened=False,source_guided_development=True,records=records,template_units=observed,ablations=ablations,
           original_label_errors_retained=2,
           interpretation='Developer-audited units in exposed source; not unseen real-code accuracy. Original strict metadata reports remain unchanged.'))
    context=[]
    extra=read(OUT/'context-exposure.json')['records']
    if args.fetch_context:
        for row in extra:
            if row['cve_id']!='CVE-2023-29159' or row['path'] not in {'starlette/responses.py','starlette/types.py'} or (row['cve_id'],row['role'],row['revision']) not in groups:
                raise ValueError('Only predeclared exposed context may be fetched')
            root=ROOT/'.benchmark-cache/context-audit'
            path=(root/row['cve_id']/row['role']/row['revision']/row['path']).resolve()
            if not path.is_relative_to(root.resolve()):
                raise ValueError('Context source outside cache')
            if path.exists():
                continue
            url=f"https://raw.githubusercontent.com/{row['repository']}/{row['revision']}/{row['path']}"
            raw=urllib.request.urlopen(url,timeout=30).read(2_000_001)
            if len(raw)>2_000_000 or hashlib.sha256(raw).hexdigest()!=row['source_sha256']:
                raise ValueError('Context bytes differ from frozen receipt')
            path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(raw)
    for (cve,role,revision),files in groups.items():
        if cve!='CVE-2023-29159':
            continue
        files=dict(files)
        for row in extra:
            if row['cve_id']!=cve or row['revision']!=revision or row['role']!=role:
                continue
            files[row['path']]=checked_source(ROOT/'.benchmark-cache/context-audit',row)
        fs=SASTScanner().scan(ScanContext(files,{},ProjectProfile(),RuleLoader(),{}))
        context.append(dict(cve_id=cve,role=role,revision=revision,files=list(files),alerts=[compact(f) for f in fs]))
    write(OUT/'context-after.json',dict(implementation_revision=FREEZE,records=context,final_test_source_opened=False))
    print('Audited unsafe template matches:',sum(bool(u['matched_alerts']) for u in observed if u['unit']['role']=='vul_func'),'/ 2',flush=True)
    print('Audited patched template matches:',sum(bool(u['matched_alerts']) for u in observed if u['unit']['role']=='fix_func'),'/ 2',flush=True)
    if not args.skip_synthetic:
        manifest=read(ROOT/'docs/evaluation/owasp-2026-11-12/split.json')
        for split in ['development','validation','test']:
            result=synthetic_evaluate(ROOT/'.benchmark-cache/BenchmarkPython',manifest,split)
            write(OUT/(split+'.json'),result)
            print(split,result['summary'],flush=True)
        result=tuning_evaluate(ROOT/'.benchmark-cache/PySASTBench')
        write(OUT/'pysastbench.json',result)
        print('pysastbench',result['summary'],flush=True)


if __name__=='__main__':
    main()
