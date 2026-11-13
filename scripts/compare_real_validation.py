"""Static real-validation comparison. Never import or execute target code."""
import argparse
import ast
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile

from scanner.models import ProjectProfile, ScanContext
from scanner.plugins.sast import SASTScanner
from scanner.python_project import PythonProject
from scanner.rule_loader import RuleLoader
from scripts.evaluate_real_validation import FREEZE, ROOT, read, reference_matches, validation_cases
from scripts.evaluate_step5 import checked_path, external_records

OUTPUT=ROOT/'docs/evaluation/real-comparison-2026-11-13'
CACHE=ROOT/'.benchmark-cache/real-comparison'
RULE_REV='a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')


def key(r):
    return '/'.join([r['cve_id'],r['role'],r['revision'],r['path']])


def load_sources():
    cases=validation_cases()
    rows=read(ROOT/'docs/evaluation/research-repair-2026-11-13/validation-exposure.json')['records']
    if set(cases)!={r['cve_id'] for r in rows}:
        raise ValueError('All and only validation cases are required')
    sources={}
    cache=ROOT/'.benchmark-cache/research-validation'
    for r in rows:
        if not any(l['role']==r['role'] and l['path']==r['path'] and l['resolution']['sha']==r['revision'] for l in cases[r['cve_id']]['locations']):
            raise ValueError('Snapshot not in frozen validation metadata')
        raw=checked_path(cache,key(r)).read_bytes()
        if sha(raw)!=r['source_sha256']:
            raise ValueError('Snapshot bytes changed')
        if key(r) in sources:
            raise ValueError('Duplicate snapshot')
        sources[key(r)]=raw
    return cases,rows,sources


def stage():
    _,_,sources=load_sources()
    target=CACHE/'stage'
    if target.exists() and any(target.iterdir()):
        raise ValueError('Stage must be empty')
    rules=ROOT/'.benchmark-cache/semgrep-rules'
    if subprocess.check_output(['git','-C',str(rules),'rev-parse','HEAD'],text=True).strip()!=RULE_REV:
        raise ValueError('Rules revision changed')
    if subprocess.check_output(['git','-C',str(rules),'status','--porcelain','--untracked-files=all','--','python'],text=True).strip():
        raise ValueError('Rule bytes changed')
    inventory={}
    def put(name,raw):
        path=checked_path(target,name)
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(raw)
        inventory[name]=sha(raw)
    for name,raw in sources.items():
        put('real-validation/'+name,raw)
    for path in sorted((rules/'python').rglob('*')):
        if path.suffix in {'.yaml','.yml'}:
            put('rules/'+path.relative_to(rules).as_posix(),path.read_bytes())
    write(OUTPUT/'input-provenance.json',dict(implementation_revision=FREEZE,rules_revision=RULE_REV,files=inventory,
                                             source_files=len(sources),final_test_source_opened=False))
    with tarfile.open(CACHE/'inputs.tar','w') as archive:
        for name in inventory:
            archive.add(target/name,arcname=name,recursive=False)
    print('Exact-byte stage:',len(sources),'sources;',len(inventory)-len(sources),'rule files')


def compact(f,prefix):
    return dict(path=prefix+f.file_path,rule_id=f.rule_id,cwes=[f.cwe] if f.cwe else [],
                line_number=f.line_number,severity=f.severity.value,confidence=f.confidence,
                maturity=f.maturity,evidence_kind=f.evidence_kind,trace=f.trace)


def context_inventory(files):
    project=PythonProject(files)
    imports=[]
    for path,code in files.items():
        try:
            tree=ast.parse(code)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            modules=[]
            if isinstance(node,ast.Import):
                modules=[a.name for a in node.names]
            elif isinstance(node,ast.ImportFrom):
                base=project.import_module(path,node.module,node.level)
                modules=[base]+[base+'.'+a.name for a in node.names]
            for module in modules:
                imports.append(dict(file=path,line=node.lineno,module=module,
                                    target=project.modules.get(module),available=bool(project.modules.get(module))))
    return dict(files=len(files),imports=imports,
                available_imports=sum(r['available'] for r in imports),
                unresolved_import_candidates=sum(not r['available'] for r in imports),
                limitation='Import candidates include standard/external libraries and imported symbols; unresolved does not mean a missing local module.')


def compare():
    cases,rows,sources=load_sources()
    provenance=read(OUTPUT/'input-provenance.json')
    for name,digest in provenance['files'].items():
        if sha(checked_path(CACHE/'stage',name).read_bytes())!=digest:
            raise ValueError('Exact-byte stage changed')
    native=read(CACHE/'native-verification.json')
    if not native.get('all_bytes_identical') or native.get('verified_files')!=len(provenance['files']) or native.get('source_files')!=len(sources):
        raise ValueError('Native Linux inventory verification is required')
    bandit_version=subprocess.check_output([str(ROOT/'.benchmark-cache/bandit-venv/Scripts/python.exe'),'-m','bandit','--version'],text=True)
    if bandit_version.splitlines()[0].split()[-1]!='1.9.4':
        raise ValueError('Bandit version changed')
    write(OUTPUT/'environment.json',dict(implementation_revision=FREEZE,bandit_version_output=bandit_version,
          semgrep_version='1.185.0',semgrep_rules_revision=RULE_REV,native_verification=native,
          bandit_flags=['all default tests/severities/confidences','--ignore-nosec','--exit-zero'],
          semgrep_flags=['--metrics=off','--disable-version-check','--no-git-ignore','--no-rewrite-rule-ids','--timeout 10','--jobs 2'],
          timing_limitation='Windows Bandit/Theron and native WSL Semgrep; no speed ranking.'))
    reports={}
    contexts=[]
    for mode in ['isolated','grouped']:
        groups=defaultdict(dict)
        for r in rows:
            group=(r['cve_id'],r['role'],r['revision'],r['path'] if mode=='isolated' else '')
            groups[group][r['path']]=sources[key(r)].decode('utf-8-sig')
        alerts=[]
        for (cve,role,revision,_),files in groups.items():
            prefix='/'.join([cve,role,revision])+'/'
            findings=SASTScanner().scan(ScanContext(files,{},ProjectProfile(),RuleLoader(),{}))
            alerts.extend(compact(f,prefix) for f in findings)
            if mode=='grouped':
                contexts.append(dict(cve_id=cve,role=role,revision=revision,**context_inventory(files)))
        reports['theron-'+mode]=dict(engine='theron-'+mode,covered_files=len(sources),alerts=alerts,
                                     errors=[a for a in alerts if a['rule_id']=='PY-PARSE-001'])
    for tool,version in [('bandit','1.9.4'),('semgrep','1.185.0')]:
        path=CACHE/(tool+'.json')
        raw=read(path)
        if tool=='semgrep' and raw.get('version')!=version:
            raise ValueError('Semgrep version changed')
        report=external_records(raw,tool,'real-validation',sources)
        report.update(version=version,raw_report_sha256=sha(path.read_bytes()))
        reports[tool]=report
    previous=read(ROOT/'docs/evaluation/research-repair-2026-11-13/real-validation.json')
    prior={key(r):r for r in previous['records']}
    unit_outcomes={}
    for tool,report in reports.items():
        outcomes=[]
        for r in rows:
            prior_record=prior[key(r)]
            result=dict(cve_id=r['cve_id'],role=r['role'],revision=r['revision'],path=r['path'])
            if 'error' in prior_record:
                result.update(label_error=prior_record['error'],reference_matches=None)
            else:
                alerts=[dict(a,cwe=cwe,evidence_kind=a.get('evidence_kind','static-baseline'))
                        for a in report['alerts'] if a['path']==key(r) for cwe in a.get('cwes',[])]
                matched=[a for unit in prior_record['units'] for a in reference_matches(
                    alerts,cases[r['cve_id']]['cwes'],unit['start_line'],unit['end_line'])]
                result.update(reference_matches=matched)
            outcomes.append(result)
        unit_outcomes[tool]=outcomes
        report['reference_outcomes']=outcomes
        write(OUTPUT/(tool+'.json'),report)
    summary=dict(implementation_revision=FREEZE,cases=len(cases),snapshots=len(sources),
                 original_label_errors=sum('error' in r for r in previous['records']),
                 independent_labels=False,final_test_source_opened=False,tools={})
    for tool,r in reports.items():
        summary['tools'][tool]=dict(covered_files=r['covered_files'],alerts=len(r['alerts']),scanner_errors=len(r['errors']),
            vulnerable_reference_match_cases=sorted({u['cve_id'] for u in r['reference_outcomes'] if u['role']=='vul_func' and u['reference_matches']}),
            fixed_reference_match_cases=sorted({u['cve_id'] for u in r['reference_outcomes'] if u['role']=='fix_func' and u['reference_matches']}))
    summary['context_groups']=len(contexts)
    summary['available_import_candidates']=sum(c['available_imports'] for c in contexts)
    write(OUTPUT/'context-inventory.json',contexts)
    write(OUTPUT/'summary.json',summary)
    print(json.dumps(summary,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=['stage','compare'])
    args=p.parse_args()
    stage() if args.mode=='stage' else compare()
