"""Separate source-guided checks, controlled correlation study and live OSV receipts."""
import argparse
from collections import defaultdict
import hashlib
from pathlib import Path
import subprocess
import time

from scanner.models import ScanContext,ProjectProfile
from scanner.plugins.sast import SASTScanner
from scanner.plugins.sca import SCAScanner
from scanner.finding_utils import normalize_findings
from scanner.rule_loader import RuleLoader
from scripts.evaluate_final_realcode import ROOT,read,write
from scripts.evaluate_obligations import load_sources

FREEZE='f370de1c7078e2b6e07154e2a8d4974ef757e3b1'
OUT=ROOT/'docs/evaluation/evidence-2026-11-14'
PREVIOUS=ROOT/'docs/evaluation/mechanisms-2026-11-14'


def context_sources():
    groups=defaultdict(dict)
    for r in read(PREVIOUS/'vul4py/source-receipts.json')['records']:
        if r.get('expected_absent'):continue
        if r.get('error'):raise ValueError('Unrecovered source receipt')
        raw=(ROOT/'.benchmark-cache/vul4py-pilot'/r['id']/r['role']/r['path']).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=r['source_sha256']:raise ValueError('Source changed')
        groups[r['id'],r['role']][r['path']]=raw.decode('utf-8-sig')
    return groups


def replay():
    from scripts.evaluate_vul4py_pilot import application
    rows=[]
    for label,groups,old in [('six-exposed',load_sources(),read(PREVIOUS/'default.json')['records']),
                             ('ten-exposed',context_sources(),read(PREVIOUS/'vul4py/default.json')['records'])]:
        for record in old:
            key=(record['id'],record['role'])
            files={p:s for p,s in groups[key].items() if application(p)}
            fs=normalize_findings(SASTScanner().scan(ScanContext(files,{},ProjectProfile(),RuleLoader(),{})))
            alerts=[f.to_dict() for f in fs]
            matched=[f for f in alerts if f['severity']!='INFO' and f['rule_id'].startswith('PY-OBL-') and any(
                u['path']==f['file_path'] and f['line_number'] is not None and u['start_line']<=f['line_number']<=u['end_line'] for u in record['units'])]
            rows.append(dict(partition=label,id=key[0],role=key[1],alerts=alerts,mechanism_candidates=matched,
                original_cna_cwes=record.get('cna_cwes',[]),units=record['units'],
                strict_cna_matches=[f for f in matched if f['cwe'] in record.get('cna_cwes',[])]))
    summary={label:dict(vulnerable_mechanism_cases=sorted({r['id'] for r in rows if r['partition']==label and r['role']=='vulnerable' and r['mechanism_candidates']}),
        repaired_mechanism_cases=sorted({r['id'] for r in rows if r['partition']==label and r['role']=='fixed' and r['mechanism_candidates']})) for label in ['six-exposed','ten-exposed']}
    write(OUT/'development.json',dict(implementation_revision=FREEZE,source_guided_development=True,new_holdout=False,
        independent_human_labels=False,records=rows,summary=summary,
        interpretation='All pilot source is exposed. Original zero-match pilot and Requests alias overlap remain preserved. Mechanism candidates and strict CNA matches are separate; none establishes deployment exploitability.'))
    print(summary,flush=True)


def correlation():
    from tests.dependency_correlation_fixture import build,edges,CASES
    rows=[]
    for name,kwargs,expected in CASES:
        files,on=build(**kwargs);_,off=build(**kwargs,enabled=False)
        before=[f.to_dict() for f in off.findings];after=[f.to_dict() for f in on.findings]
        assert before==after
        actual=bool(edges(on))
        rows.append(dict(name=name,expected_context_edge=expected,actual_context_edge=actual,
            exact_result=actual==expected,original_findings_unchanged=True,
            source_sha256={p:hashlib.sha256(s.encode()).hexdigest() for p,s in files.items()},
            correlation_on_groups=len(on.correlation_groups),correlation_off_groups=len(off.correlation_groups)))
    write(OUT/'correlation-controls.json',dict(implementation_revision=FREEZE,original_authored_controls=True,independent_real_code_study=False,
        records=rows,correct=sum(r['exact_result'] for r in rows),total=len(rows),
        additional_context_edges=sum(r['actual_context_edge'] for r in rows),additional_vulnerability_discoveries=0,
        review_time_or_decision_improvement_measured=False,
        interpretation='Typed join correctness on original controls only. Ablation confirms unchanged findings. Context is not causal reachability, an independent research contribution, or new vulnerability discovery.'))
    print('Correlation controls:',sum(r['exact_result'] for r in rows),'/',len(rows),flush=True)


def osv():
    names=['requirements.txt','pyproject.toml','Pipfile','Pipfile.lock','package.json','package-lock.json','frontend/package.json','frontend/package-lock.json']
    files={p:(ROOT/p).read_text(encoding='utf-8-sig') for p in names if (ROOT/p).is_file()}
    scanner=SCAScanner();start=time.perf_counter()
    result=normalize_findings(scanner.scan(ScanContext(files,{},ProjectProfile(),RuleLoader(),{})))
    write(OUT/'osv-local.json',dict(implementation_revision=FREEZE,live_external_api=True,authentication_header_supplied=False,
        source_sha256={p:hashlib.sha256(s.encode()).hexdigest() for p,s in files.items()},
        wall_seconds=time.perf_counter()-start,successful_unique_queries=len(scanner._osv_cache),
        findings=[f.to_dict() for f in result],sbom=scanner.generate_sbom(files,'spideyctf/theron'),
        interpretation='Exact manifest/lock declarations queried against live OSV; ranges unresolved. No credential key or installed/deployed/reachable vulnerability assertion. Database results may change.'))
    write(OUT/'osv-responses.json',dict(records=scanner._osv_cache))
    print('OSV:',len(scanner._osv_cache),'complete unique queries;',len(result),'findings/notices',flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['replay','correlation','osv']);args=parser.parse_args()
    subprocess.run(['git','diff','--exit-code',FREEZE,'--','scanner','rules'],cwd=ROOT,check=True,capture_output=True)
    {'replay':replay,'correlation':correlation,'osv':osv}[args.mode]()
