"""Frozen developer probes and delivery artifacts; target code is AST-only."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import subprocess

from scanner.benchmark import evaluate as tuning_evaluate
from scanner.finding_utils import normalize_findings
from scanner.models import ProjectProfile, ScanContext
from scanner.owasp_benchmark import evaluate as synthetic_evaluate
from scanner.plugins.sast import SASTScanner
from scanner.realworld_audit import check_freeze
from scanner.rule_loader import RuleLoader
from scanner.reporters.json_reporter import generate_json_report
from scanner.reporters.sarif import generate_sarif_report
from scanner.reporters.html import generate_html_report
from scripts.evaluate_audited_units import checked_source,compact,matches_unit,read
from tests.flow_delivery_fixture import build

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'docs/evaluation/flow-completion-2026-11-13'
FREEZE='d8fc59850ff1c261c29cdf53b53ec90c3571f5fb'


def write(path,value):
    path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')


def select_units(rows,audit):
    units=[dict(u,cve_id='CVE-2021-4315') for u in next(c for c in audit['cases'] if c['cve_id']=='CVE-2021-4315')['units']]
    for r in rows:
        if r['cve_id']=='CVE-2023-29159':
            units.append(dict(cve_id=r['cve_id'],role=r['role'],revision=r['revision'],path=r['path'],
                source_sha256=r['source_sha256'],sink_line=192,source_line=111,cwe='CWE-22',
                expected='unsafe_path_flow' if r['role']=='vul_func' else 'safe_for_this_lexical_path_boundary',
                label_status='Provisional developer source/sink unit; not independently adjudicated'))
    return units


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--skip-synthetic',action='store_true')
    args=parser.parse_args()
    if subprocess.run(['git','diff','--quiet',FREEZE,'--','scanner','rules'],cwd=ROOT).returncode:
        raise ValueError('Frozen detector changed')
    ledger=ROOT/'docs/evaluation/realworld-2026-11-12'
    inputs={n:read(ledger/n) for n in ['inputs.json','queries.json','github-metadata.json','prior-unit-index.json','manifest.json']}
    if not check_freeze(ledger,inputs):
        raise ValueError('Original metadata changed')
    cases={c['cve_id']:c for c in inputs['manifest.json']['cases'] if c['partition']=='validation'}
    rows=read(ROOT/'docs/evaluation/research-repair-2026-11-13/validation-exposure.json')['records']
    if set(cases)!={r['cve_id'] for r in rows}:
        raise ValueError('Use all and only exposed validation cases')
    groups=defaultdict(dict)
    for r in rows:
        if not any(l['role']==r['role'] and l['path']==r['path'] and l['resolution']['sha']==r['revision'] for l in cases[r['cve_id']]['locations']):
            raise ValueError('Snapshot outside declared validation metadata')
        groups[(r['cve_id'],r['role'],r['revision'])][r['path']]=checked_source(ROOT/'.benchmark-cache/research-validation',r)
    audit=read(ROOT/'docs/evaluation/unit-audit-2026-11-13/audit.json')
    units=select_units(rows,audit)
    if len(units)!=6 or any(sum(u['role']==role for u in units)!=3 for role in ['vul_func','fix_func']):
        raise ValueError('Expected exactly three unsafe and three patched developer units')
    if len({(u['cve_id'],u['role'],u['revision'],u['path'],u['sink_line']) for u in units})!=6:
        raise ValueError('Duplicate developer unit')
    write(OUT/'developer-units.json',dict(independent_labels=False,source_guided_development=True,units=units))
    records=[]
    for (cve,role,revision),files in groups.items():
        fs=normalize_findings(SASTScanner().scan(ScanContext(files,{},ProjectProfile(),RuleLoader(),{})))
        alerts=[compact(f) for f in fs]
        records.append(dict(cve_id=cve,role=role,revision=revision,files=list(files),alerts=alerts))
    outcomes=[]
    for u in units:
        row=next(r for r in records if all(r[k]==u[k] for k in ['cve_id','role','revision']))
        source=next(r for r in rows if all(r[k]==u[k] for k in ['cve_id','role','revision','path']))
        if source['source_sha256']!=u['source_sha256']:
            raise ValueError('Developer-unit source identity differs')
        outcomes.append(dict(unit=u,matched_alerts=[a for a in row['alerts'] if matches_unit(a,u)]))
    ablations=[]
    for (cve,role,revision),files in groups.items():
        if cve not in {'CVE-2021-4315','CVE-2023-29159'}:
            continue
        for feature in ['interprocedural','sanitizers']:
            fs=normalize_findings(SASTScanner().scan(ScanContext(files,{},ProjectProfile(),RuleLoader(),{'analysis_disabled_features':[feature]})))
            ablations.append(dict(cve_id=cve,role=role,disabled=feature,alerts=[compact(f) for f in fs]))
    write(OUT/'real-development.json',dict(implementation_revision=FREEZE,independent_labels=False,
        source_guided_development=True,final_test_source_opened=False,original_label_errors_retained=2,
        records=records,unit_outcomes=outcomes,ablations=ablations,
        interpretation='Normalized developer probes, not a new independent holdout or real-world accuracy denominator. Archive notices are not confirmed vulnerabilities.'))
    extra=read(ROOT/'docs/evaluation/unit-audit-2026-11-13/context-exposure.json')['records']
    context=[]
    for (cve,role,revision),files in groups.items():
        if cve!='CVE-2023-29159':
            continue
        files=dict(files)
        for r in extra:
            if (r['cve_id'],r['role'],r['revision'])==(cve,role,revision):
                files[r['path']]=checked_source(ROOT/'.benchmark-cache/context-audit',r)
        fs=normalize_findings(SASTScanner().scan(ScanContext(files,{},ProjectProfile(),RuleLoader(),{})))
        context.append(dict(cve_id=cve,role=role,files=list(files),alerts=[compact(f) for f in fs]))
    write(OUT/'package-context.json',dict(implementation_revision=FREEZE,records=context,final_test_source_opened=False))
    _,result=build()
    for fmt,generate in [('json',generate_json_report),('sarif',generate_sarif_report),('html',generate_html_report)]:
        (OUT/('original-delivery-fixture.'+fmt)).write_text(generate(result),encoding='utf-8')
    write(OUT/'delivery-check.json',dict(original_fixture=True,not_a_real_github_scan=True,
        vulnerability_findings=result.summary['vulnerability_findings'],total_findings=result.summary['total_findings'],
        correlation_groups=len(result.correlation_groups),finding_metadata=result.to_dict()['findings']))
    print('Developer unsafe units matched:',sum(bool(o['matched_alerts']) for o in outcomes if o['unit']['role']=='vul_func'),'/ 3',flush=True)
    print('Developer patched units matched:',sum(bool(o['matched_alerts']) for o in outcomes if o['unit']['role']=='fix_func'),'/ 3',flush=True)
    if not args.skip_synthetic:
        manifest=read(ROOT/'docs/evaluation/owasp-2026-11-12/split.json')
        for split in ['development','validation','test']:
            r=synthetic_evaluate(ROOT/'.benchmark-cache/BenchmarkPython',manifest,split)
            write(OUT/(split+'.json'),r)
            print(split,r['summary'],flush=True)
        r=tuning_evaluate(ROOT/'.benchmark-cache/PySASTBench')
        write(OUT/'pysastbench.json',r)
        print('pysastbench',r['summary'],r['fixed_file_alerts'],flush=True)


if __name__=='__main__':
    main()
