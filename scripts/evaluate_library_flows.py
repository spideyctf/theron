"""Source-guided exposed-library probes, never a fresh final test."""
from collections import defaultdict
import hashlib
import subprocess

from scanner.benchmark import evaluate as tuning_evaluate
from scanner.owasp_benchmark import evaluate as synthetic_evaluate
from scanner.finding_utils import normalize_findings
from scanner.models import ScanContext, ProjectProfile
from scanner.plugins.sast import SASTScanner
from scanner.rule_loader import RuleLoader
from scanner.realworld_audit import snippet_digest, check_freeze
from scanner.reporters.html import generate_html_report
from scanner.reporters.json_reporter import generate_json_report
from scanner.reporters.sarif import generate_sarif_report
from scripts.evaluate_final_realcode import ROOT, CACHE, read, write, snapshot_key, checked_path, compact, summarize
from scripts.evaluate_real_validation import reference_matches

FREEZE='634573431544a3ef16da99df5fcad35360372971'
OUT=ROOT/'docs/evaluation/library-flows-2026-11-14'


def main():
    if subprocess.run(['git','diff','--quiet',FREEZE,'--','scanner','rules'],cwd=ROOT).returncode:
        raise ValueError('Declared library-flow freeze changed')
    ledger=ROOT/'docs/evaluation/realworld-2026-11-12'
    inputs={n:read(ledger/n) for n in ['inputs.json','queries.json','github-metadata.json','prior-unit-index.json','manifest.json']}
    if not check_freeze(ledger,inputs):
        raise ValueError('Original metadata changed')
    cases={c['cve_id']:c for c in inputs['manifest.json']['cases'] if c['partition']=='test'}
    rows=read(ROOT/'docs/evaluation/final-validation-2026-11-13/source-exposure.json')['records']
    if set(cases)!={r['cve_id'] for r in rows}:
        raise ValueError('All nine exposed cases required')
    groups=defaultdict(dict)
    checks=0
    for r in rows:
        if 'error' in r or 'label_error' in r:
            raise ValueError('Previously verified source receipt changed')
        raw=checked_path(CACHE/'stage',snapshot_key(r)).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=r['source_sha256']:
            raise ValueError('Source bytes changed')
        source=raw.decode('utf-8-sig')
        lines=source.splitlines()
        locations=[l for l in cases[r['cve_id']]['locations'] if (l['role'],l['resolution']['sha'],l['path'])==(r['role'],r['revision'],r['path'])]
        if not locations:
            raise ValueError('Snapshot outside original membership')
        for l in locations:
            if snippet_digest('\n'.join(lines[l['start_line']-1:l['end_line']]))!=l['snippet_sha256']:
                raise ValueError('Original function hash changed')
            checks+=1
        groups[(r['cve_id'],r['role'],r['revision'])][r['path']]=source
    entries=read(OUT/'entrypoint-models.json')['analysis_entrypoints']
    summaries={}
    for mode in ['default','configured','configured-no-sanitizers']:
        alerts={}
        for (cve,role,revision),files in groups.items():
            active=[] if mode=='default' else [e for e in entries if e['file'] in files]
            config=dict(analysis_entrypoints=active,analysis_disabled_features=['sanitizers'] if mode.endswith('no-sanitizers') else [])
            fs=normalize_findings(SASTScanner().scan(ScanContext(files,{},ProjectProfile(),RuleLoader(),config)))
            for path in files:
                alerts['/'.join([cve,role,revision,path])]=[dict(compact(f),description=f.description) for f in fs if f.file_path==path]
        records=[]
        semantic=[]
        for r in rows:
            row=dict(r,alerts=alerts[snapshot_key(r)])
            row['scanner_errors']=[a for a in row['alerts'] if a['rule_id']=='PY-PARSE-001']
            row['reference_matches']=[a for u in r['units'] for a in reference_matches(row['alerts'],cases[r['cve_id']]['cwes'],u['start_line'],u['end_line'])]
            records.append(row)
            if r['path']=='celery/backends/base.py':
                unit_rule='PY-SAST-DYNAMIC-CALL-001'
            elif r['path']=='mechanicalsoup/browser.py':
                unit_rule='PY-SAST-PATH-001'
            else:
                continue
            matched=[a for a in row['alerts'] if a['rule_id']==unit_rule and any(u['start_line']<=a['line_number']<=u['end_line'] for u in r['units'])]
            semantic.append(dict(cve_id=r['cve_id'],role=r['role'],path=r['path'],rule_id=unit_rule,alerts=matched,
                interpretation='Provisional author/assistant mechanism unit, conditional on explicit library contract; separate from original CWE matching.'))
        summary=summarize(records)
        summary['semantic_unsafe_cases_with_conditional_evidence']=sorted({s['cve_id'] for s in semantic if s['role']=='vul_func' and s['alerts']})
        summary['semantic_patched_cases_with_conditional_evidence']=sorted({s['cve_id'] for s in semantic if s['role']=='fix_func' and s['alerts']})
        write(OUT/(mode+'.json'),dict(implementation_revision=FREEZE,source_guided_development=True,
            new_holdout=False,independent_labels=False,original_function_hash_checks=checks,
            matching='Original upstream CWE/function spans unchanged; configured advisory findings are not confirmed real-world detections.',
            records=records,semantic_developer_units=semantic,summary=summary))
        summaries[mode]=summary
        print(mode,summary,flush=True)
    manifest=read(ROOT/'docs/evaluation/owasp-2026-11-12/split.json')
    synthetic={}
    for name in ['development','validation','test','pysastbench']:
        result=(tuning_evaluate(ROOT/'.benchmark-cache/PySASTBench') if name=='pysastbench'
                else synthetic_evaluate(ROOT/'.benchmark-cache/BenchmarkPython',manifest,name))
        write(OUT/(name+'.json'),result)
        old=read(ROOT/('docs/evaluation/flow-completion-2026-11-13/'+name+'.json'))
        synthetic[name]=dict(summary=result['summary'],case_outcomes_and_alert_counts_unchanged=result['cases']==old['cases'])
        if name=='pysastbench':
            synthetic[name]['fixed_file_alerts']=result['fixed_file_alerts']
        print(name,synthetic[name],flush=True)
    from tests.library_delivery_fixture import build
    report=build()
    for fmt,generate in [('json',generate_json_report),('html',generate_html_report),('sarif',generate_sarif_report)]:
        (OUT/('original-delivery-fixture.'+fmt)).write_text(generate(report),encoding='utf-8')
    write(OUT/'summary.json',dict(implementation_revision=FREEZE,source_guided_development=True,new_heldout_accuracy=False,
        independent_human_adjudication=False,original_final_result_preserved='4c166e0: 0/9 reference cases',
        original_source_snapshots=len(rows),original_function_hash_checks=checks,real_development=summaries,
        synthetic=synthetic,original_delivery_fixture=True,not_a_live_scan=True,
        observed_flows_only_in_mcp_associations=True))


if __name__=='__main__':
    main()
