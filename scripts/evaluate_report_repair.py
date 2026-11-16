"""Development replay of the supplied report and exposed synthetic regression."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import time
from scanner.models import ScanContext,ScanResult
from scanner.profiler import ProjectProfiler
from scanner.plugins import discover_plugins,clear_registry
from scanner.rule_loader import RuleLoader
from scanner.finding_utils import normalize_findings,partition_findings
from scanner.correlation import correlate
from scanner.reporters.html import save_html_report
from scanner.reporters.json_reporter import save_json_report
from scanner.reporters.sarif import save_sarif_report

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'docs/evaluation/report-repair-2026-11-17'
CACHE=ROOT/'.benchmark-cache/report-repair-2026-11-17'


def write(name,value):
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/name).write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')


def report_replay(path):
    started=time.perf_counter()
    original=json.loads(Path(path).read_text(encoding='utf-8'))
    files,receipts={},[]
    for row in json.loads((CACHE/'fetch-receipts.json').read_text()):
        assert row['status']=='fetched'
        raw=base64.b64decode((CACHE/'blobs'/(row['sha']+'.b64')).read_text())
        assert len(raw)==row['size']
        assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==row['sha']
        receipts.append(dict(path=row['path'],git_blob_sha=row['sha'],sha256=hashlib.sha256(raw).hexdigest()))
        files[row['path']]=raw.decode('utf-8',errors='replace')
    assert len(files)==original['files_scanned']==65
    profile=ProjectProfiler().analyze(files)
    context=ScanContext(files,{},profile,RuleLoader(),{'include_experimental':True})
    clear_registry();plugins=discover_plugins()
    findings=[]
    for name in original['modules_run']:findings.extend(plugins[name].scan(context))
    result=ScanResult(repo_full_name=original['repo_full_name'],branch=original['branch'],commit_sha=original['commit_sha'],
        findings=normalize_findings(findings),files_scanned=len(files),modules_run=original['modules_run'],project_profile=profile.to_dict())
    result.sbom=plugins['sca'].generate_sbom(files,result.repo_full_name)
    partition_findings(result);correlate(result,files)
    result.scan_duration_seconds=round(time.perf_counter()-started,3)
    write('source-receipts.json',receipts)
    save_json_report(result,str(OUT/'repaired-report.json'))
    save_html_report(result,str(OUT/'repaired-report.html'))
    save_sarif_report(result,str(OUT/'repaired-report.sarif'))
    forbidden={'PY-SAST-006','AI-TAINT-003','JS-SAST-003'}
    assert not [f for f in result.findings if f.rule_id in forbidden]
    assert not [f for f in result.findings if f.rule_id=='PY-SAST-SSTI-001' and f.file_path in {'Path Traversal/py_ctf.py','Server Side Template Injection/asis_ssti_pt.py'}]
    for rule,source_path,line in [('JS-SAST-CMD-001','Command Injection/exec.js',18),
                           ('JS-SAST-SQL-001','SQL Injection/mysql.js',35),
                           ('PY-SAST-SSTI-001','Server Side Template Injection/test.py',11)]:
        assert any(f.rule_id==rule and f.file_path==source_path and f.line_number==line for f in result.findings),(rule,source_path,line)
    write('comparison.json',dict(implementation_revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        scanner_worktree_changed=bool(subprocess.check_output(['git','diff','--','scanner','rules'],cwd=ROOT)),
        development_exposed=True,independent_labels=False,target_code_executed=False,
        old_summary=original['summary'],new_summary=result.summary,
        original_report_sha256=hashlib.sha256(Path(path).read_bytes()).hexdigest(),
        scanner_source_sha256={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_text(encoding='utf-8').encode()).hexdigest() for folder in ('scanner','rules') for p in (ROOT/folder).rglob('*') if p.suffix in {'.py','.yaml'}},
        interpretation='Same pinned 65-file snapshot, all modules and experimental rules enabled. Development correction, not fresh accuracy or vulnerability confirmation.'))
    print('Previous',original['summary'],flush=True)
    print('Repaired',result.summary,flush=True)


def synthetic():
    from scanner.benchmark import evaluate as pairs
    from scanner.owasp_benchmark import evaluate
    manifest=json.loads((ROOT/'docs/evaluation/owasp-2026-11-12/split.json').read_text())
    summary={}
    for split in ('development','validation','test','pysastbench'):
        value=pairs(ROOT/'.benchmark-cache/PySASTBench') if split=='pysastbench' else evaluate(ROOT/'.benchmark-cache/BenchmarkPython',manifest,split)
        previous=json.loads((ROOT/'docs/evaluation/library-flows-2026-11-14'/(split+'.json')).read_text())
        write(split+'.json',value)
        outcomes_unchanged=all(new['outcome']==old['outcome'] for new,old in zip(value['cases'],previous['cases'])) and len(value['cases'])==len(previous['cases'])
        summary[split]=dict(summary=value['summary'],label_outcomes_unchanged=outcomes_unchanged,
                            case_outcomes_and_alert_counts_unchanged=value['cases']==previous['cases'])
        print(split,summary[split],flush=True)
    write('synthetic-summary.json',dict(exposed_data=True,partitions=summary))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--report');parser.add_argument('--synthetic',action='store_true')
    args=parser.parse_args()
    if args.report:report_replay(args.report)
    if args.synthetic:synthetic()
    assert args.report or args.synthetic
