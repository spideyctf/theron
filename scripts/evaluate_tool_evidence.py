"""Frozen correlation controls, four input ablations and adapted upstream-source checks."""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess

from scanner.correlation import CONFIG_NAMES,correlate
from scanner.models import ScanResult
from tests.tool_correlation_fixture import CASES,build,groups,edges
from tests.osv_delivery_fixture import RECORD

ROOT=Path(__file__).resolve().parents[1]
BASE_OUT=ROOT/'docs/evaluation/tool-correlation-2026-11-15'
OUT=BASE_OUT/'followup'
FREEZE='7b99d5c6573c4486fa711938626d5f1b9a5b6823'


def write(name,value):(OUT/name).write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')


def controls():
    records=[]
    for name,kwargs,expected in CASES:
        files,original=build(**kwargs,enabled=False)
        original_findings=[f.to_dict() for f in original.findings]
        modes={}
        for mode in ['code_only','dependency_only','code_dependency','combined']:
            result=deepcopy(original)
            modules={'sast'} if mode=='code_only' else {'sca'} if mode=='dependency_only' else {'sast','sca'}
            result.findings=[f for f in result.findings if f.module in modules]
            result.context_findings=[f for f in result.context_findings if f.module in modules]
            result.modules_run=sorted(modules)
            inputs={p:s for p,s in files.items() if mode=='combined' or PureName(p) not in CONFIG_NAMES}
            if mode=='code_only':inputs={p:s for p,s in inputs.items() if p.endswith('.py')}
            elif mode=='dependency_only':inputs={p:s for p,s in inputs.items() if not p.endswith('.py')}
            correlate(result,inputs)
            modes[mode]=dict(tool_groups=len(groups(result)),api_call_edges=len(edges(result,'calls_imported_api')),
                dependency_context_edges=len(edges(result,'import_has_dependency_context')),
                attribution_bases=sorted({e['basis'] for e in edges(result,'import_has_dependency_context')}),
                original_finding_count=len(result.findings),vulnerability_count=result.summary['vulnerability_findings'])
            if mode=='combined':assert [f.to_dict() for f in result.findings]==original_findings
        actual=bool(modes['combined']['dependency_context_edges'])
        advisory=deepcopy(RECORD);advisory['affected'][0]['package']['name']=kwargs.get('package','PyYAML')
        records.append(dict(name=name,expected_link=expected,actual_link=actual,exact_result=actual==expected,modes=modes,
            advisory_snapshot=advisory,
            full_correlation_preserves_findings=True,source_text_sha256={p:hashlib.sha256(s.encode()).hexdigest() for p,s in sorted(files.items())}))
    write('controls.json',dict(implementation_revision=FREEZE,original_authored_controls=True,independent_real_code_study=False,
        advisory_fixture=RECORD,records=records,correct=sum(r['exact_result'] for r in records),total=len(records),
        evaluation_driver_sha256=hashlib.sha256(Path(__file__).read_text().replace('\r\n','\n').encode()).hexdigest(),
        additional_vulnerabilities=0,review_benefit_measured=False,
        interpretation='Correctness of original handler/dependency-context controls and required-input ablations only. Missing MCP configuration prevents configured-entrypoint groups by design. This is not a scanner accuracy or research-advantage estimate.'))
    print('Original controls:',sum(r['exact_result'] for r in records),'/',len(records))
    assert all(r['exact_result'] for r in records)


def PureName(path):return Path(path).name


def upstream():
    receipt=json.loads((BASE_OUT/'upstream-source-receipts.json').read_text())
    rows=[]
    for r in receipt['records']:
        raw=(ROOT/'.benchmark-cache/tool-correlation-2026-11-15'/r['path']).read_bytes()
        assert hashlib.sha256(raw).hexdigest()==r['source_sha256']
        assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==r['git_blob_sha']
        config={'servers':{'upstream-example':{'type':'stdio','command':'python','args':[r['path']]}}}
        files={r['path']:raw.decode('utf-8-sig'),'.vscode/mcp.json':json.dumps(config)}
        result=ScanResult(repo_full_name=receipt['repository'],branch=receipt['revision'],commit_sha=receipt['revision'],modules_run=['sast'],findings=[])
        correlate(result,files)
        rows.append(dict(path=r['path'],source_sha256=r['source_sha256'],configuration_researcher_generated=True,
                         standalone_server_startup_verified=False,
                         groups=result.correlation_groups,resolutions=result.correlation_resolutions,vulnerability_findings=0))
    write('upstream-compatibility.json',dict(implementation_revision=FREEZE,records=rows,project_previously_exposed=True,
        evaluation_driver_sha256=hashlib.sha256(Path(__file__).read_text().replace('\r\n','\n').encode()).hexdigest(),
        untouched_holdout=False,independent_labels=False,
        interpretation='Unchanged public source with generated direct-Python declarations used only as static harness inputs, not verified runnable client setups. These examples declare tools but do not contain a server run call. Static tool/call-path compatibility only; no code execution, installed dependencies, advisory matching, vulnerability accuracy or real-world triage benefit evaluated.'))
    print([(r['path'],len(r['groups'])) for r in rows])


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['controls','upstream']);args=parser.parse_args()
    subprocess.run(['git','diff','--exit-code',FREEZE,'--','scanner'],cwd=ROOT,check=True,capture_output=True)
    OUT.mkdir(parents=True,exist_ok=True)
    {'controls':controls,'upstream':upstream}[args.mode]()
