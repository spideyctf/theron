"""Frozen engineering evaluation. Targets are static text; never imported/executed."""
import argparse
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import re
import statistics
import subprocess
import tarfile
import time

from scanner.owasp_benchmark import BANDIT_CWES, evaluate, load_files
from scanner.realworld_audit import check_freeze
from scripts.probe_realworld_development import probe

FREEZE='36ee9eef341b561cb79f8f1c2edfbd9c7533187f'
REPO=Path(__file__).resolve().parents[1]
SPLITS=['development','validation','test']
FEATURES=[None,'interprocedural','local_imports','sanitizers']


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def write(path,value):
    Path(path).parent.mkdir(parents=True,exist_ok=True)
    Path(path).write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def checked_path(root,name):
    path=(Path(root)/name).resolve()
    if not path.is_relative_to(Path(root).resolve()):
        raise ValueError('Path outside evaluation root')
    return path


def check_implementation():
    result=subprocess.run(['git','diff','--quiet',FREEZE,'--','scanner','rules'],cwd=REPO)
    if result.returncode:
        raise ValueError('Frozen detector/correlation/rules changed; declare a new evaluation')
    root=REPO/'docs/evaluation/realworld-2026-11-12'
    if not check_freeze(root,{n:read(root/n) for n in ['inputs.json','queries.json','github-metadata.json','prior-unit-index.json','manifest.json']}):
        raise ValueError('Frozen reserve ledger is required')


def stage(args):
    target=args.cache/'stage'
    if target.exists() and any(target.iterdir()):
        raise ValueError('Use a new empty staging directory')
    records={}
    def put(name,raw):
        path=checked_path(target,name)
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(raw)
        records[name]=sha(raw)
    manifest=read(args.owasp_manifest)
    for split in SPLITS:
        files,_=load_files(args.dataset,manifest,split)
        for name in files:
            put('owasp/'+split+'/'+name,checked_path(args.dataset,name).read_bytes())
    real=probe(read(args.real_manifest),read(args.selection),args.source_cache)
    if any('error' in r for r in real['records']):
        raise ValueError('Development source/span integrity check failed')
    real['frozen_implementation']=FREEZE
    write(args.output/'real-theron.json',real)
    for record in real['records']:
        name='/'.join([record['cve_id'],record['role'],record['path']])
        raw=checked_path(args.source_cache,name).read_text(encoding='utf-8').encode()
        if sha(raw)!=record['source_sha256']:
            raise ValueError('Real source changed during staging')
        put('realcode/'+name,raw)
    revision=subprocess.check_output(['git','-C',str(args.rules),'rev-parse','HEAD'],text=True).strip()
    if revision!='a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2':
        raise ValueError('Baseline rules revision differs')
    if subprocess.run(['git','-C',str(args.rules),'diff','--quiet','HEAD','--','python']).returncode:
        raise ValueError('Pinned baseline rule files have local changes')
    for path in sorted((args.rules/'python').rglob('*')):
        if path.suffix in {'.yaml','.yml'}:
            put('rules/python/'+path.relative_to(args.rules/'python').as_posix(),path.read_bytes())
    write(target/'input-sha256.json',records)
    with tarfile.open(args.cache/'inputs.tar','w') as archive:
        for name in list(records)+['input-sha256.json']:
            raw=checked_path(target,name).read_bytes()
            info=tarfile.TarInfo(name)
            info.size=len(raw)
            archive.addfile(info,io.BytesIO(raw))
    write(args.output/'input-provenance.json',dict(frozen_implementation=FREEZE,
        owasp_manifest_sha256=sha(Path(args.owasp_manifest).read_bytes()),
        real_membership_sha256=real['membership_sha256'],rules_revision=revision,files=records,
        real_source_encoding='UTF-8 with universal line endings, matching prior development probe',
        owasp_source_encoding='Exact corpus bytes, no text-mode staging conversion',
        reserved_real_source_opened=False,target_execution=False))
    print(json.dumps({'staged_files':len(records),'real_snapshots':len(real['records'])}),flush=True)


def theron(args):
    manifest=read(args.owasp_manifest)
    for split in SPLITS:
        for feature in FEATURES:
            result=evaluate(args.dataset,manifest,split,ablation=feature)
            result['frozen_implementation']=FREEZE
            result['exposure']='Previously exposed synthetic regression; not a fresh holdout'
            name=split+'-'+(feature or 'default')+'.json'
            write(args.output/name,result)
            print(name,json.dumps(result['summary']),flush=True)
    from scanner.python_analysis import analyze_python
    base=read(args.output/'real-theron.json')
    variants={}
    for feature in FEATURES[1:]:
        records=[]
        for original in base['records']:
            name='/'.join([original['cve_id'],original['role'],original['path']])
            content=checked_path(args.source_cache,name).read_text(encoding='utf-8')
            if sha(content.encode())!=original['source_sha256']:
                raise ValueError('Development source hash changed')
            modes={}
            for mode,experimental in [('default',False),('experimental',True)]:
                findings=analyze_python(original['path'],content,module='sast',include_experimental=experimental,disabled_features={feature})
                modes[mode]=[dict(rule_id=f.rule_id,cwe=f.cwe,line_number=f.line_number,maturity=f.maturity,
                                  confidence=f.confidence,evidence_kind=f.evidence_kind,trace=f.trace) for f in findings]
            records.append(dict(cve_id=original['cve_id'],role=original['role'],path=original['path'],
                                source_sha256=original['source_sha256'],modes=modes))
        variants[feature]=records
    write(args.output/'real-ablations.json',dict(frozen_implementation=FREEZE,independent_labels=False,scorable_cases=0,variants=variants))


def relative_path(path,track):
    normalized=str(path).replace('\\','/')
    marker='/'+track+'/'
    if marker not in normalized:
        raise ValueError('Baseline path is outside the declared stage')
    value=normalized.rsplit(marker,1)[1]
    if not value or '..' in value.split('/') or value.startswith('/'):
        raise ValueError('Unsafe baseline path')
    return value


def external_records(raw,tool,track,expected):
    """Keep compact alert metadata and errors; never publish raw code/messages."""
    if tool not in {'bandit','semgrep'}:
        raise ValueError('Unknown baseline')
    paths=([p for p in raw.get('metrics',{}) if p!='_totals'] if tool=='bandit'
           else raw.get('paths',{}).get('scanned',[]))
    covered={relative_path(p,track) for p in paths}
    errors=[]
    for item in raw.get('errors',[]):
        original=item.get('filename') if tool=='bandit' else item.get('path')
        path=relative_path(original,track) if original else None
        if path:
            covered.add(path)
        errors.append(dict(path=path,type=str(item.get('type','parse_or_scan_error')),
                           level=str(item.get('level','error'))))
    if covered!=set(expected):
        raise ValueError('Baseline coverage differs from exact staged input inventory')
    alerts=[]
    for item in raw.get('results',[]):
        path=relative_path(item['filename'] if tool=='bandit' else item['path'],track)
        if path not in covered:
            raise ValueError('Alert is not in the declared input inventory')
        if tool=='bandit':
            rule=item['test_id']
            cwe=BANDIT_CWES.get(rule,'CWE-'+str(item.get('issue_cwe',{}).get('id')))
            cwes=[cwe] if re.fullmatch(r'CWE-\d+',cwe) else []
            line=item['line_number']
            end_line=max(item['line_range']) if item.get('line_range') else None
            severity,confidence=item.get('issue_severity'),item.get('issue_confidence')
        else:
            rule=item['check_id']
            extra=item.get('extra',{})
            cwes=sorted(set(re.findall(r'CWE-\d+',json.dumps(extra.get('metadata',{}).get('cwe',[])))))
            if 'CWE-327' in cwes and re.search(r'(insecure|weak).*(hash|md5|sha1)',rule,re.I):
                cwes=sorted(set(cwes)|{'CWE-328'})
            line=item['start']['line']
            end_line=item.get('end',{}).get('line')
            severity,confidence=extra.get('severity'),extra.get('metadata',{}).get('confidence')
        alerts.append(dict(path=path,rule_id=rule,cwes=cwes,line_number=line,end_line_number=end_line,severity=severity,confidence=confidence))
    return dict(engine=tool,covered_files=len(covered),alerts=alerts,errors=errors)


def collect(args):
    version=subprocess.check_output([str(args.bandit_python),'-m','bandit','--version'],text=True)
    if not re.search(r'\b1\.9\.4\b',version):
        raise ValueError('Bandit environment must be pinned to 1.9.4')
    inventory=read(args.output/'input-provenance.json')['files']
    for name,digest in inventory.items():
        if sha(checked_path(args.cache/'stage',name).read_bytes())!=digest:
            raise ValueError('Exact-byte staged inputs/rules changed')
    manifest=read(args.owasp_manifest)
    for tool in ['bandit','semgrep']:
        for split in SPLITS:
            path=args.cache/(tool+'-'+split+'.json')
            raw=read(path)
            if tool=='semgrep' and raw.get('version')!='1.185.0':
                raise ValueError('Semgrep report must be pinned to 1.185.0')
            track='owasp/'+split
            expected={p[len(track)+1:] for p in inventory if p.startswith(track+'/')}
            compact=external_records(raw,tool,track,expected)
            result=evaluate(args.dataset,manifest,split,**{tool+'_json':path})
            result.update(frozen_implementation=FREEZE,baseline_provenance='Fresh exact-byte staged run',
                          exposure='Previously exposed synthetic regression; not a fresh holdout',
                          input_inventory_verified=True,covered_files=compact['covered_files'])
            result['baseline_version']='1.9.4' if tool=='bandit' else raw['version']
            write(args.output/(split+'-'+tool+'.json'),result)
            print(tool,split,json.dumps(result['summary']),flush=True)
        path=args.cache/(tool+'-realcode.json')
        raw=read(path)
        if tool=='semgrep' and raw.get('version')!='1.185.0':
            raise ValueError('Semgrep report must be pinned to 1.185.0')
        expected={p[len('realcode/'):] for p in inventory if p.startswith('realcode/')}
        compact=external_records(raw,tool,'realcode',expected)
        compact.update(raw_report_sha256=sha(path.read_bytes()),independent_labels=False,scorable_cases=0,
                       frozen_implementation=FREEZE,baseline_provenance='Fresh exact-byte staged run',
                       baseline_version='1.9.4' if tool=='bandit' else raw['version'])
        write(args.output/('real-'+tool+'.json'),compact)


def original_controls(args):
    from tests.test_correlation import sample
    from scanner.correlation import correlate
    scenarios=[('direct_python',{},1),('safe_entrypoint',{'code':'print("safe")'},0),
        ('unrelated_unsafe_file',{'code':'pass','extra':{'unrelated.py':'exec(input())'}},0),
        ('missing_target',{'server':{'command':'python','args':['missing.py']}},0),
        ('wrapper',{'server':{'command':'uv','args':['run','server.py']}},0),
        ('ambiguous_cwd',{'server':{'command':'python','args':['server.py'],'cwd':'.'}},0),
        ('unknown_client',{'config_path':'.mcp.json','field':'mcpServers'},0),
        ('case_collision',{'extra':{'Server.py':'pass'}},0),
        ('example_context',{'code':'pass','config_path':'examples/demo/.vscode/mcp.json','extra':{'examples/demo/server.py':'exec(input())'}},1)]
    prior={r['name']:r for r in read(REPO/'docs/evaluation/correlation-2026-11-13/original-controls.json')['cases']}
    records=[]
    for name,options,expected in scenarios:
        files,result=sample(**options)
        if {p:sha(s.encode()) for p,s in files.items()}!=prior[name]['input_sha256']:
            raise ValueError('Original control input hashes differ')
        original=(deepcopy(result.findings),deepcopy(result.context_findings),result.summary.copy())
        timings={}
        for enabled in [True,False]:
            correlate(result,files,enabled)  # one warm-up
            samples=[]
            for _ in range(30):
                started=time.perf_counter_ns()
                correlate(result,files,enabled)
                samples.append((time.perf_counter_ns()-started)/1_000_000)
            timings['enabled' if enabled else 'disabled']=dict(samples_ms=samples,median_ms=statistics.median(samples),
                p95_nearest_rank_ms=sorted(samples)[28],groups=len(result.correlation_groups))
            if len(result.correlation_groups)!=(expected if enabled else 0):
                raise ValueError('Original control outcome differs')
            if (result.findings,result.context_findings,result.summary)!=original:
                raise ValueError('Correlation changed original evidence/counts')
        records.append(dict(name=name,expected_groups=expected,findings_and_counts_unchanged=True,timings=timings))
    write(args.output/'correlation-ablations.json',dict(frozen_implementation=FREEZE,
        provenance='Nine original author-labelled mechanism controls, not independent real-code labels',
        timing_scope='Post-analysis pass only; one warm-up and 30 repetitions per mode/case; uncontrolled local machine',
        tool_graph_comparison='Not applicable: Bandit/Semgrep are component-code baselines, not this MCP graph method',records=records))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=['stage','theron','collect','controls'])
    p.add_argument('--cache',type=Path,default=REPO/'.benchmark-cache/step5')
    p.add_argument('--output',type=Path,default=REPO/'docs/evaluation/step5-2026-11-13')
    p.add_argument('--dataset',type=Path,default=REPO/'.benchmark-cache/BenchmarkPython')
    p.add_argument('--owasp-manifest',type=Path,default=REPO/'docs/evaluation/owasp-2026-11-12/split.json')
    p.add_argument('--real-manifest',type=Path,default=REPO/'docs/evaluation/realworld-2026-11-12/manifest.json')
    p.add_argument('--selection',type=Path,default=REPO/'docs/evaluation/development-2026-11-12/selection.json')
    p.add_argument('--source-cache',type=Path,default=REPO/'.benchmark-cache/realworld-step3')
    p.add_argument('--rules',type=Path,default=REPO/'.benchmark-cache/semgrep-rules')
    p.add_argument('--bandit-python',type=Path,default=REPO/'.benchmark-cache/bandit-venv/Scripts/python.exe')
    args=p.parse_args()
    check_implementation()
    args.cache.mkdir(parents=True,exist_ok=True)
    args.output.mkdir(parents=True,exist_ok=True)
    {'stage':stage,'theron':theron,'collect':collect,'controls':original_controls}[args.mode](args)


if __name__=='__main__':
    main()
