"""External label corroboration and matched baseline collection, without tuning."""
import argparse
import hashlib
import json
import subprocess

from scripts.evaluate_final_realcode import ROOT, OUT, CACHE, cases, read, write, checked_path, snapshot_key, summarize
from scripts.evaluate_real_validation import reference_matches
from scripts.evaluate_step5 import external_records

RULE_REV = 'a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2'


def labels():
    selected = cases()
    external = read(OUT/'external-cve-records.json')
    if {r['cve_id'] for r in external['records']} != {c['cve_id'] for c in selected}:
        raise ValueError('External records must cover every final case')
    rows = []
    for c in selected:
        r = next(r for r in external['records'] if r['cve_id']==c['cve_id'])
        record = r['record']
        if record['cveMetadata']['cveId']!=c['cve_id']:
            raise ValueError('CVE identity differs')
        cna = record['containers']['cna']
        types = [d['cweId'] for t in cna.get('problemTypes',[]) for d in t.get('descriptions',[]) if d.get('cweId')]
        refs = [v['url'] for v in cna.get('references',[])]
        patches = [v['url'] for v in c['patch_references']]
        rows.append(dict(cve_id=c['cve_id'],record_state=record['cveMetadata']['state'],provider=cna.get('providerMetadata'),
            source_url=r['url'],upstream_cwes=c['cwes'],cna_cwes=types,cwe_overlap=sorted(set(c['cwes'])&set(types)),
            reference_urls=refs,declared_patch_urls=patches,
            patch_url_exact_overlap=sorted(set(u.lower() for u in refs)&set(u.lower() for u in patches)),
            cna_title=cna.get('title'),record_sha256=hashlib.sha256(json.dumps(record,sort_keys=True).encode()).hexdigest(),
            function_spans_adjudicated_by_external_reviewer=False,theron_alerts_independently_reviewed=False))
    write(OUT/'label-corroboration.json',dict(source_revision=external['revision'],all_nine_cases_represented=True,
        label_origin='External PatchEval repair metadata plus CVE CNA records; independent of Theron development',
        independent_human_adjudication=False,independent_alert_precision_established=False,records=rows))


def stage_baselines():
    cases()
    rules = ROOT/'.benchmark-cache/semgrep-rules'
    if subprocess.check_output(['git','-C',str(rules),'rev-parse','HEAD'],text=True).strip()!=RULE_REV:
        raise ValueError('Baseline rules revision differs')
    if subprocess.check_output(['git','-C',str(rules),'status','--porcelain','--','python'],text=True).strip():
        raise ValueError('Baseline rule bytes changed')
    for p in (rules/'python').rglob('*'):
        if p.suffix in {'.yml','.yaml'}:
            target=checked_path(CACHE/'rules',p.relative_to(rules))
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(p.read_bytes())
    files={p.relative_to(CACHE).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
           for top in ['stage','rules'] for p in (CACHE/top).rglob('*') if p.is_file()}
    write(OUT/'baseline-inputs.json',dict(rules_revision=RULE_REV,files=files))


def baselines():
    selected = {c['cve_id']:c for c in cases()}
    inputs=read(OUT/'baseline-inputs.json')
    for path,digest in inputs['files'].items():
        if hashlib.sha256(checked_path(CACHE,path).read_bytes()).hexdigest()!=digest:
            raise ValueError('Staged inputs changed')
    native=read(CACHE/'native-verification.json')
    if not native.get('all_bytes_identical') or native['files']!=inputs['files']:
        raise ValueError('Native baseline input bytes not verified')
    exposure=read(OUT/'source-exposure.json')['records']
    expected={snapshot_key(r) for r in exposure if 'error' not in r}
    bandit_version=subprocess.check_output([str(ROOT/'.benchmark-cache/bandit-venv/Scripts/python.exe'),'-m','bandit','--version'],text=True)
    if bandit_version.splitlines()[0].split()[-1]!='1.9.4':
        raise ValueError('Bandit version differs')
    reports={}
    for tool in ['bandit','semgrep']:
        raw_path=CACHE/(tool+'.json')
        raw=read(raw_path)
        if tool=='semgrep' and raw['version']!='1.185.0':
            raise ValueError('Semgrep version differs')
        report=external_records(raw,tool,'stage',expected)
        records=[]
        for r in exposure:
            row=dict(r)
            alerts=[a for a in report['alerts'] if a['path']==snapshot_key(r)]
            row['alerts']=alerts
            row['scanner_errors']=[e for e in report['errors'] if e['path']==snapshot_key(r)]
            expanded=[dict(a,cwe=cwe,evidence_kind='static-baseline') for a in alerts for cwe in a['cwes']]
            row['reference_matches']=None if any(k in r for k in ['error','label_error']) else [a for u in r['units']
                for a in reference_matches(expanded,selected[r['cve_id']]['cwes'],u['start_line'],u['end_line'])]
            records.append(row)
        report.update(records=records,summary=summarize(records),raw_report_sha256=hashlib.sha256(raw_path.read_bytes()).hexdigest(),
            independent_alert_adjudication=False,comparison_scope='Original CWE/function-span proxy on same 22 input files; not confirmed alert precision')
        write(OUT/(tool+'.json'),report)
        reports[tool]=report['summary']
    write(OUT/'baseline-environment.json',dict(bandit_version_output=bandit_version,semgrep_version='1.185.0',
        semgrep_rules_revision=RULE_REV,native_verified_files=native['verified_files'],all_bytes_identical=True,
        rule_files=337,source_files=22,bandit_flags=['--ignore-nosec','all default tests/severities/confidences','--exit-zero'],
        semgrep_flags=['--metrics=off','--disable-version-check','--no-git-ignore','--no-rewrite-rule-ids','--timeout 10','--jobs 2'],
        timing_limitation='Theron and Bandit Windows; Semgrep native WSL. No speed ranking.'))
    print(json.dumps(reports,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['labels','stage-baselines','baselines'])
    args=parser.parse_args()
    {'labels':labels,'stage-baselines':stage_baselines,'baselines':baselines}[args.action]()
