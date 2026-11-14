"""Frozen changed-file pilot. Downloaded targets are parsed, never imported/executed."""
import ast
import base64
from collections import defaultdict
import hashlib
from pathlib import Path
import re
import subprocess

from scanner.models import ScanContext,ProjectProfile
from scanner.plugins.sast import SASTScanner
from scanner.rule_loader import RuleLoader
from scanner.finding_utils import normalize_findings,finding_scope
from scripts.evaluate_final_realcode import ROOT,read,write,checked_path
from scripts.evaluate_mechanisms import OUT,FREEZE
from scripts.evaluate_obligations import functions

CACHE=ROOT/'.benchmark-cache/vul4py-pilot'
PILOT=OUT/'vul4py'


def application(path):
    return finding_scope(path)=='application' and Path(path).name not in {'tests.py','conftest.py'}


def sources():
    receipts=read(OUT/'vul4py-source-receipts.json')
    groups=defaultdict(dict)
    for r in receipts['records']:
        if r.get('error') or r.get('expected_absent'):continue
        dest=checked_path(CACHE,'/'.join([r['id'],r['role'],r['path']]))
        if not dest.exists():
            raw=base64.b64decode(dest.with_name(dest.name+'.b64').read_text(),validate=False)
            blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
            if blob!=r['git_blob_sha']:raise ValueError('Git blob mismatch: '+str(dest))
            dest.write_bytes(raw)
        raw=dest.read_bytes();digest=hashlib.sha256(raw).hexdigest()
        if hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()!=r['git_blob_sha']:raise ValueError('Git blob changed')
        if r.get('source_sha256',digest)!=digest:raise ValueError('Source bytes changed')
        r['source_sha256']=digest
        groups[r['id'],r['role']][r['path']]=raw.decode('utf-8-sig')
    write(OUT/'vul4py-source-receipts.json',receipts)
    write(PILOT/'source-receipts.json',receipts)
    return groups


def units(code,patch,role):
    spans=[]
    for hunk in patch['hunks']:
        match=re.match(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@',hunk)
        if not match:raise ValueError('Invalid patch hunk')
        start,count=(match.group(1),match.group(2)) if role=='vulnerable' else (match.group(3),match.group(4))
        if int(count or 1):spans.append((int(start),int(start)+int(count or 1)-1))
    tree=ast.parse(code);result=[]
    for name,node in functions(tree.body):
        if any(node.lineno<=end and start<=node.end_lineno for start,end in spans):
            result.append(dict(function=name,start_line=node.lineno,end_line=node.end_lineno))
    # Module-level edits (e.g. regex definitions) remain changed-span proxies.
    for start,end in spans:
        if not any(u['start_line']<=start<=u['end_line'] for u in result):
            result.append(dict(function=None,start_line=start,end_line=end))
    return result


def main():
    subprocess.run(['git','diff','--exit-code',FREEZE,'--','scanner','rules'],cwd=ROOT,check=True,capture_output=True)
    registration=read(OUT/'vul4py-registration.json')
    plans={r['id']:r for r in read(OUT/'vul4py-source-plan.json')['records']}
    cves={r['id']:r for r in read(OUT/'vul4py-cve-records.json')['records']}
    groups=sources();records=[];case_rows=[]
    for case in registration['selected']:
        cve=case['vuln_id'];plan=plans[cve]
        label=cves[cve]
        cwes=sorted({d['cweId'] for t in label.get('record',{}).get('containers',{}).get('cna',{}).get('problemTypes',[])
                    for d in t.get('descriptions',[]) if d.get('cweId')})
        for role in ['vulnerable','fixed']:
            files={p:s for p,s in groups[cve,role].items() if application(p)}
            errors=[];locations=[]
            for p,s in files.items():
                patch=next(f for f in plan['files'] if (f['old_path'] if role=='vulnerable' else f['path'])==p)
                try:locations.extend(dict(u,path=p) for u in units(s,patch,role))
                except (SyntaxError,ValueError) as exc:errors.append(dict(path=p,error=str(exc)))
            fs=normalize_findings(SASTScanner().scan(ScanContext(files,{},ProjectProfile(),RuleLoader(),{})))
            alerts=[f.to_dict() for f in fs]
            in_units=[f for f in alerts if f['severity']!='INFO' and any(f['file_path']==u['path'] and f['line_number'] is not None
                       and u['start_line']<=f['line_number']<=u['end_line'] for u in locations)]
            records.append(dict(id=cve,role=role,files=len(files),units=locations,alerts=alerts,cna_cwes=cwes,
                strict_cna_cwe_scorable=bool(cwes),strict_cna_cwe_unit_matches=[f for f in in_units if f['cwe'] in cwes],
                all_alerts_in_repair_units=in_units,unit_errors=errors,scanner_errors=[f for f in alerts if f['rule_id']=='PY-PARSE-001']))
        case_rows.append(dict(id=cve,repository=case['repository'],runtime_status='not_run',
            reason='Changed test files retained; full upstream dependency/service environment and paired functional/exploit oracles not locally verified.'))
        print(cve,[(r['role'],len(r['alerts']),len(r['strict_cna_cwe_unit_matches'])) for r in records if r['id']==cve],flush=True)
    assert len(records)==20
    summary=dict(cases=10,snapshots=20,source_files=sum(r['files'] for r in records),
        strict_cna_cwe_vulnerable_match_cases=sorted({r['id'] for r in records if r['role']=='vulnerable' and r['strict_cna_cwe_unit_matches']}),
        strict_cna_cwe_patched_match_cases=sorted({r['id'] for r in records if r['role']=='fixed' and r['strict_cna_cwe_unit_matches']}),
        strict_cna_cwe_unscorable_cases=sorted({r['id'] for r in records if not r['strict_cna_cwe_scorable']}),
        alerts=sum(len(r['alerts']) for r in records),scanner_errors=sum(len(r['scanner_errors']) for r in records),unit_errors=sum(len(r['unit_errors']) for r in records))
    write(PILOT/'default.json',dict(implementation_revision=FREEZE,records=records,summary=summary,runtime_attempts=case_rows,
        independent_label_origin='External Vul4Py fix metadata and CVE CNA records; source-location proxy derived by Theron authors',
        independent_human_adjudication=False,upstream_oracles_locally_verified=False,
        interpretation='Frozen ten-project changed-file pilot selected before source inspection. Function/hunk+CWE proxy only, not independently adjudicated recall/precision. Missing full-repository context and all not-run runtime oracles retained. No source tuning after exposure.'))
    print(summary,flush=True)


if __name__=='__main__':main()
