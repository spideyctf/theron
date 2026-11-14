"""Audit the current checkpoint without relabelling its adverse external result."""
import hashlib
import json
from pathlib import Path
import subprocess
from scripts.evaluate_final_realcode import ROOT,read,write
from scripts.evaluate_mechanisms import OUT
from scripts.check_mechanism_optimization import OPTIMIZATION


def normalized(path):return path.read_text(encoding='utf-8-sig').replace('\r\n','\n').encode()


def main():
    subprocess.run(['git','diff','--exit-code',OPTIMIZATION,'--','scanner','rules'],cwd=ROOT,check=True,capture_output=True)
    registered=json.loads(subprocess.check_output(['git','show','22522ae:docs/evaluation/mechanisms-2026-11-14/vul4py-registration.json'],cwd=ROOT))
    assert registered==read(OUT/'vul4py-registration.json')
    assert hashlib.sha256(normalized(OUT/'vul4py-metadata.csv')).hexdigest()==registered['metadata_sha256']
    ids={r['vuln_id'] for r in registered['selected']};assert len(ids)==10
    aliases={}
    for case in read(ROOT/'docs/evaluation/realworld-2026-11-12/manifest.json')['cases']:
        identity=case.get('repository_identity',{})
        for value in [case['repository'],identity.get('canonical'),identity.get('root'),*identity.get('aliases',[])]:
            if isinstance(value,str):aliases[value.lower()]=case['cve_id']
    overlaps=[dict(id=r['vuln_id'],repository=r['repository'],previous_case=aliases[r['repository'].lower()],
        reason='Initial selection excluded raw repository names but omitted known canonical aliases')
        for r in registered['selected'] if r['repository'].lower() in aliases]
    overlap_ids={r['id'] for r in overlaps}
    assert overlap_ids=={'CVE-2024-35195'}
    write(OUT/'vul4py/overlap-audit.json',dict(records=overlaps,original_membership_retained=True,
        clean_project_subset_cases=9,clean_project_subset_cna_labelled_cases=7,
        interpretation='One project alias overlap invalidates a fully project-disjoint ten-case claim. No case replaced after exposure; future selection guard includes canonical names and aliases.'))
    checks=0;absent=0
    for filename in ['vul4py-source-receipts.json','vul4py-runtime-sources.json']:
        for r in read(OUT/filename)['records']:
            if r.get('expected_absent'):absent+=1;continue
            assert not r.get('error'),r
            raw=(ROOT/'.benchmark-cache/vul4py-pilot'/r['id']/r['role']/r['path']).read_bytes()
            assert hashlib.sha256(raw).hexdigest()==r['source_sha256']
            assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==r['git_blob_sha']
            checks+=1
    pilot=read(OUT/'vul4py/default.json')
    assert {(r['id'],r['role']) for r in pilot['records']}=={(c,role) for c in ids for role in ['vulnerable','fixed']}
    assert pilot['summary']['source_files']==46 and pilot['summary']['scanner_errors']==pilot['summary']['unit_errors']==0
    assert pilot['summary']['strict_cna_cwe_vulnerable_match_cases']==[]
    assert len(pilot['summary']['strict_cna_cwe_unscorable_cases'])==2
    runtime=read(OUT/'vul4py/runtime.json')
    for r in runtime['records']:
        expected='1 failed, 1 passed' if r['role']=='vulnerable' else '2 passed'
        assert expected in r['result']['output'] and not r['result']['timed_out']
        assert r['result']['exit_code']==(1 if r['role']=='vulnerable' else 0)
    for name,digest in runtime['harness_sha256'].items():assert hashlib.sha256(normalized(ROOT/'scripts'/name)).hexdigest()==digest
    assert runtime['dependency_wheels']==read(OUT/'vul4py/runtime-dependencies.json')
    baseline=read(OUT/'vul4py/baselines.json')
    assert all(r['covered_files']==46 and not r['errors'] for r in baseline['tools'].values())
    for tool,r in baseline['tools'].items():assert hashlib.sha256((OUT/'vul4py'/(tool+'-raw.json')).read_bytes()).hexdigest()==r['raw_report_sha256']
    equivalent=read(OUT/'optimization-equivalence.json')
    assert equivalent['implementation_revision']==OPTIMIZATION and len(equivalent['records'])==32
    assert all(r['alerts_unchanged'] for r in equivalent['records'])
    assert all(r['case_outcomes_and_alert_counts_unchanged'] for r in read(OUT/'final-regression/synthetic-summary.json')['partitions'].values())
    smoke=read(OUT/'offline-selfscan.json');assert smoke['status']=='completed' and smoke['wall_seconds']<120
    assert read(OUT/'offline-selfscan-initial.json')['status']=='failed'
    assert read(OUT/'offline-selfscan-import-gate.json')['status']=='failed'
    cases=[dict(id=r['vuln_id'],repository=r['repository'],prior_project_overlap=r['vuln_id'] in overlap_ids,
        static_status='no_strict_match' if r['vuln_id'] not in pilot['summary']['strict_cna_cwe_unscorable_cases'] else 'cna_cwe_missing',
        runtime_status='upstream_security_and_functional_pair_verified' if r['vuln_id']=='CVE-2024-34078' else 'not_run') for r in registered['selected']]
    write(OUT/'vul4py/case-ledger.json',dict(records=cases,full_vul4py_acceptance=False,independent_human_review=False))
    write(OUT/'readiness.json',dict(implementation_revision=OPTIMIZATION,research_ready=False,
        engineering='688 Python tests, 15 frontend tests and build passed',
        exposed_development=dict(vulnerable_semantic_candidates=5,cases=6,strict_cna_matches=2,strict_labelled_cases=5),
        external_pilot=dict(strict_matches=0,labelled_cases=8,unscorable_cases=2,prior_project_alias_overlap_cases=1,
            clean_project_subset_cases=9,clean_project_subset_labelled_cases=7,clean_project_subset_strict_matches=0,
            upstream_paired_cases_verified=1,runtime_not_run=9),
        operational_smoke=dict(status='completed',wall_seconds=smoke['wall_seconds'],limit_seconds=120,earlier_timeouts_retained=2),
        unmet=['fresh real-code generalization','complete upstream oracle validation','custom IAM/remaining detection models',
               'independent vulnerability-location/alert validation','measured cross-layer benefit','broader platform coverage and production validation','defensible contribution relative to related work']))
    write(OUT/'evidence-audit.json',dict(source_sha256_and_git_blob_checks=checks,expected_absent_files=absent,
        registered_cases_retained=10,registration_unchanged=True,prior_project_alias_overlaps=1,full_alert_equivalence_groups=32,
        synthetic_variants_unchanged=1470,earlier_failures_retained=True,independent_human_review=False))
    files={p.relative_to(OUT).as_posix():hashlib.sha256(normalized(p)).hexdigest() for p in sorted(OUT.rglob('*'))
           if p.is_file() and p.name!='artifact-manifest.json'}
    write(OUT/'artifact-manifest.json',dict(hash_format='SHA-256 of UTF-8 text normalized to LF without BOM; raw baseline hashes additionally retained in baselines.json',files=files))
    print('Audit passed:',checks,'source receipts;',len(files),'artifacts; research_ready=false')


if __name__=='__main__':main()
