"""Fail closed on changed membership, source hashes, freezes or reported outcomes."""
import hashlib
import json
import subprocess
from pathlib import Path
from scripts.evaluate_final_realcode import ROOT,read,write
from scripts.evaluate_obligations import OUT,CACHE,FREEZE,functions


def main():
    subprocess.run(['git','diff','--exit-code',FREEZE,'--','scanner','rules'],cwd=ROOT,check=True,capture_output=True)
    candidates=read(OUT/'candidates.json')['records']
    assert len(candidates)==6 and len({r['id'] for r in candidates})==6
    ids={r['id'] for r in candidates}
    external=read(OUT/'external-cve-records.json')
    assert {r['id'] for r in external}==ids
    corroboration=[]
    for r in external:
        expected=next(c for c in candidates if c['id']==r['id'])
        assert hashlib.sha256(json.dumps(r['record'],sort_keys=True).encode()).hexdigest()==expected['metadata_sha256']
        assert r['record']['cveMetadata']['cveId']==r['id']
        cna=r['record']['containers']['cna']
        corroboration.append(dict(id=r['id'],record_state=r['record']['cveMetadata']['state'],
            cwes=sorted({d['cweId'] for t in cna.get('problemTypes',[]) for d in t.get('descriptions',[]) if d.get('cweId')}),
            references=[ref['url'] for ref in cna.get('references',[])],independent_human_adjudication=False))
    write(OUT/'label-corroboration.json',dict(records=corroboration,metadata_hashes_match_registration=True,
        labels='External CVE records corroborate advisory identity; author-derived function units and Theron alerts lack independent adjudication.'))
    source_checks=0
    for filename in ['source-receipts.json','runtime-source-receipts.json']:
        for r in read(OUT/filename)['records']:
            if 'error' in r:continue
            assert hashlib.sha256((CACHE/r['id']/r['role']/r['path']).read_bytes()).hexdigest()==r['source_sha256']
            source_checks+=1
    import ast
    units=0
    for mode in ['default','no-auth','no-crypto','no-protocol']:
        report=read(OUT/(mode+'.json'))
        assert report['implementation_revision']==FREEZE
        assert {(r['id'],r['role']) for r in report['records']}=={(c,role) for c in ids for role in ['vulnerable','fixed']}
        assert not report['summary']['scanner_errors']
        for r in report['records']:
            for u in r['units']:
                code=(CACHE/r['id']/r['role']/u['path']).read_text(encoding='utf-8-sig')
                node=dict(functions(ast.parse(code).body))[u['function']]
                assert (node.lineno,node.end_lineno)==(u['start_line'],u['end_line'])
                assert hashlib.sha256('\n'.join(code.splitlines()[node.lineno-1:node.end_lineno]).encode()).hexdigest()==u['snippet_sha256']
                units+=1
    assert read(OUT/'default.json')['summary']['vulnerable_cases_with_obligation_candidates']==['CVE-2026-82411']
    assert read(OUT/'default.json')['summary']['patched_cases_with_obligation_candidates']==[]
    assert read(OUT/'no-auth.json')['summary']['vulnerable_cases_with_obligation_candidates']==[]
    assert read(OUT/'default.json')['summary']['strict_cna_cwe_vulnerable_match_cases']==[]
    assert read(OUT/'default.json')['summary']['strict_cna_cwe_unscorable_cases']==['CVE-2024-33663']
    runtime=read(OUT/'runtime.json')
    assert {r['id'] for r in runtime['records']}==ids
    assert runtime['dependency_wheels']==read(OUT/'runtime-dependencies.json')
    for name,digest in runtime['harness_sha256'].items():
        assert hashlib.sha256((ROOT/'scripts'/name).read_bytes()).hexdigest()==digest
    probe=json.loads(runtime['probe']['output'])
    assert probe==dict(windows_visible=False,home_visible=False,network_result=101)
    for r in runtime['records']:
        if r['id']=='CVE-2026-58373':
            assert r['status']=='not_run';continue
        result=r['result'];assert not result['timed_out']
        if r['oracle_kind']=='upstream_unmodified':
            assert result['exit_code']==(1 if r['role']=='vulnerable' else 0)
            assert ('10 failed, 3 passed' if r['role']=='vulnerable' else '13 passed') in result['output']
        else:
            assert result['exit_code']==0
            assert json.loads(result['output'])['accepted']==(r['role']=='vulnerable')
    baseline=read(OUT/'baselines.json')
    assert all(r['covered_files']==28 and not r['errors'] for r in baseline['tools'].values())
    assert all(not u['alerts_in_reference_functions'] for r in baseline['tools'].values() for u in r['units'])
    assert all(r['case_outcomes_and_alert_counts_unchanged'] for r in read(OUT/'synthetic-summary.json')['partitions'].values())
    smoke=read(OUT/'offline-selfscan.json')
    assert smoke['status']=='completed' and smoke['wall_seconds']<smoke['limit_seconds']
    write(OUT/'evidence-audit.json',dict(implementation_revision=FREEZE,metadata_hash_checks=6,
        source_receipt_hash_checks=source_checks,mechanism_function_hash_checks_across_modes=units,
        all_six_cases_retained=True,scanner_freeze_unchanged=True,baseline_membership_verified=True,
        runtime_results_separate_from_static_detection=True,independent_human_adjudication=False))
    artifacts={}
    for path in sorted(OUT.iterdir()):
        if path.is_file() and path.name!='artifact-manifest.json':
            artifacts[path.name]=hashlib.sha256(path.read_text(encoding='utf-8-sig').replace('\r\n','\n').encode()).hexdigest()
    write(OUT/'artifact-manifest.json',dict(hash_format='SHA-256 of UTF-8 text with LF newlines and no BOM',files=artifacts))
    print('Evidence audit passed:',len(artifacts),'artifacts;',source_checks,'source receipts;',units,'function checks')


if __name__=='__main__':main()
