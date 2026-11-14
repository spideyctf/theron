"""Summarize selected upstream/adapted execution without treating every failure as a vulnerability."""
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'docs/evaluation/evidence-2026-11-14'
PAIRS=[('mcp','upstream_unmodified',4),('pymdown','upstream_unmodified',1),
       ('smolagents','upstream_unmodified',3),('sigstore','upstream_unmodified',1),
       ('requests','upstream_body_adapted_transport',1),('owlmixin','upstream_body_adapted_environment',1),
       ('urllib3','author_derived_adapter',None)]


def main():
    rows=[]
    for name,kind,failures in PAIRS:
        path=OUT/(name+'-oracle.json');data=json.loads(path.read_text())
        records=data['records'];adapter=name=='urllib3'
        security='security_adapter' if adapter else 'security'
        functional='functional_adapter' if adapter else 'functional'
        assert {(r['role'],r['phase']) for r in records}=={(a,b) for a in ['vulnerable','fixed'] for b in [security,functional]}
        for r in records:
            result=r['result']
            assert not result['timed_out'] and not result['output_truncated']
            assert 'TARGET_MODULE /target/' in result['output']
            vulnerable=r['role']=='vulnerable' and r['phase']==security
            assert result['exit_code']==(1 if vulnerable else 0)
            if vulnerable:
                if failures:
                    assert f'{failures} failed' in result['output'],name
                    expected={'mcp':'ValidationError','pymdown':'SnippetMissingError not raised'}.get(name,'DID NOT RAISE')
                    assert expected in result['output'],name
                else:assert '"accepted": true, "hostname_rejected": false' in result['output']
        rows.append(dict(project=name,evidence_kind=kind,selected_pair_distinguishes_revisions=True,
                         legitimate_control_passes_both=True,receipt=path.name,complete_upstream_suite=False))
    html=ROOT/'docs/evaluation/mechanisms-2026-11-14/vul4py/runtime.json'
    records=json.loads(html.read_text())['records']
    assert any(r.get('id')=='CVE-2024-34078' and r['role']=='vulnerable' and '1 failed, 1 passed' in r['result']['output'] for r in records)
    assert any(r.get('id')=='CVE-2024-34078' and r['role']=='fixed' and '2 passed' in r['result']['output'] for r in records)
    rows.append(dict(project='html-sanitizer',evidence_kind='upstream_unmodified',selected_pair_distinguishes_revisions=True,
                     legitimate_control_passes_both=True,receipt='../mechanisms-2026-11-14/vul4py/runtime.json',complete_upstream_suite=False))
    for name in ['sqlparse','octoprint']:
        data=json.loads((OUT/(name+'-oracle.json')).read_text())
        functional='functional_suite' if name=='sqlparse' else 'functional'
        controls=[r for r in data['records'] if r['phase']==functional]
        assert len(controls)==2 and all(r['result']['exit_code']==0 and not r['result']['timed_out'] and not r['result']['output_truncated'] for r in controls)
        if name=='sqlparse':assert all(r['result']['exit_code']==0 for r in data['records'])
        else:
            checks=[r for r in data['records'] if r['phase']=='new_api_regression']
            assert any(r['role']=='vulnerable' and 'AttributeError' in r['result']['output'] and '15 failed' in r['result']['output'] for r in checks)
            assert any(r['role']=='fixed' and r['result']['exit_code']==0 and '15 passed' in r['result']['output'] for r in checks)
        behavior_name='sqlparse-resource-oracle.json' if name=='sqlparse' else 'octoprint-identity-oracle.json'
        behavior=json.loads((OUT/behavior_name).read_text())
        for r in behavior['records']:
            result=r['result'];negative=r['role']=='vulnerable' and r['phase'] in {'resource_adapter','security_adapter'}
            assert result['exit_code']==(1 if negative else 0)
            assert not result['timed_out'] and not result['output_truncated']
        if name=='sqlparse':
            assert len(behavior['records'])==2
            assert '"completed": false' in behavior['records'][0]['result']['output']
            assert '"completed": true' in behavior['records'][1]['result']['output']
        else:
            assert len(behavior['records'])==4
            assert any('"returned": "127.0.0.1"' in r['result']['output'] for r in behavior['records'] if r['role']=='vulnerable')
            assert any('"returned": "203.0.113.21"' in r['result']['output'] for r in behavior['records'] if r['role']=='fixed')
        rows.append(dict(project=name,evidence_kind='author_derived_adapter',selected_pair_distinguishes_revisions=True,
            legitimate_control_passes_both=True,receipt=name+'-oracle.json',behavior_receipt=behavior_name,complete_upstream_suite=False,
            original_upstream_patch_test_discriminates_security=False))
    assert len(rows)==10
    result=dict(records=rows,pilot_projects_with_execution_receipts=10,
        selected_behavior_pairs=10,unmodified_upstream_pairs=5,adapted_upstream_pairs=2,author_derived_pairs=3,
        original_patch_checks_without_security_discrimination=2,complete_upstream_suite_acceptance=False,independent_human_adjudication=False,
        cvat=dict(status='not_run',reason='Docker Linux engine unavailable. Desktop startup fails removing stale userAnalyticsOtlpHttp.sock. Automatic approval review rejected the attempted stop/stale-runtime-socket recovery as blocked by policy; no recovery mutation executed.'),
        receipt_sha256_lf={name:hashlib.sha256((OUT/name).read_text().replace('\r\n','\n').encode()).hexdigest() for r in rows for name in [r['receipt']]+([r['behavior_receipt']] if r.get('behavior_receipt') else [])},
        interpretation='Ten exposed development projects, selected checks only. Ten behavior pairs distinguish revisions: five upstream, two adapted upstream and three author-derived. This is not scanner recall, complete upstream security/functional acceptance, deployed exploitation, or independent label adjudication. Original SQLparse/OctoPrint patch-test outcomes remain nondiscriminating or API-incompatible; separate bounded/helper-level adapters provide the paired observations.')
    (OUT/'upstream-summary.json').write_text(json.dumps(result,indent=2)+'\n')
    print({k:v for k,v in result.items() if k not in ['records','receipt_sha256_lf']})


if __name__=='__main__':main()
