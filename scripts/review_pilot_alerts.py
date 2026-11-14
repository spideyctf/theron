"""Action-level author review of the frozen exposed pilot; not independent labels."""
import ast
from collections import Counter
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'docs/evaluation/evidence-2026-11-14'


def main():
    frozen=json.loads((OUT/'development.json').read_text())
    receipts=json.loads((ROOT/'docs/evaluation/mechanisms-2026-11-14/vul4py/source-receipts.json').read_text())['records']
    hashes={(r['id'],r['role'],r['path']):r['source_sha256'] for r in receipts if 'source_sha256' in r}
    oracles={
        'PY-OBL-MCP-VALIDATION-001':('mcp-oracle.json','tests/issues/test_malformed_input.py',
            'Uncaught model validation in the per-message receive loop; upstream malformed-message assertions distinguish revisions on asyncio/trio.',False),
        'PY-OBL-TLS-POOL-001':('requests-oracle.json','tests/test_requests.py::TestPreparingURLs::test_different_connection_pool_for_tls_settings',
            'Certificate policy is mutated after pool selection. An unchanged upstream assertion distinguishes revisions using a disclosed socketpair TLS transport.',True),
        'PY-OBL-AI-CAPABILITY-001':('smolagents-oracle.json','tests/test_local_python_executor.py::TestLocalPythonExecutorSecurity::test_vulnerability_via_submodules_through_indirect_attribute_access',
            'A raw tool registry lookup bypasses the wrapper introduced by the repair. Upstream map/filter module-access assertions distinguish revisions.',False),
        'PY-OBL-HTML-ORDER-001':('../mechanisms-2026-11-14/vul4py/runtime.json','html_sanitizer/tests.py::SanitizerTestCase::test_normalize_early',
            'Compatibility normalization after cleaning reintroduces markup; upstream normalization assertion distinguishes revisions.',False)}
    rows=[]
    for record in frozen['records']:
        if record['partition']!='ten-exposed':continue
        for alert in record['alerts']:
            path=alert['file_path'];raw=(ROOT/'.benchmark-cache/vul4py-pilot'/record['id']/record['role']/path).read_bytes()
            digest=hashlib.sha256(raw).hexdigest();assert digest==hashes[record['id'],record['role'],path]
            source=raw.decode('utf-8-sig');lines=source.splitlines();line=alert['line_number'];tree=ast.parse(source)
            nodes=[n for n in ast.walk(tree) if getattr(n,'lineno',0)==line and isinstance(n,(ast.Call,ast.Return,ast.Assign))]
            action=min(nodes,key=lambda n:n.end_lineno-n.lineno);action_text=ast.get_source_segment(source,action)
            functions=[n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.lineno<=line<=n.end_lineno]
            function=min(functions,key=lambda n:n.end_lineno-n.lineno)
            rule=alert['rule_id'];runtime=None
            if rule in oracles:
                receipt,test,reason,adapted=oracles[rule]
                runtime=json.loads((OUT/receipt).read_text())
                checks=runtime['records']
                if rule=='PY-OBL-HTML-ORDER-001':
                    assert any(r['role']=='vulnerable' and r['result']['exit_code']==1 for r in checks)
                    assert any(r['role']=='fixed' and r['result']['exit_code']==0 for r in checks)
                else:
                    assert {(r['role'],r['phase']) for r in checks}=={(a,b) for a in ['vulnerable','fixed'] for b in ['security','functional']}
                    assert all(r['result']['exit_code']==0 and not r['result']['timed_out'] for r in checks if r['role']=='fixed' or r['phase']=='functional')
                    assert all(r['result']['exit_code']==1 and not r['result']['timed_out'] for r in checks if r['role']=='vulnerable' and r['phase']=='security')
                    expected_failures={'PY-OBL-MCP-VALIDATION-001':4,'PY-OBL-TLS-POOL-001':1,'PY-OBL-AI-CAPABILITY-001':3}[rule]
                    assert all('TARGET_MODULE /target/src/' in r['result']['output'] for r in checks)
                    assert any(f'{expected_failures} failed' in r['result']['output'] for r in checks if r['role']=='vulnerable' and r['phase']=='security')
                status='runtime_corroborated_mechanism'
                evidence=dict(receipt=receipt,upstream_test=test,author_adapted_transport=adapted,
                              receipt_sha256=hashlib.sha256((OUT/receipt).read_bytes()).hexdigest())
            elif rule=='PY-SAST-HASH-001':
                status='non_security_use_observed'
                reason=('Visible use derives ETags/cache change identifiers or UI plugin-list fingerprints, not passwords, signatures or an authentication proof. '
                        'No demonstrated collision attack or deployed security consequence; do not count as a confirmed vulnerability or this CVE detection.')
                evidence=dict(observed_role='UI plugin-list fingerprint' if path.endswith('sockjs.py') else 'ETag/cache identifier')
            elif rule=='PY-SAST-REDIRECT-001':
                assert 'validate_local_redirect(redirect_url, allowed_paths)' in ast.get_source_segment(source,function)
                status='unresolved_custom_guard'
                reason=('The same function calls a project-specific redirect validator and replaces rejected destinations before this redirect. '
                        'The scanner does not model that helper. Its presence does not prove the guard or deployment configuration safe; this alert is not confirmed.')
                evidence=dict(observed_guard='validate_local_redirect',guard_status='observed, semantics not adjudicated')
            else:raise ValueError('Unreviewed rule '+rule)
            rows.append(dict(id=record['id'],role=record['role'],rule_id=rule,fingerprint=alert['fingerprint'],
                path=path,line=line,source_sha256=digest,function=function.name,function_start=function.lineno,function_end=function.end_lineno,
                function_sha256=hashlib.sha256(ast.get_source_segment(source,function).encode()).hexdigest(),
                action=action_text,action_sha256=hashlib.sha256(action_text.encode()).hexdigest(),
                assessment=status,rationale=reason,external_evidence=evidence,
                independent_human_adjudication=False,deployment_exploitability_confirmed=False))
    assert len(rows)==14
    result=dict(detector_revision=frozen['implementation_revision'],review_kind='assistant_source_review_corroborated_by_selected_upstream_tests',
        independent_human_labels=False,untouched_evaluation=False,records=rows,summary=dict(Counter(r['assessment'] for r in rows)),
        interpretation='Exact source/action/function hashes and external test receipts refine the original CWE/patch proxy. Four mechanisms are runtime-corroborated, eight hash occurrences have visible non-security uses, and two redirect occurrences retain an unmodelled custom guard. These categories are not an independent alert-precision estimate, whole-application exploit proof, or new vulnerability discoveries. Historical detections and labels are unchanged.')
    (OUT/'individual-alert-review.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(result['summary'])


if __name__=='__main__':main()
