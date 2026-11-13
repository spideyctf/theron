"""Research adapters retain errors and do not turn patch roles into clean labels."""
from scripts.evaluate_final_realcode import summarize, checked_path
from scripts.evaluate_real_validation import reference_matches
import pytest


def test_hash_error_excludes_whole_case_and_preserves_alert_burden():
    rows=[dict(cve_id='A',role='vul_func',alerts=[{}],reference_matches=[{}]),
          dict(cve_id='A',role='vul_func',alerts=[],label_error='hash mismatch'),
          dict(cve_id='B',role='vul_func',alerts=[],reference_matches=[]),
          dict(cve_id='B',role='fix_func',alerts=[{}],reference_matches=[{}])]
    result=summarize(rows)
    assert result['vulnerable']['total_cases']==2
    assert result['vulnerable']['hash_verified_cases']==1
    assert result['vulnerable']['reference_match_count']==0
    assert result['vulnerable']['excluded_error_cases']==['A']
    assert result['patched']['reference_match_cases']==['B']
    assert result['whole_file_alerts']==2 and result['label_errors']==1


def test_reference_proxy_keeps_declared_cwe_span_and_excludes_notices():
    alerts=[dict(cwe='CWE-89',line_number=10,evidence_kind='static-flow'),
            dict(cwe='CWE-89',line_number=10,evidence_kind='coverage-notice'),
            dict(cwe='CWE-22',line_number=10,evidence_kind='static-flow'),
            dict(cwe='CWE-89',line_number=21,evidence_kind='static-flow')]
    assert reference_matches(alerts,['CWE-89'],10,20)==alerts[:1]


def test_input_stage_rejects_paths_outside_root(tmp_path):
    with pytest.raises(ValueError,match='outside'):
        checked_path(tmp_path,'../other.py')


def test_operational_queue_failure_and_recovery_contract():
    from scripts.evaluate_operations import api_contract
    result=api_contract()
    assert result['completed_jobs']==9 and result['failed_jobs']==1
    assert result['overflow_status']==429 and result['failure_secret_redacted']
