"""Original tool-output fixtures, no datasets or external tool processes."""
import json

import pytest

from scripts.evaluate_step5 import checked_path, external_records, relative_path
from scripts.summarize_step5 import draft_match


def test_stage_paths_cannot_escape_and_baseline_paths_must_belong_to_track(tmp_path):
    assert checked_path(tmp_path,'realcode/file.py').is_relative_to(tmp_path)
    with pytest.raises(ValueError,match='outside'):
        checked_path(tmp_path,'../private.py')
    assert relative_path('D:\\stage\\owasp\\test\\testcode\\case.py','owasp/test')=='testcode/case.py'
    with pytest.raises(ValueError):
        relative_path('/somewhere/else.py','realcode')
    with pytest.raises(ValueError):
        relative_path('/stage/realcode/../outside.py','realcode')


def test_bandit_mapping_retains_errors_and_omits_source_and_messages():
    raw={'metrics':{'/stage/realcode/a.py':{},'_totals':{}},'results':[
        dict(filename='/stage/realcode/a.py',test_id='B307',issue_cwe={'id':78},line_number=5,
             line_range=[5,6],
             issue_severity='MEDIUM',issue_confidence='HIGH',code='SECRET_SOURCE_BODY',issue_text='PRIVATE_MESSAGE')],
         'errors':[dict(filename='/stage/realcode/b.py',reason='PRIVATE_ERROR_SOURCE')]}
    result=external_records(raw,'bandit','realcode',{'a.py','b.py'})
    assert result['covered_files']==2 and result['alerts'][0]['cwes']==['CWE-94']
    assert result['alerts'][0]['end_line_number']==6
    assert result['errors'][0]['path']=='b.py'
    assert not any(value in json.dumps(result) for value in ['SECRET_SOURCE_BODY','PRIVATE_MESSAGE','PRIVATE_ERROR_SOURCE'])


def test_missing_coverage_does_not_become_a_clean_negative():
    with pytest.raises(ValueError,match='coverage'):
        external_records({'metrics':{},'results':[]},'bandit','realcode',{'a.py'})


def test_semgrep_keeps_all_cwes_and_only_maps_weak_hash_rule():
    def item(rule):
        return dict(path='/stage/realcode/a.py',check_id=rule,start={'line':8},
                    extra={'metadata':{'cwe':['CWE-327: cryptography','CWE-200: exposure'],'confidence':'LOW'},
                           'severity':'WARNING','lines':'PRIVATE_CODE'})
    raw={'paths':{'scanned':['/stage/realcode/a.py']},'results':[item('python.insecure-hash'),item('python.weak-cipher')],'errors':[]}
    result=external_records(raw,'semgrep','realcode',{'a.py'})
    assert result['alerts'][0]['cwes']==['CWE-200','CWE-327','CWE-328']
    assert result['alerts'][1]['cwes']==['CWE-200','CWE-327']
    assert 'PRIVATE_CODE' not in json.dumps(result)


@pytest.mark.parametrize('line',[None,0,-1,True])
def test_unassigned_or_invalid_target_never_becomes_a_false_negative(line):
    if line is None:
        assert draft_match([],'a.py',['CWE-22'],line) is None
    else:
        with pytest.raises(ValueError):
            draft_match([],'a.py',['CWE-22'],line)


def test_draft_match_requires_file_cwe_line_and_excludes_notices():
    alert=dict(path='a.py',cwes=['CWE-22','CWE-73'],line_number=5)
    assert draft_match([alert],'a.py',['CWE-22'],5)
    assert not draft_match([alert],'other.py',['CWE-22'],5)
    assert not draft_match([alert],'a.py',['CWE-601'],5)
    assert not draft_match([alert],'a.py',['CWE-22'],6)
    assert not draft_match([dict(alert,evidence_kind='coverage-notice')],'a.py',['CWE-22'],5)
