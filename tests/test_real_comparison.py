"""Original controls for bounded real-source evaluation context."""
import hashlib
import pytest

from scripts.compare_real_validation import context_inventory,key
from scripts.evaluate_step5 import checked_path,external_records
from scripts.verify_real_stage import verify


def test_grouped_context_records_only_supplied_module_resolutions():
    result=context_inventory({'entry.py':'from helper import action\nimport os\nimport missing',
                              'helper.py':'def action():\n pass'})
    available=[r['module'] for r in result['imports'] if r['available']]
    assert available==['helper']
    assert result['files']==2 and result['unresolved_import_candidates']==3


def test_stage_identity_keeps_roles_and_revisions_separate(tmp_path):
    row=dict(cve_id='case',role='vul_func',revision='a'*40,path='package/app.py')
    assert key(row)!=key(dict(row,role='fix_func'))
    assert key(row)!=key(dict(row,revision='b'*40))
    with pytest.raises(ValueError):
        checked_path(tmp_path,'../outside.py')


def test_baseline_info_is_retained_with_cwe_and_end_line():
    report=dict(paths=dict(scanned=['/tmp/stage/real-validation/case/app.py']),errors=[],
                results=[dict(path='/tmp/stage/real-validation/case/app.py',check_id='original-rule',
                              start=dict(line=3),end=dict(line=7),extra=dict(severity='INFO',metadata=dict(cwe=['CWE-22'])))])
    result=external_records(report,'semgrep','real-validation',{'case/app.py'})
    assert result['alerts'][0]['severity']=='INFO'
    assert result['alerts'][0]['end_line_number']==7
    assert result['alerts'][0]['cwes']==['CWE-22']


def test_native_byte_verifier_rejects_line_ending_changes(tmp_path):
    file=tmp_path/'real-validation/app.py'
    file.parent.mkdir()
    raw=b'x=1\r\n'
    file.write_bytes(raw)
    inventory={'real-validation/app.py':hashlib.sha256(raw).hexdigest()}
    assert verify(tmp_path,inventory)['source_files']==1
    file.write_bytes(b'x=1\n')
    with pytest.raises(ValueError,match='bytes differ'):
        verify(tmp_path,inventory)
