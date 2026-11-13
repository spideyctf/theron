"""Reference-unit identity and source-integrity controls, using original data."""
import hashlib

import pytest

from scripts.evaluate_audited_units import matches_unit,checked_source


def test_audited_template_matching_requires_source_and_exact_unit():
    unit=dict(path='app.py',sink_line=7,cwe='CWE-1336')
    alert=dict(file_path='app.py',line_number=7,cwe='CWE-1336',evidence_kind='static-flow',trace=[dict(role='source')])
    assert matches_unit(alert,unit)
    for change in [dict(cwe='CWE-94'),dict(line_number=8),dict(file_path='other.py'),dict(trace=[]),dict(evidence_kind='static-pattern')]:
        assert not matches_unit(dict(alert,**change),unit)


def test_pinned_source_bytes_and_cache_boundary(tmp_path):
    source=b'# inert original fixture\n'
    row=dict(cve_id='case',role='vul_func',revision='a'*40,path='app.py',source_sha256=hashlib.sha256(source).hexdigest())
    file=tmp_path/'case/vul_func'/('a'*40)/'app.py'
    file.parent.mkdir(parents=True); file.write_bytes(source)
    assert checked_source(tmp_path,row)==source.decode()
    file.write_bytes(b'changed')
    with pytest.raises(ValueError,match='bytes changed'):
        checked_source(tmp_path,row)
    with pytest.raises(ValueError,match='outside'):
        checked_source(tmp_path,dict(row,path='../../../../outside.py'))
