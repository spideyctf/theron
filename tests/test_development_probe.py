import pytest

from scanner.realworld_audit import snippet_digest
from scripts.probe_realworld_development import probe


def sample(tmp_path):
    source='raise AssertionError("target must never execute")\n'
    for role in ['vul_func','fix_func']:
        path=tmp_path/'CVE-2026-10000'/role/'app.py'
        path.parent.mkdir(parents=True)
        path.write_text(source)
    return {'membership_sha256':'frozen','cases':[{'cve_id':'CVE-2026-10000','partition':'development','locations':[
        dict(role=role,path='app.py',start_line=1,end_line=1,snippet_sha256=snippet_digest(source),resolution={'sha':'a'*40})
        for role in ['vul_func','fix_func']]}]}


def test_probe_preserves_modes_hashes_and_pending_labels_without_execution(tmp_path):
    manifest=sample(tmp_path)
    result=probe(manifest,['CVE-2026-10000'],tmp_path)
    assert result['scorable_cases']==0 and not result['independent_labels']
    assert len(result['records'])==2
    assert all(r['declared_function_hashes_match'] and r['modes']=={'default':[],'experimental':[]} for r in result['records'])
    manifest['cases'][0]['locations'][0]['snippet_sha256']='wrong'
    assert probe(manifest,['CVE-2026-10000'],tmp_path)['records'][0]['error']=='ValueError'


def test_probe_rejects_reserved_cases_and_duplicates_before_reading(tmp_path):
    manifest=sample(tmp_path)
    with pytest.raises(ValueError,match='unique'):
        probe(manifest,['CVE-2026-10000']*2,tmp_path)
    manifest['cases'][0]['partition']='test'
    with pytest.raises(ValueError,match='only.*development'):
        probe(manifest,['CVE-2026-10000'],tmp_path)


def test_probe_rejects_path_escape(tmp_path):
    manifest=sample(tmp_path)
    manifest['cases'][0]['locations'][0]['path']='../../../outside.py'
    with pytest.raises(ValueError,match='escapes'):
        probe(manifest,['CVE-2026-10000'],tmp_path)
