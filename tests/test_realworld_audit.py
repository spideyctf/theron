"""Original metadata fixtures; no third-party source or network access."""
import copy
import json

import pytest

from scanner.realworld_audit import check_freeze, frozen_artifacts, write_json


def test_freeze_rejects_redraw_and_tampered_files(tmp_path):
    artifacts = {'manifest.json': {'membership': ['one']}}
    assert not check_freeze(tmp_path, artifacts)
    write_json(tmp_path/'manifest.json', artifacts['manifest.json'])
    write_json(tmp_path/'FREEZE.json', {'artifact_canonical_sha256': frozen_artifacts(artifacts)})
    assert check_freeze(tmp_path, artifacts)
    with pytest.raises(ValueError, match='versioned amendment'):
        check_freeze(tmp_path, {'manifest.json': {'membership': ['two']}})
    write_json(tmp_path/'manifest.json', {})
    with pytest.raises(ValueError, match='modified'):
        check_freeze(tmp_path, artifacts)


def test_fetcher_rejects_source_endpoint_before_network(monkeypatch):
    from scripts.fetch_realworld_metadata import fetch
    monkeypatch.setattr('scripts.fetch_realworld_metadata.subprocess.run', lambda *a, **k: pytest.fail('network called'))
    with pytest.raises(ValueError):
        fetch({'key':'repo:one/project','kind':'repository','repository':'one/project',
               'url':'https://api.github.com/repos/one/project/contents/service.py'})


def test_fetcher_sanitizes_response_and_records_failure(monkeypatch):
    from scripts.fetch_realworld_metadata import fetch
    from types import SimpleNamespace
    query={'key':'repo:one/project','kind':'repository','repository':'one/project',
           'url':'https://api.github.com/repos/one/project'}
    def request(argv, **kwargs):
        assert argv == ['gh','api','--method','GET','repos/one/project']
        return SimpleNamespace(returncode=0, stdout=json.dumps({'full_name':'one/project','description':'private text'}))
    monkeypatch.setattr('scripts.fetch_realworld_metadata.subprocess.run', request)
    result=fetch(query)
    assert result['status']=='ok' and 'private text' not in json.dumps(result)
    monkeypatch.setattr('scripts.fetch_realworld_metadata.subprocess.run', lambda *a, **k: SimpleNamespace(returncode=1))
    assert fetch(query)['status']=='unresolved'

from scanner.realworld_audit import (build_manifest, digest, graph_prefix_candidates, json_digest,
                                    patch_reference, prepare_inputs, queries, repository,
                                    sanitize_metadata, snippet_digest, validate_metadata_query)


def fixtures(projects=('one/project','two/project','three/project','four/project','five/project')):
    rows=[]
    for index,repo in enumerate(projects):
        full_vul=f'{index+1:040x}'
        full_fix=f'{index+101:040x}'
        # Abbreviations retain leading zeros, as valid Git object prefixes can.
        vulnerable={'commit':full_vul,'file_path':'service.py','start_line':2,'end_line':4,
                    'snippet':f'def input_{index}():\n    return "fixture-{index}"\n','vul_localization':[3]}
        fixed={'commit':full_fix,'file_path':'service.py','start_line':2,'end_line':4,
               'snippet':f'def output_{index}():\n    return "control-{index}"\n'}
        rows.append({'cve_id':f'CVE-2026-{1000+index}','repo':'https://github.com/'+repo,
                     'programming_language':'Python','patch_url':[f'https://github.com/{repo}/commit/{full_fix}'],
                     'vul_func':[vulnerable],'fix_func':[fixed],'cwe_info':{'id':'CWE-94'}})
    raw=json.dumps(rows).encode()
    reserve={'revision':'b'*40,'metadata_sha256':digest(raw),'python_cases':len(rows),'cases':[]}
    for row in rows:
        reserve['cases'].append({k:row[k] for k in ['cve_id','repo','programming_language','patch_url']}
                                | {role+'_sha256':json_digest(row[role]) for role in ['vul_func','fix_func']})
    prior=b'CVE,project\n'
    inputs=prepare_inputs(reserve,raw,prior)
    cache={}
    for query in queries(inputs):
        if query['kind']=='repository':
            cache[query['key']]=sanitize_metadata(query,{'full_name':query['repository'],'license':{'spdx_id':'MIT'}})
        else:
            revision=query['requested_revision']
            cache[query['key']]=sanitize_metadata(query,{'sha':revision,'tree':{'sha':'a'*40},'parents':[{'sha':'f'*40}]})
    return inputs,cache,{'hashes':{},'parse_failures':[]},reserve,raw


def test_identity_normalization_and_metadata_endpoint_allowlist():
    assert repository('https://github.com/Owner/Repo.git/')=='owner/repo'
    assert patch_reference('https://github.com/Owner/Repo/commit/abcdef0')==('owner/repo','abcdef0')
    for value in ['https://github.com.evil/owner/repo','https://user@github.com/owner/repo',
                  'https://github.com/owner/repo/tree/main','http://github.com/owner/repo']:
        with pytest.raises(ValueError):
            repository(value)
    query={'kind':'commit','key':'commit:one/project@abcdef0','repository':'one/project',
           'requested_revision':'abcdef0','url':'https://api.github.com/repos/one/project/commits?sha=abcdef0&per_page=1'}
    assert validate_metadata_query(query).endswith('per_page=1')
    for url in ['https://api.github.com/repos/one/project/commits/abcdef0',
                'https://api.github.com/repos/one/project/contents/service.py',
                query['url']+'&extra=1']:
        with pytest.raises(ValueError):
            validate_metadata_query(dict(query,url=url))


def test_input_integrity_and_no_source_body_export():
    inputs,cache,inventory,reserve,raw=fixtures()
    assert 'fixture-' not in json.dumps(inputs)
    assert len(inputs['cases'])==5
    with pytest.raises(ValueError,match='hash changed'):
        prepare_inputs(reserve,raw+b' ',b'CVE,project\n')
    changed=copy.deepcopy(reserve)
    changed['cases'][0]['vul_func_sha256']='0'*64
    with pytest.raises(ValueError,match='function metadata'):
        prepare_inputs(changed,raw,b'CVE,project\n')


def test_concatenated_prior_urls_are_recovered_with_audit_evidence():
    _,_,_,reserve,raw=fixtures()
    value='https://github.com/One/Project'
    prior=f'CVE,project\nCVE-2026-9999,{value}{value}\n'.encode()
    inputs=prepare_inputs(reserve,raw,prior)
    assert inputs['prior_projects']==['one/project']
    assert inputs['recovered_prior_project_fields'][0]['repetitions']==2
    assert inputs['invalid_prior_projects']==[]


def test_commit_metadata_filter_and_prefix_checks():
    query={'key':'commit:one/project@abcdef0','kind':'commit','url':'metadata-only','requested_revision':'abcdef0'}
    raw=[{'sha':'abcdef0'+'1'*33,'commit':{'tree':{'sha':'a'*40},'message':'PRIVATE-SOURCE-BODY'},
          'parents':[{'sha':'b'*40}], 'files':[{'patch':'PRIVATE-SOURCE-BODY'}]}]
    record=sanitize_metadata(query,raw)
    assert record['status']=='ok'
    assert 'PRIVATE-SOURCE-BODY' not in json.dumps(record)
    assert sanitize_metadata(query,dict(raw[0],sha='c'*40))['status']=='unresolved'


def test_project_splits_are_deterministic_and_label_pending():
    inputs,cache,inventory,_,_=fixtures()
    first=build_manifest(inputs,cache,inventory)
    second=build_manifest(dict(inputs,cases=list(reversed(inputs['cases']))),cache,inventory)
    assert first['membership_sha256']==second['membership_sha256']
    assert first['counts']['scorable_cases']==0
    assert all(not c['scorable'] and c['label_status'].startswith('pending_') for c in first['cases'])
    assert {c['partition'] for c in first['cases']}=={'development','validation','test'}


def test_same_project_and_exact_duplicate_snippets_cannot_cross_splits():
    inputs,cache,inventory,_,_=fixtures(('one/project','one/project','two/project'))
    inputs['cases'][2]['locations'][0]['snippet_sha256']=inputs['cases'][0]['locations'][0]['snippet_sha256']
    manifest=build_manifest(inputs,cache,inventory)
    assert manifest['counts']['groups']==1
    assert len({c['partition'] for c in manifest['cases']})==1


def test_prior_exposure_propagates_to_a_whole_connected_component():
    inputs,cache,inventory,_,_=fixtures(('one/project','two/project','three/project'))
    inputs['prior_projects']=['ancestor/original']
    cache['repo:ancestor/original']={'status':'ok','full_name':'ancestor/original'}
    cache['repo:one/project'].update(fork=True,source_full_name='ancestor/original')
    inputs['cases'][1]['locations'][0]['snippet_sha256']=inputs['cases'][0]['locations'][0]['snippet_sha256']
    manifest=build_manifest(inputs,cache,inventory)
    first,second=manifest['cases'][:2]
    assert first['partition']==second['partition']=='development_only'
    assert 'prior_project_or_fork_root_metadata_exposed' in second['group_overlap_reasons']


def test_unresolved_member_quarantines_project_without_discarding_cases():
    inputs,cache,inventory,_,_=fixtures(('one/project','one/project','two/project'))
    key='commit:one/project@'+inputs['cases'][0]['locations'][0]['requested_revision']
    cache[key]={'status':'unresolved','reason':'not_found'}
    manifest=build_manifest(inputs,cache,inventory)
    assert manifest['counts']['cases']==3
    assert [c['partition'] for c in manifest['cases'][:2]]==['quarantine','quarantine']
    assert not manifest['cases'][1]['metadata_blockers']
    assert manifest['cases'][1]['group_blockers']==['function_snapshot_unresolved']


def test_aliases_canonicalize_and_foreign_patch_stays_blocked():
    inputs,cache,inventory,_,_=fixtures(('old/project','another/project'))
    cache['repo:old/project']['full_name']='renamed/project'
    manifest=build_manifest(inputs,cache,inventory)
    assert manifest['cases'][0]['repository_identity']['canonical']=='renamed/project'
    assert not manifest['cases'][0]['metadata_blockers']
    patch=inputs['cases'][0]['patch_references'][0]
    patch['repository']='another/project'
    cache['commit:another/project@'+patch['revision']]=cache['commit:old/project@'+patch['revision']]
    manifest=build_manifest(inputs,cache,inventory)
    assert 'patch_project_mismatch_requires_review' in manifest['cases'][0]['metadata_blockers']


def test_exact_prior_units_force_development_only_and_normalization_is_limited():
    inputs,cache,inventory,_,_=fixtures()
    value=inputs['cases'][0]['locations'][0]['snippet_sha256']
    inventory['hashes'][value]=['previous:service.py:2-4']
    manifest=build_manifest(inputs,cache,inventory)
    assert manifest['cases'][0]['partition']=='development_only'
    assert snippet_digest('  def f():\r\n      return 1  \r\n')==snippet_digest('def f():\n    return 1')
    assert snippet_digest('def f():\n return 1')!=snippet_digest('def f():\n return 2')


def test_ambiguous_prefix_graph_is_not_silently_selected():
    query={'kind':'commit','repository':'one/project','requested_revision':'abcdef0'}
    first='abcdef0'+'1'*33
    second='abcdef0'+'2'*33
    cache={'repo:one/project':{'full_name':'one/project'},
           'commit:one/project@'+'f'*40:{'status':'ok','sha':'f'*40,'parents':[first,second]},
           'commit:other/project@'+'e'*40:{'status':'ok','sha':'e'*40,'parents':['abcdef0'+'3'*33]}}
    assert set(graph_prefix_candidates(query,cache))=={first,second}
    cache['commit:one/project@'+'f'*40]['parents']=[first]
    assert set(graph_prefix_candidates(query,cache))=={first}


def test_unchanged_or_merge_metadata_is_review_flag_not_validated_label():
    inputs,cache,inventory,_,_=fixtures()
    case=inputs['cases'][0]
    case['locations'][1]['snippet_sha256']=case['locations'][0]['snippet_sha256']
    key='commit:one/project@'+case['patch_references'][0]['revision']
    cache[key]['parents']=['a'*40,'b'*40]
    manifest=build_manifest(inputs,cache,inventory)
    reviewed=manifest['cases'][0]
    assert 'unchanged_snippet_requires_surrounding_context_review' in reviewed['review_notes']
    assert 'patch_merge_or_root_requires_revision_review' in reviewed['review_notes']
    assert not reviewed['scorable']
