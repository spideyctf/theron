from copy import deepcopy
import pytest
from scanner.advisory_usage import annotate_usage
from tests.osv_delivery_fixture import build


def review(files, package='demo'):
    result=build()
    result.findings[0].dependency['package']=package
    before=deepcopy(result.findings[0].to_dict())
    annotate_usage(result.findings, files)
    finding=result.findings[0]
    assert finding.severity.value==before['severity'] and finding.fingerprint==before['fingerprint']
    return finding.dependency['application_review']


def test_calls_have_source_locations_hashes_and_no_vulnerability_confirmation():
    value=review({'app.py':'import demo as d\ndef run(text):\n    return d.parse(text)\n'})
    assert value['status']=='direct_api_call_observed'
    assert value['calls'][0]['symbol']=='demo.parse' and value['calls'][0]['line_number']==3
    assert value['imports'][0]['line_number']==1
    assert not value['affected_behavior_verified'] and not value['vulnerability_confirmed']
    assert len(value['source_text_sha256']['app.py'])==64


@pytest.mark.parametrize('code', ['import demo\ndemo=custom\ndemo.parse(x)',
    'import demo\ndef f(demo): return demo.parse(x)',
    'import demo\ndef f():\n    import other as demo\n    return demo.parse(x)',
    'import demo\ndemo.parse=custom\ndemo.parse(x)'])
def test_shadowing_and_replacement_do_not_claim_original_api_calls(code):
    value=review({'app.py':code})
    assert value['status']=='import_only_observed' and not value['calls']


def test_examples_and_transitive_absence_do_not_establish_application_usage_or_safety():
    value=review({'examples/demo_app.py':'import demo\ndemo.parse(x)'})
    assert value['status']=='no_direct_usage_observed'
    assert value['calls'][0]['scope']=='example'
    assert 'transitive dependencies' in ' '.join(value['limitations'])


def test_parse_and_collection_limits_are_visible():
    value=review({**{f'app{i}.py':'pass' for i in range(201)}, 'bad.py':'def broken('})
    assert value['coverage']['truncated']
    value=review({'bad.py':'def broken('})
    assert value['coverage']['parse_failures']==['bad.py']


def test_import_name_contract_is_explicit_and_local_shadow_is_unknown():
    value=review({'app.py':'from dotenv import load_dotenv\nload_dotenv()'}, 'python-dotenv')
    assert value['status']=='direct_api_call_observed' and value['attribution_basis']=='documented_import_name_contract'
    assert review({'app.py':'import demo\ndemo.parse(x)', 'demo.py':'pass'})['status']=='module_ownership_unresolved'
