import json
from pathlib import Path

import pytest

from scanner.correlation import correlate
from scanner.utils.helpers import should_scan_file
from tests.tool_correlation_fixture import CODE,HELPER,build,groups,edges
from tests.tool_correlation_fixture import CASES


@pytest.mark.parametrize('name,kwargs,expected',CASES,ids=[r[0] for r in CASES])
def test_original_study_controls(name,kwargs,expected):
    assert bool(edges(build(**kwargs)[1],'import_has_dependency_context'))==expected


def test_registered_handler_helper_package_and_osv_chain_retains_original_findings(monkeypatch):
    monkeypatch.setattr('subprocess.run',lambda *a,**k:pytest.fail('Target command executed'))
    files,result=build();_,off=build(enabled=False)
    assert [f.to_dict() for f in result.findings]==[f.to_dict() for f in off.findings]
    group=groups(result)[0]
    assert len(group['finding_fingerprints'])==2 and 'severity' not in group
    assert edges(result,'declares_tool_handler')[0]['target']['symbol']=='server.inspect_text'
    assert edges(result,'calls_local_function')[0]['target']['symbol']=='helpers.parse'
    assert edges(result,'calls_imported_api')[0]['target']['symbol']=='yaml.load'
    assert edges(result,'import_has_dependency_context')[0]['basis']=='distribution-record-claim'
    assert edges(result,'declared_version_matches_osv_advisory')[0]['provenance']['advisory_record_sha256']
    assert any('affected by the advisory' in s for s in group['limitations'])
    for edge in group['relationships']:
        assert edge['provenance']['commit_sha']=='b'*40
        assert edge['provenance']['source_text_sha256']
    correlate(result,dict(reversed(list(files.items()))))
    assert groups(result)[0]['id']==group['id']


@pytest.mark.parametrize('code',[
    CODE.replace('@app.tool(name="inspect_text")\n',''),
    CODE.replace('app=FastMCP("demo")','app=custom()'),
    CODE.replace('from mcp.server.fastmcp import FastMCP','from custom import FastMCP'),
    CODE.replace('app=FastMCP("demo")','app=FastMCP("demo")\napp=custom'),
    CODE.replace('@app.tool(name="inspect_text")','@app.tool(name="inspect_text")\n@custom'),
])
def test_absent_or_unresolved_registration_cannot_create_a_tool_path(code):
    assert not groups(build(code=code)[1])


def test_imported_handler_add_tool_and_manager_alias_are_supported():
    code='from mcp.server.fastmcp import FastMCP\nfrom helpers import parse\napp=FastMCP("demo")\nother=app\nother.add_tool(parse)\n'
    result=build(code=code)[1]
    assert edges(result,'declares_tool_handler')[0]['target']['symbol']=='helpers.parse'
    assert edges(result,'calls_imported_api')


def test_registration_does_not_resolve_symbols_imported_or_defined_later():
    code='app=FastMCP("demo")\nfrom mcp.server.fastmcp import FastMCP\n@app.tool()\ndef run(text): return text\n'
    assert not groups(build(code=code)[1])
    code='from mcp.server.fastmcp import FastMCP\napp=FastMCP("demo")\napp.add_tool(later)\ndef later(text): return text\n'
    result=build(code=code)[1]
    assert not groups(result)
    assert result.correlation_resolutions[0]['tool_resolution_notes'][0]['reason']=='handler_not_bound_at_registration'


@pytest.mark.parametrize('mutation', ['app.tool=custom','del app.tool','if flag:\n    app.tool=custom','FastMCP.tool=custom'])
def test_replaced_registration_contract_does_not_bind_original_handler(mutation):
    assert not groups(build(code=CODE.replace('@app.tool',mutation+'\n@app.tool'))[1])


def test_ambiguous_module_roots_and_local_fastmcp_are_unresolved():
    assert not groups(build(extra={'src/server.py':'pass'})[1])
    assert not groups(build(extra={'mcp/local.py':'pass'})[1])
    assert not groups(build(extra={'nested/mcp.py':'pass'})[1])


def test_conditional_tool_registration_remains_explicitly_unresolved():
    code=CODE.replace('@app.tool(name="inspect_text")\ndef inspect_text(text):\n    exec(input())\n    return parse(text)',
        'if enabled:\n    @app.tool()\n    def inspect_text(text):\n        return parse(text)')
    result=build(code=code)[1]
    assert not groups(result)
    assert any(n['reason']=='conditional_registration_not_resolved' for n in result.correlation_resolutions[0]['tool_resolution_notes'])


def test_recursive_local_calls_are_bounded_and_keep_supported_external_calls():
    helper=HELPER.replace('    return parser.load(text)','    if again:\n        parse(text)\n    return parser.load(text)')
    result=build(helper=helper)[1]
    assert len(edges(result,'calls_imported_api'))==1


def test_deep_paths_record_a_limit_instead_of_inventing_a_dependency_link():
    functions='\n'.join(f'def h{i}(text):\n    return h{i+1}(text)\n' for i in range(7))+'\ndef h7(text):\n    return parser.load(text)\n'
    result=build(helper='import yaml as parser\n'+functions,code=CODE.replace('import parse','import h0 as parse'))[1]
    assert not edges(result,'import_has_dependency_context')
    assert any(n['reason']=='handler_call_depth_reached' for n in groups(result)[0]['resolution_notes'])


def test_direct_async_handler_and_from_import_alias_are_supported():
    code=CODE.replace('from helpers import parse','from yaml import load as parse').replace('def inspect_text','async def inspect_text')
    assert edges(build(code=code)[1],'calls_imported_api')[0]['target']['symbol']=='yaml.load'


@pytest.mark.parametrize('body',[
    '    return text\n    return parse(text)',
    '    if False:\n        return parse(text)\n    return text',
    '    def unused():\n        return parse(text)\n    return text',
    '    parse=custom\n    return parse(text)',
])
def test_dead_nested_or_shadowed_helper_is_not_a_dependency_call(body):
    code=CODE[:CODE.index('    exec(input())')]+body+'\n'
    assert groups(build(code=code)[1])
    assert not edges(build(code=code)[1],'calls_imported_api')


def test_unused_import_and_unregistered_function_do_not_gain_a_dependency_path():
    helper=HELPER.replace('return parser.load(text)','return text')+'\ndef unused(text):\n    return parser.load(text)\n'
    assert not edges(build(helper=helper)[1],'calls_imported_api')


@pytest.mark.parametrize('extra',[
    {'yaml.py':'def load(text): return text'},
    {'yaml/local.py':'pass'},
    {'nested/yaml.py':'pass'},
])
def test_local_and_namespace_shadowing_blocks_distribution_association(extra):
    assert not edges(build(extra=extra)[1],'import_has_dependency_context')


def test_metadata_version_mismatch_is_explicit_and_does_not_fall_back():
    result=build(extra={'evidence/PyYAML-1.0.0.dist-info/METADATA':'Name: PyYAML\nVersion: 2.0\n'})[1]
    assert not edges(result,'import_has_dependency_context')
    assert any(n['reason']=='distribution_version_mismatch' for n in groups(result)[0]['resolution_notes'])


def test_conflicting_distribution_owners_remain_ambiguous():
    extra={'other/other-1.dist-info/METADATA':'Name: other\nVersion: 1\n',
           'other/other-1.dist-info/RECORD':'yaml/__init__.py,,\n'}
    result=build(extra=extra)[1]
    assert not edges(result,'import_has_dependency_context')
    assert groups(result)[0]['resolution_notes'][0]['reason']=='ambiguous_distribution_metadata'


@pytest.mark.parametrize('record', ['../yaml/__init__.py,,\n','/yaml/__init__.py,,\n','yaml/__init__.py,\n'])
def test_unsafe_or_malformed_record_does_not_establish_module_ownership(record):
    result=build(extra={'evidence/PyYAML-1.0.0.dist-info/RECORD':record})[1]
    assert not edges(result,'import_has_dependency_context')


def test_same_name_without_metadata_remains_a_weaker_context_claim():
    result=build(helper=HELPER.replace('yaml','demo'),package='demo',metadata=False)[1]
    edge=edges(result,'import_has_dependency_context')[0]
    assert edge['basis']=='same-name-declaration-only'
    assert not edges(build(metadata=False)[1],'import_has_dependency_context')


def test_nearer_manifest_blocks_root_dependency_attribution():
    code=CODE.replace('from helpers import parse','from nested.helpers import parse')
    result=build(code=code,extra={'nested/helpers.py':HELPER,'nested/pyproject.toml':'[project]\nname="nested"'})[1]
    assert not edges(result,'import_has_dependency_context')


def test_custom_callee_decorator_and_replaced_api_do_not_imply_original_calls():
    assert not edges(build(helper=HELPER.replace('def parse','@custom\ndef parse'))[1],'calls_imported_api')
    result=build(helper=HELPER.replace('def parse','parser.load=custom\ndef parse'))[1]
    assert not edges(result,'calls_imported_api')
    assert any(n['reason']=='call_target_reassigned' for n in groups(result)[0]['resolution_notes'])


def test_stdlib_and_disabled_server_do_not_gain_pypi_links():
    result=build(helper=HELPER.replace('yaml','json'),package='json',metadata=False)[1]
    assert not edges(result,'import_has_dependency_context')
    files,result=build();files['.vscode/mcp.json']='{"servers":{"local":{"command":"python","args":["server.py"],"disabled":true}}}'
    correlate(result,files);assert not groups(result)


def test_distribution_metadata_collection_keeps_environment_exclusions():
    assert should_scan_file('evidence/demo-1.dist-info/METADATA')
    assert should_scan_file('evidence/demo-1.dist-info/RECORD')
    assert not should_scan_file('.venv/lib/demo-1.dist-info/METADATA')
    assert not should_scan_file('data/RECORD')


def test_exports_and_shared_frontend_fixture_preserve_tool_provenance():
    from scanner.reporters.html import generate_html_report
    from scanner.reporters.sarif import generate_sarif_report
    _,result=build()
    assert json.loads(generate_sarif_report(result))['runs'][0]['properties']['correlation_groups']==result.correlation_groups
    assert 'distribution-record-claim' in generate_html_report(result)
    assert json.loads((Path(__file__).parent/'fixtures/tool-correlation-report.json').read_text())==result.to_dict()


@pytest.mark.parametrize('fmt',['json','sarif','html'])
def test_local_cli_collects_distribution_records_and_delivers_the_handler_chain(tmp_path,monkeypatch,fmt):
    from copy import deepcopy
    from scanner.cli import main
    from scanner.plugins.sca import SCAScanner
    from tests.osv_delivery_fixture import RECORD
    files,_=build()
    for name,text in files.items():
        p=tmp_path/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text,encoding='utf-8')
    record=deepcopy(RECORD);record['affected'][0]['package']['name']='PyYAML'
    monkeypatch.setattr(SCAScanner,'_query_osv',lambda *args:[record])
    output=tmp_path.parent/('tool-report.'+fmt)
    monkeypatch.setattr('sys.argv',['ai-sec-scan','--local',str(tmp_path),'--modules','sast,sca','--format',fmt,'--output',str(output)])
    main();report=output.read_text(encoding='utf-8')
    assert 'declares_tool_handler' in report and 'yaml.load' in report and 'distribution-record-claim' in report
    assert 'advisory_record_sha256' in report and 'helpers.parse' in report
