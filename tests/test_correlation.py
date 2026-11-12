"""Original static fixtures; no MCP commands or target modules are executed."""
import json
from pathlib import Path

import pytest

from scanner.correlation import correlate
from scanner.finding_utils import normalize_findings, partition_findings
from scanner.models import ScanResult, Severity
from scanner.python_analysis import analyze_python


def sample(server=None, code='exec(input())', config_path='.vscode/mcp.json', extra=None, field='servers'):
    server = server if server is not None else {'command':'python','args':['server.py']}
    if isinstance(server,dict): server={'type':'stdio',**server}
    files={config_path:json.dumps({field:{'local':server}}),'server.py':code,**(extra or {})}
    findings=[f for path,text in files.items() if path.endswith('.py') for f in analyze_python(path,text,module='sast')]
    result=ScanResult(repo_full_name='owner/project',branch='main',commit_sha='a'*40,
                      findings=normalize_findings(findings),files_scanned=len(files),modules_run=['sast'])
    partition_findings(result)
    correlate(result,files)
    return files,result


def test_exact_declaration_links_existing_evidence_without_new_vulnerability_counts(monkeypatch):
    monkeypatch.setattr('subprocess.run',lambda *a,**k:pytest.fail('Declared command executed'))
    files,result=sample()
    assert len(result.correlation_groups)==1 and result.summary['vulnerability_findings']==1
    group=result.correlation_groups[0]
    assert group['classification']=='inferred' and group['maturity']=='experimental'
    assert 'severity' not in group and 'confidence' not in group
    assert group['finding_fingerprints']==[result.findings[0].fingerprint]
    declaration,flow=group['relationships']
    assert declaration['source']==dict(kind='configuration',file_path='.vscode/mcp.json',pointer='/servers/local')
    assert declaration['target']==dict(kind='file',file_path='server.py')
    assert flow['classification']=='observed' and flow['evidence']==result.findings[0].trace
    identity=group['id']
    correlate(result,dict(reversed(list(files.items()))))
    assert result.correlation_groups[0]['id']==identity
    before=[f.to_dict() for f in result.findings]
    correlate(result,files,enabled=False)
    assert not result.correlation_enabled and result.correlation_groups==result.correlation_resolutions==[]
    assert [f.to_dict() for f in result.findings]==before


@pytest.mark.parametrize('code,extra', [('print("safe")',None), ('pass',{'unrelated.py':'exec(input())'})])
def test_safe_or_unrelated_code_does_not_create_a_group(code,extra):
    _,result=sample(code=code,extra=extra)
    assert not result.correlation_groups
    assert result.correlation_resolutions[0]['status']=='resolved'
    assert result.correlation_resolutions[0]['reason']=='no_eligible_flow_evidence_in_entrypoint'


@pytest.mark.parametrize('server,reason', [
    ({'command':'sh','args':['-c','python server.py']},'unsupported_interpreter_or_wrapper'),
    ({'command':'uv','args':['run','server.py']},'unsupported_interpreter_or_wrapper'),
    ({'command':'python server.py','args':[]},'unsupported_interpreter_or_wrapper'),
    ({'command':'python','args':['-m','server']},'unsupported_python_invocation'),
    ({'command':'python','args':['-c','exec(input())']},'unsupported_python_invocation'),
    ({'command':'python','args':['missing.py']},'target_not_collected_with_exact_case'),
    ({'command':'python','args':['../outside.py']},'unsupported_or_outside_python_path'),
    ({'command':'python','args':['C:\\outside.py']},'unsupported_or_outside_python_path'),
    ({'command':'python','args':['/outside.py']},'unsupported_or_outside_python_path'),
    ({'command':'python','args':['${env:HOME}/server.py']},'unsupported_or_outside_python_path'),
    ({'command':'python','args':['server.py'],'cwd':'.'},'unresolved_working_directory'),
    ({'command':'python','args':['server.py'],'cwd':'${workspaceFolder}/../outside'},'working_directory_outside_workspace_or_dynamic'),
    ({'command':'python','args':'server.py'},'invalid_or_missing_argument_vector'),
    ({'command':'python','args':[None]},'invalid_or_missing_argument_vector'),
    ({'type':'http','url':'https://example.invalid'},'not_a_direct_stdio_declaration'),
    ({'command':'python','args':['server.py'],'disabled':True},'server_explicitly_disabled'),
    ({'command':'python','args':['server.py'],'enabled':False},'server_explicitly_disabled'),
    (None,'invalid_server_object'),
])
def test_unresolved_declarations_preserve_reason_without_fabricated_edge(server,reason):
    if server is None:
        files,result=sample()
        files['.vscode/mcp.json']='{"servers":{"local":null}}'
        correlate(result,files)
    else:
        _,result=sample(server)
    assert not result.correlation_groups
    row=result.correlation_resolutions[0]
    assert row['status']=='unresolved' and row['classification']=='unknown' and row['reason']==reason


def test_unknown_client_semantics_are_not_guessed_from_config_location():
    _,result=sample(config_path='.mcp.json',field='mcpServers')
    assert not result.correlation_groups
    assert result.correlation_resolutions[0]['reason']=='unknown_client_working_directory_or_variable_semantics'


@pytest.mark.parametrize('args,cwd', [(['${workspaceFolder}/server.py'],None),(['-u','-B','server.py'],None),(['server.py'],'${workspaceFolder}'),(['server.py'],'${workspaceFolder}/.')])
def test_supported_invocation_forms(args,cwd):
    server={'type':'stdio','command':'python3.12','args':args}
    if cwd is not None: server['cwd']=cwd
    assert sample(server)[1].correlation_groups


def test_nested_workspace_and_config_pointer_and_secret_omission():
    files,result=sample(code='pass',config_path='examples/demo/.vscode/mcp.json',extra={'examples/demo/server.py':'exec(input())'})
    data={'servers':{'a~/b':{'type':'stdio','command':'python','args':['server.py','SECRET_ARG_NOT_FOR_EXPORT'],
                           'env':{'PASSWORD':'SECRET_ENV_NOT_FOR_EXPORT'}}}}
    files['examples/demo/.vscode/mcp.json']=json.dumps(data)
    correlate(result,files)
    group=result.correlation_groups[0]
    assert group['scope']=='example' and group['relationships'][0]['source']['pointer']=='/servers/a~0~1b'
    assert group['relationships'][0]['target']['file_path']=='examples/demo/server.py'
    serialized=json.dumps(result.to_dict())
    assert 'SECRET_ARG_NOT_FOR_EXPORT' not in serialized and 'SECRET_ENV_NOT_FOR_EXPORT' not in serialized
    assert all(f.file_path!='examples/demo/server.py' for f in result.findings)
    assert result.summary['vulnerability_findings']==0 and len(result.context_findings)==1


@pytest.mark.parametrize('text', ['{"servers":{} ,"servers":{}}','{"servers":[]}','{"servers":{},"mcpServers":{}}','//JSONC\n{}','{"servers":{"local":NaN}}'])
def test_malformed_or_ambiguous_json_is_visible(text):
    files,result=sample()
    files['.vscode/mcp.json']=text
    correlate(result,files)
    assert not result.correlation_groups and result.correlation_resolutions[0]['status']=='unresolved'


def test_case_collision_and_missing_or_pattern_only_evidence_are_not_connected():
    _,result=sample(extra={'Server.py':'pass'})
    assert result.correlation_resolutions[0]['reason']=='ambiguous_collected_path'
    for mutation in ['trace','evidence_kind','severity']:
        files,result=sample()
        finding=result.findings[0]
        if mutation=='trace': finding.trace=[]
        elif mutation=='severity': finding.severity=Severity.INFO
        else: finding.evidence_kind='static-pattern'
        correlate(result,files)
        assert not result.correlation_groups


def test_json_sarif_html_and_terminal_keep_the_same_edges(capsys):
    from scanner.reporters.json_reporter import generate_json_report
    from scanner.reporters.sarif import generate_sarif_report
    from scanner.reporters.html import generate_html_report
    from scanner.reporters.terminal import print_terminal_report
    _,result=sample()
    assert json.loads(generate_json_report(result))['correlation_groups']==result.correlation_groups
    props=json.loads(generate_sarif_report(result))['runs'][0]['properties']
    assert props['correlation_groups']==result.correlation_groups
    assert props['correlation_resolutions']==result.correlation_resolutions
    html=generate_html_report(result)
    assert result.correlation_groups[0]['id'] in html and 'correlation-evidence' in html
    print_terminal_report(result)
    assert result.correlation_groups[0]['id'] in capsys.readouterr().out


def test_html_escapes_configuration_pointers():
    from scanner.reporters.html import generate_html_report
    files,result=sample()
    files['.vscode/mcp.json']=json.dumps({'servers':{'</script><img>':{'type':'stdio','command':'python','args':['server.py']}}})
    correlate(result,files)
    assert '</script><img>' not in generate_html_report(result)


@pytest.mark.parametrize('path,expected',[('.vscode/mcp.json',True),('.vscode/settings.json',False),
    ('node_modules/.vscode/mcp.json',False),('.git/.vscode/mcp.json',False),('demo/.vscode/mcp.json',True)])
def test_only_mcp_file_is_an_exception_to_editor_directory_skip(path,expected):
    from scanner.utils.helpers import should_scan_file
    assert should_scan_file(path) is expected


def test_local_cli_collection_and_disabled_ablation(tmp_path,monkeypatch):
    from scanner.cli import main
    (tmp_path/'.vscode').mkdir()
    (tmp_path/'.vscode'/'mcp.json').write_text(json.dumps({'servers':{'local':{'type':'stdio','command':'python','args':['server.py']}}}))
    (tmp_path/'.vscode'/'settings.json').write_text('do not collect')
    (tmp_path/'server.py').write_text('exec(input())')
    for disabled in [False,True]:
        output=tmp_path/('disabled.json' if disabled else 'report.json')
        monkeypatch.setattr('sys.argv',['ai-sec-scan','--local',str(tmp_path),'--modules','sast','--format','json','--output',str(output)]+(['--no-correlation'] if disabled else []))
        main()
        report=json.loads(output.read_text())
        assert bool(report['correlation_groups']) is not disabled
        assert report['summary']['vulnerability_findings']==1


def test_github_collection_and_symlink_exclusion(monkeypatch):
    from scanner.engine import ScanEngine
    files,_=sample()
    engine=ScanEngine(github_token='test-token-not-live',config={'modules':['sast']})
    engine.github.revision='b'*40
    monkeypatch.setattr(engine.github,'get_repo_info',lambda *a:{'default_branch':'main'})
    monkeypatch.setattr(engine.github,'get_tree',lambda *a:[dict(type='blob',path=p,size=len(t),mode='100644') for p,t in files.items()]+[dict(type='blob',path='link.py',mode='120000',size=10)])
    def get_file(owner,repo,path,revision):
        assert path!='link.py' and revision=='b'*40
        return files[path]
    monkeypatch.setattr(engine.github,'get_file_content',get_file)
    result=engine.scan_repo('owner','project')
    assert result.correlation_groups and result.commit_sha=='b'*40
    assert any(f.rule_id=='SCAN-COVERAGE-001' and f.file_path=='link.py' for f in result.findings)


def test_shared_frontend_fixture_matches_backend_output():
    stored=json.loads((Path(__file__).parent/'fixtures'/'correlation-report.json').read_text())
    assert stored==sample()[1].to_dict()


@pytest.mark.parametrize('enabled',[True,False])
def test_web_api_and_downloads_retain_groups_and_ablation(monkeypatch,enabled):
    from fastapi.testclient import TestClient
    from scanner.web import create_app
    from tests.test_web import wait_for
    monkeypatch.setenv('GITHUB_TOKEN','test-token-not-live')
    class Engine:
        def __init__(self,token,config): self.config=config
        def scan_repo(self,*args,**kwargs):
            files,result=sample()
            correlate(result,files,self.config['correlation_enabled'])
            return result
    with TestClient(create_app(scanner_factory=Engine)) as client:
        response=client.post('/api/scans',json={'repository':'owner/project','modules':['sast'],'correlation_enabled':enabled})
        job=wait_for(client,response.json()['id'],'completed')
        assert job['correlation_enabled'] is enabled
        assert bool(job['result']['correlation_groups']) is enabled
        exported=client.get('/api/scans/'+job['id']+'/report').json()
        assert exported['correlation_groups']==job['result']['correlation_groups']
        sarif=client.get('/api/scans/'+job['id']+'/report?format=sarif').json()
        assert sarif['runs'][0]['properties']['correlation_groups']==exported['correlation_groups']


def test_local_symlink_is_not_read_or_connected(tmp_path,monkeypatch):
    from scanner.cli import main
    (tmp_path/'.vscode').mkdir()
    (tmp_path/'.vscode'/'mcp.json').write_text('{"servers":{"local":{"type":"stdio","command":"python","args":["server.py"]}}}')
    (tmp_path/'server.py').write_text('exec(input())')
    monkeypatch.setattr('os.path.islink',lambda path:str(path).endswith('server.py'))
    output=tmp_path/'output.json'
    monkeypatch.setattr('sys.argv',['ai-sec-scan','--local',str(tmp_path),'--modules','sast','--format','json','--output',str(output)])
    main()
    result=json.loads(output.read_text())
    assert not result['correlation_groups'] and result['summary']['vulnerability_findings']==0
    assert result['correlation_resolutions'][0]['reason']=='target_not_collected_with_exact_case'


def test_config_can_disable_correlation_and_rejects_non_boolean(tmp_path):
    from scanner.config import load_config
    path=tmp_path/'theron.yml'
    path.write_text('correlation_enabled: false')
    assert load_config(tmp_path)['correlation_enabled'] is False
    path.write_text('correlation_enabled: "false"')
    with pytest.raises(ValueError,match='boolean'):
        load_config(tmp_path)


def test_multiple_declarations_and_experimental_members_do_not_boost_severity():
    files,result=sample()
    finding=result.findings[0]
    finding.maturity='experimental'
    finding.confidence='medium'
    files['.vscode/mcp.json']=json.dumps({'servers':{name:{'type':'stdio','command':'python','args':['server.py']} for name in ['one','two']}})
    before=result.summary
    correlate(result,files)
    assert len(result.correlation_groups)==2 and result.summary==before
    assert len({g['id'] for g in result.correlation_groups})==2
    assert all(g['relationships'][1]['confidence']=='medium' and g['relationships'][1]['maturity']=='experimental' for g in result.correlation_groups)


@pytest.mark.parametrize('bad_step',[dict(role='source',file_path='missing.py',line_number=1),
    dict(role='sink',file_path='server.py',line_number=200),dict(role='unknown',file_path='server.py',line_number=1)])
def test_unknown_or_unavailable_trace_endpoint_cannot_support_a_link(bad_step):
    files,result=sample()
    result.findings[0].trace.append(bad_step)
    correlate(result,files)
    assert not result.correlation_groups


def test_missing_required_stdio_type_remains_unresolved():
    files,result=sample()
    files['.vscode/mcp.json']='{"servers":{"local":{"command":"python","args":["server.py"]}}}'
    correlate(result,files)
    assert not result.correlation_groups
    assert result.correlation_resolutions[0]['reason']=='missing_or_invalid_stdio_type'


def test_unsupported_workspace_directory_retains_an_unresolved_reason():
    _,result=sample(config_path='$dynamic/.vscode/mcp.json')
    assert not result.correlation_groups
    assert result.correlation_resolutions[0]['classification']=='unknown'
    assert result.correlation_resolutions[0]['reason']=='unsupported_workspace_path'
