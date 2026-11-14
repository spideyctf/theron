import hashlib
import json
import pytest
from scanner.correlation import correlate
from scanner.models import ScanResult
from scanner.mcp_bindings import validate_bindings
from tests.test_package_entrypoints import CODE


def example(kind='http'):
    server={'type':'http','url':'https://example.invalid/mcp'} if kind=='http' else {
        'command':'/original/project/.venv/bin/python','args':['/original/project/server.py']}
    config='mcp-config.json'
    files={config:json.dumps({'mcpServers':{'demo':server}}), 'server.py':CODE}
    digest=lambda p:hashlib.sha256(files[p].encode()).hexdigest()
    binding=dict(config_file=config, pointer='/mcpServers/demo', entrypoint='server.py', kind=kind,
                 config_sha256=digest(config), entrypoint_sha256=digest('server.py'),
                 reason='Reviewer maps this deployment declaration to the collected implementation; runtime identity unverified.')
    return files,binding


def run(files,bindings):
    result=ScanResult(repo_full_name='owner/project',branch='main',findings=[])
    correlate(result,files,bindings=bindings)
    return result


@pytest.mark.parametrize('kind',['http','absolute-python'])
def test_hash_bound_mappings_add_source_context_without_connecting_or_running(monkeypatch,kind):
    monkeypatch.setattr('requests.get',lambda *a,**k:pytest.fail('Endpoint contacted'))
    monkeypatch.setattr('subprocess.run',lambda *a,**k:pytest.fail('Command executed'))
    files,binding=example(kind)
    result=run(files,[binding])
    row=result.correlation_resolutions[0]
    assert row['status']=='source_bound' and not row['deployment_binding']['runtime_verified']
    assert result.correlation_groups[0]['relationships'][0]['kind']=='explicitly_binds_implementation_source'
    assert result.summary['vulnerability_findings']==0


@pytest.mark.parametrize('mutation,reason',[
    ('config','binding_source_digest_mismatch'),('source','binding_source_digest_mismatch'),
    ('missing','binding_source_not_collected'),('disabled','binding_declaration_disabled_or_invalid'),
])
def test_stale_missing_and_disabled_sources_do_not_create_groups(mutation,reason):
    files,binding=example()
    if mutation=='config':files[binding['config_file']]+=' '
    elif mutation=='source':files['server.py']+='\n# changed\n'
    elif mutation=='missing':del files['server.py']
    else:
        data=json.loads(files[binding['config_file']]);data['mcpServers']['demo']['disabled']=True
        files[binding['config_file']]=json.dumps(data)
    result=run(files,[binding])
    assert not result.correlation_groups and result.correlation_resolutions[0]['reason']==reason


@pytest.mark.parametrize('field,value',[('entrypoint','../outside.py'),('config_sha256','invalid'),
    ('pointer','/other/demo'),('reason',''),('kind','shell')])
def test_invalid_binding_schema_is_rejected(field,value):
    _,binding=example();binding[field]=value
    with pytest.raises(ValueError):validate_bindings([binding])


def test_bindings_load_from_local_config_and_cli_exports_source_claim(tmp_path,monkeypatch):
    import yaml
    from scanner.cli import main
    files,binding=example('absolute-python')
    for path,text in files.items():(tmp_path/path).write_text(text,encoding='utf-8')
    (tmp_path/'theron.yml').write_text(yaml.safe_dump({'modules':['sast'],'mcp_bindings':[binding]}),encoding='utf-8')
    output=tmp_path.parent/'binding.json'
    monkeypatch.setattr('sys.argv',['ai-sec-scan','--local',str(tmp_path),'--output',str(output),'--format','json'])
    main()
    value=json.loads(output.read_text(encoding='utf-8'))
    assert value['correlation_resolutions'][0]['status']=='source_bound'


def test_api_rejects_invalid_binding_before_creating_work():
    from fastapi.testclient import TestClient
    from scanner.web import create_app
    _,binding=example();binding['entrypoint']='../outside.py'
    with TestClient(create_app()) as client:
        response=client.post('/api/scans',json={'repository':'owner/project','mcp_bindings':[binding]})
    assert response.status_code==422


def test_windows_absolute_paths_and_malformed_http_values():
    files,binding=example('absolute-python')
    files[binding['config_file']]=json.dumps({'mcpServers':{'demo':{
        'command':'C:\\repo\\.venv\\Scripts\\python.exe','args':['C:\\repo\\server.py']}}})
    binding['config_sha256']=hashlib.sha256(files[binding['config_file']].encode()).hexdigest()
    assert run(files,[binding]).correlation_resolutions[0]['status']=='source_bound'
    files,binding=example('http')
    files[binding['config_file']]=json.dumps({'mcpServers':{'demo':{'url':3}}})
    binding['config_sha256']=hashlib.sha256(files[binding['config_file']].encode()).hexdigest()
    assert not run(files,[binding]).correlation_groups
