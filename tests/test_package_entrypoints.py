import json
import pytest
from scanner.package_entrypoints import package_launch
from scanner.correlation import correlate
from scanner.models import ScanResult

CODE = '''from mcp.server.fastmcp import FastMCP
app = FastMCP("demo")
@app.tool()
def inspect(text):
    return text
def main():
    app.run()
'''
PROJECT = '[build-system]\nbuild-backend="setuptools.build_meta"\nrequires=["setuptools"]\n[project]\nname="demo"\nversion="1.0"\n[project.scripts]\ndemo="server:main"\n'


def local(extra=None, server=None):
    config = '.vscode/mcp.json'
    server = server or dict(type='stdio', command='uv', args=['run', 'demo'])
    files = {'server.py': CODE, 'pyproject.toml': PROJECT, config: json.dumps({'servers': {'demo': server}}), **(extra or {})}
    return config, server, files


def test_local_project_script_reaches_static_tool_context_without_execution(monkeypatch):
    monkeypatch.setattr('subprocess.run', lambda *a, **k: pytest.fail('Target execution'))
    config, server, files = local()
    result = ScanResult(repo_full_name='owner/project', branch='main', findings=[])
    correlate(result, files)
    assert result.correlation_resolutions[0]['package_entrypoint']['object_reference'] == 'server:main'
    assert any(g['id'].startswith('mcp-tool-') for g in result.correlation_groups)
    assert result.correlation_groups[0]['relationships'][0]['kind'] == 'package_metadata_declares_entrypoint'
    assert result.summary['vulnerability_findings'] == 0


def distribution():
    config, server, files = local(server=dict(command='uvx', args=['--from', 'demo==1.0', 'demo']))
    files.pop('pyproject.toml')
    files.update({'demo-1.0.dist-info/METADATA': 'Name: demo\nVersion: 1.0\n',
                  'demo-1.0.dist-info/entry_points.txt': '[console_scripts]\ndemo = server:main\n',
                  'demo-1.0.dist-info/RECORD': 'server.py,,\n'})
    return config, server, files


def test_pinned_uvx_uses_collected_distribution_entrypoint_and_record():
    config, server, files = distribution()
    path, reason, evidence = package_launch(config, 'servers', server, files)
    assert path == 'server.py' and reason == 'package_entrypoint_inferred'
    assert evidence['installation_verified'] is False
    assert len(evidence['source_text_sha256']) == 4


@pytest.mark.parametrize('extra,reason', [
    ({'pyproject.toml': PROJECT.replace('server:main', 'other:main')}, 'missing_or_ambiguous_entrypoint_module'),
    ({'src/server.py': CODE}, 'missing_or_ambiguous_entrypoint_module'),
    ({'server.py': CODE+'\nmain=custom\n'}, 'entrypoint_callable_unresolved'),
    ({'server.py': CODE.replace('def main', '@custom\ndef main')}, 'entrypoint_callable_unresolved'),
    ({'pyproject.toml': PROJECT+'\n[tool.hatch]\n'}, 'custom_project_layout_unresolved'),
    ({'pyproject.toml': PROJECT.replace('server:main', 'server:obj.method')}, 'unsupported_entrypoint_object_reference'),
    ({'pyproject.toml': PROJECT.replace('setuptools.build_meta', 'custom.backend')}, 'project_installation_contract_unresolved'),
    ({'pyproject.toml': PROJECT+'\n[tool.uv]\npackage=false\n'}, 'project_installation_contract_unresolved'),
    ({'server.py': CODE.replace('def main', 'async def main')}, 'entrypoint_callable_unresolved'),
])
def test_unsupported_or_conflicting_project_contracts_remain_unknown(extra, reason):
    config, server, files = local(extra)
    assert package_launch(config, 'servers', server, files) == (None, reason, None)


@pytest.mark.parametrize('server,reason', [
    ({'command': 'uvx', 'args': ['demo']}, 'external_package_version_unresolved'),
    ({'command': 'uv', 'args': ['run', '--directory', '/tmp', 'demo']}, 'unsupported_uv_invocation'),
    ({'command': 'uv', 'args': ['run', 'demo'], 'cwd': '../other'}, 'unresolved_working_directory'),
    ({'command': 'uv', 'args': ['run', 'demo'], 'env': {'PYTHONPATH': '/tmp'}}, 'package_launch_environment_override_unresolved'),
])
def test_launch_overrides_do_not_guess_effective_environment(server, reason):
    config, server, files = local(server=server)
    assert package_launch(config, 'servers', server, files) == (None, reason, None)


@pytest.mark.parametrize('path,content', [
    ('demo-1.0.dist-info/METADATA', 'Name: demo\nVersion: 2.0\n'),
    ('demo-1.0.dist-info/RECORD', 'other.py,,\n'),
    ('demo-1.0.dist-info/entry_points.txt', '[console_scripts]\ndemo=server:main\ndemo=other:main\n'),
])
def test_untrusted_distribution_claims_need_consistent_metadata(path, content):
    config, server, files = distribution()
    files[path] = content
    assert package_launch(config, 'servers', server, files)[0] is None


def test_root_claude_project_configuration_and_src_layout():
    _, server, files = local()
    files['src/server.py'] = files.pop('server.py')
    assert package_launch('.mcp.json', 'mcpServers', server, files)[0] == 'src/server.py'


@pytest.mark.parametrize('fmt', ['json', 'sarif', 'html'])
def test_local_cli_exports_package_entrypoint_provenance(tmp_path, monkeypatch, fmt):
    from scanner.cli import main
    _, _, files = local()
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    output = tmp_path.parent / ('package-report.' + fmt)
    monkeypatch.setattr('sys.argv', ['ai-sec-scan', '--local', str(tmp_path), '--modules', 'sast', '--format', fmt, '--output', str(output)])
    main()
    rendered = output.read_text(encoding='utf-8')
    assert 'package_metadata_declares_entrypoint' in rendered
    assert 'local_project_script' in rendered and 'source_text_sha256' in rendered
