"""Original unsafe/safe controls; none of the source snippets execute."""
import json
import pytest

from scanner.python_analysis import analyze_python
from scanner.config import validate_entrypoints, load_config


def dynamic(code, **kwargs):
    return [f for f in analyze_python('app.py',code,**kwargs) if f.rule_id=='PY-SAST-DYNAMIC-CALL-001']


@pytest.mark.parametrize('prefix',[
    'import os\nfn=getattr(os,request.args["operation"])',
    'import sys\nm=sys.modules[request.args["module"]]\nfn=getattr(m,request.args["operation"])',
    'import importlib\nm=importlib.import_module(request.args["module"])\nfn=m.run',
])
def test_observed_input_selects_invoked_module_member(prefix):
    fs=dynamic('from flask import request\n'+prefix+'\nfn("argument")')
    assert len(fs)==1 and fs[0].evidence_kind=='static-flow' and fs[0].trace[0]['role']=='source'


@pytest.mark.parametrize('tail',[
    'fn=getattr(os,"getcwd")\nfn()',
    'fn=getattr(os,request.args["operation"])\nprint(fn)',
    'fn=getattr(os,request.args["operation"])\nfn=os.getcwd\nfn()',
    'fn=str(getattr(os,request.args["operation"]))\nfn()',
    'ops={"cwd":os.getcwd}\nfn=ops[request.args["operation"]]\nfn()',
])
def test_static_dispatch_lookup_only_overwrites_and_string_results_do_not_become_dynamic_calls(tail):
    assert not dynamic('from flask import request\nimport os\n'+tail)


@pytest.mark.parametrize('guard',[
    'if not issubclass(fn,BaseException):\n raise ValueError()',
    'if not isinstance(fn,type) or not issubclass(fn,BaseException):\n raise ValueError()',
])
def test_exception_class_boundary_removes_only_this_dynamic_call_candidate(guard):
    code='from flask import request\nimport sys\nfn=getattr(sys.modules[request.args["module"]],request.args["name"])\n'+guard+'\nfn("message")'
    assert not dynamic(code)


def test_callable_check_is_not_a_dispatch_boundary():
    assert dynamic('from flask import request\nimport os\nfn=getattr(os,request.args["name"])\nif callable(fn):\n fn("argument")')


def test_reflection_provenance_survives_qualified_name_loop_and_encoding():
    code='from flask import request\nfrom kombu.utils.encoding import from_utf8\nimport sys\ndata=request.get_json()\nfn=sys.modules[from_utf8(data["module"])]\nfor part in from_utf8(data["name"]).split("."):\n fn=getattr(fn,part)\nfn(*data["args"])'
    assert dynamic(code)


def test_missing_entrypoint_is_an_explicit_coverage_notice():
    entries=[dict(file='app.py',function='missing',parameter='data',reason='remote boundary')]
    assert any(f.rule_id=='PY-ENTRYPOINT-001' for f in analyze_python('app.py','def f():\n pass',entrypoints=entries))


def test_shadowed_getattr_is_not_builtin_reflection():
    assert not dynamic('from flask import request\nimport os\ndef getattr(obj,name):\n return os.getcwd\nfn=getattr(os,request.args["name"])\nfn()')


def test_untyped_library_parameter_is_not_automatically_an_input_source():
    assert not dynamic('import sys\ndef decode(data):\n fn=getattr(sys.modules[data["module"]],data["name"])\n return fn()')


def test_explicit_contract_is_conditional_and_has_trace_reason_and_maturity():
    code='import sys\ndef decode(data):\n fn=getattr(sys.modules[data["module"]],data["name"])\n return fn()'
    entries=[dict(file='app.py',function='decode',parameter='data',reason='Application feeds untrusted backend records')]
    fs=dynamic(code,entrypoints=entries)
    assert fs and fs[0].evidence_kind=='configured-flow' and fs[0].maturity=='advisory'
    assert 'Application feeds untrusted backend records' in fs[0].description
    assert fs[0].trace[0]['line_number']==2
    assert not dynamic(code,entrypoints=[dict(entries[0],file='other.py')])


@pytest.mark.parametrize('root',['requests','httpx'])
@pytest.mark.parametrize('field',['text','content','json()'])
def test_http_response_body_is_a_source(root,field):
    fs=analyze_python('app.py',f'import {root}\nimport os\nr={root}.get("https://example.invalid")\nos.system(r.{field})')
    assert any(f.cwe=='CWE-78' and f.trace[0]['line_number']==3 for f in fs)


def test_http_metadata_is_not_response_content():
    fs=analyze_python('app.py','import requests,os\nr=requests.get("https://example.invalid")\nos.system(str(r.status_code))')
    assert not any(f.cwe=='CWE-78' for f in fs)


@pytest.mark.parametrize('constructor',['requests.Session','httpx.Client'])
def test_http_client_response_source(constructor):
    root=constructor.split('.')[0]
    code=f'import {root},os\nclient={constructor}()\nr=client.get("https://example.invalid")\nos.system(r.text)'
    assert any(f.cwe=='CWE-78' for f in analyze_python('app.py',code))


def test_async_http_client_response_source():
    code='import httpx,os\nasync def f():\n async with httpx.AsyncClient() as client:\n  r=await client.get("https://example.invalid")\n  os.system(r.text)'
    assert any(f.cwe=='CWE-78' for f in analyze_python('app.py',code))


def test_reflection_can_use_constant_module_with_external_attribute():
    assert dynamic('import sys\nfrom flask import request\nfn=getattr(sys.modules["os"],request.args["name"])\nfn("arg")')


def test_default_http_source_can_drive_dynamic_target():
    assert dynamic('import requests,os\ndata=requests.get("https://example.invalid").json()\nfn=getattr(os,data["name"])\nfn(data["argument"])')


def test_class_constraint_does_not_survive_reassignment():
    code='from flask import request\nimport os\nfn=getattr(os,request.args["name"])\nif not issubclass(fn,BaseException):\n raise ValueError()\nfn=getattr(os,request.args["other"])\nfn("arg")'
    assert dynamic(code)


def test_sanitizer_ablation_preserves_reflection_provenance_and_removes_only_class_constraint():
    code='from flask import request\nimport os\nfn=getattr(os,request.args["name"])\nif not issubclass(fn,BaseException):\n raise ValueError()\nfn("message")'
    assert not dynamic(code)
    assert dynamic(code,disabled_features={'sanitizers'})


def test_unresolved_attribute_chain_has_bounded_source_traversal(monkeypatch):
    import ast
    from scanner.python_analysis import PythonAIAnalyzer
    analyzer=PythonAIAnalyzer('app.py','')
    original=analyzer._source
    calls=0
    def counted(node):
        nonlocal calls
        calls+=1
        return original(node)
    monkeypatch.setattr(analyzer,'_source',counted)
    expression=ast.parse('value'+'.attribute'*18,mode='eval').body
    assert analyzer._source(expression) is None
    assert calls<100  # A repeated traversal of each prefix previously grew exponentially.


def test_remote_html_attributes_reach_file_paths():
    code='import requests\nfrom bs4 import BeautifulSoup\npage=BeautifulSoup(requests.get("https://example.invalid").text,"html.parser")\nfor tag in page.select("input"):\n open(tag.get("value"),"rb")'
    assert any(f.rule_id=='PY-SAST-PATH-001' for f in analyze_python('app.py',code))
    assert not any(f.rule_id=='PY-SAST-PATH-001' for f in analyze_python('app.py',code.replace('requests.get("https://example.invalid").text','"<input value=local>"')))


@pytest.mark.parametrize('entry',[
    dict(file='../app.py',function='f',parameter='x',reason='remote'),
    dict(file='app.py',function='f()',parameter='x',reason='remote'),
    dict(file='app.py',function='f',parameter='self',reason='remote'),
    dict(file='app.py',function='f',parameter='x',reason=''),
    dict(file='app.py',function='f',parameter='x',reason='remote',type='made.up.Type'),
])
def test_invalid_contracts_fail_validation(entry):
    with pytest.raises(ValueError):
        validate_entrypoints([entry])


def test_entrypoint_configuration_survives_cli_config_loading(tmp_path):
    entry=dict(file='app.py',function='f',parameter='x',reason='Remote form boundary',type='bs4.element.Tag')
    (tmp_path/'theron.yml').write_text(json.dumps(dict(analysis_entrypoints=[entry])))
    assert load_config(str(tmp_path))['analysis_entrypoints']==[entry]


@pytest.mark.parametrize('guard',[
    'if not issubclass(other,BaseException):\n raise ValueError()',
    'if not issubclass(fn,object):\n raise ValueError()',
    'if not issubclass(fn,BaseException):\n pass',
])
def test_unrelated_or_nonterminating_guards_do_not_hide_dynamic_invocation(guard):
    code='from flask import request\nimport os\nfn=getattr(os,request.args["name"])\n'+guard+'\nfn("arg")'
    assert dynamic(code)


def test_shadowed_exception_guard_does_not_establish_boundary():
    code='from flask import request\nimport os\nissubclass=lambda *args: True\nfn=getattr(os,request.args["name"])\nif not issubclass(fn,BaseException):\n raise ValueError()\nfn("arg")'
    assert dynamic(code)


def test_contract_reason_and_origin_survive_imported_helper():
    from scanner.python_project import PythonProject
    files={'app.py':'from helper import consume\ndef decode(data):\n consume(data)',
           'helper.py':'def consume(path):\n open(path)'}
    entries=[dict(file='app.py',function='decode',parameter='data',reason='Remote path from service caller')]
    fs=analyze_python('app.py',files['app.py'],project=PythonProject(files),entrypoints=entries)
    path=next(f for f in fs if f.rule_id=='PY-SAST-PATH-001')
    assert path.file_path=='helper.py' and path.evidence_kind=='configured-flow'
    assert path.trace[0]['file_path']=='app.py' and path.maturity=='advisory'


def test_cli_scan_retains_conditional_classification_in_all_reports(tmp_path,monkeypatch):
    from scanner.cli import main
    code='import sys\ndef decode(data):\n fn=getattr(sys.modules[data["module"]],data["name"])\n return fn()'
    (tmp_path/'app.py').write_text(code)
    entry=dict(file='app.py',function='decode',parameter='data',reason='Service accepts external records')
    (tmp_path/'theron.yml').write_text(json.dumps(dict(analysis_entrypoints=[entry])))
    for fmt in ['json','html','sarif']:
        target=tmp_path/('report.'+fmt)
        monkeypatch.setattr('sys.argv',['ai-sec-scan','--local',str(tmp_path),'--modules','sast','--format',fmt,'--output',str(target)])
        main()
        text=target.read_text(encoding='utf-8')
        assert 'configured-flow' in text and 'advisory' in text and entry['reason'] in text


def test_shared_ui_fixture_and_correlation_preserve_observed_vs_configured_evidence():
    from pathlib import Path
    from tests.library_delivery_fixture import build
    result=build()
    assert json.loads((Path(__file__).parent/'fixtures/library-boundary-report.json').read_text())==result.to_dict()
    assert len(result.findings)==2 and len(result.correlation_groups)==1
    observed=next(f for f in result.findings if f.evidence_kind=='static-flow')
    configured=next(f for f in result.findings if f.evidence_kind=='configured-flow')
    assert result.correlation_groups[0]['finding_fingerprints']==[observed.fingerprint]
    assert configured.fingerprint not in result.correlation_groups[0]['finding_fingerprints']
