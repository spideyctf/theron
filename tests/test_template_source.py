"""Original template-boundary controls. Never render or execute scanned templates."""
import pytest

from scanner.python_analysis import analyze_python
from scanner.python_project import PythonProject
from tests.test_correlation import sample


@pytest.mark.parametrize('code',[
 'from flask import request,render_template_string\nrender_template_string(request.args["template"])',
 'from flask import request,render_template_string as render\nrender(source=request.args["template"])',
 'from quart import request,render_template_string\nrender_template_string(request.args["template"])',
 'from flask import request,render_template_string\nimport html\nrender_template_string(html.escape(request.args["template"]))',
 'from flask import request,render_template_string\ndef build(x):\n return "Hello "+x\nrender_template_string(build(request.args["name"]))',
])
def test_untrusted_template_source(code):
    fs=analyze_python('app.py',code)
    assert any(f.cwe=='CWE-1336' and f.trace[0]['role']=='source' for f in fs)


@pytest.mark.parametrize('code',[
 'from flask import request,render_template_string\nrender_template_string("Hello {{ name }}",name=request.args["name"])',
 'from flask import request,render_template_string\nrender_template_string(source="Hello {{ name }}",name=request.args["name"])',
 'from custom import render_template_string\nfrom flask import request\nrender_template_string(request.args["template"])',
 'from flask import request,render_template_string\nrender_template_string=object()\nrender_template_string(request.args["template"])',
 'from flask import request,render_template\nrender_template("page.html",name=request.args["name"])',
 'from flask import request,render_template_string\nx=request.args["x"]\nx="Hello {{ name }}"\nrender_template_string(x,name=request.args["name"])',
])
def test_context_values_and_unresolved_renderers_are_not_source_injection(code):
    assert not any(f.cwe=='CWE-1336' for f in analyze_python('app.py',code))


def test_imported_builder_provenance():
    files={'app.py':'from flask import request,render_template_string\nfrom helper import build\nrender_template_string(build(request.args["name"]))',
           'helper.py':'def build(value):\n return "Hello "+value'}
    fs=analyze_python('app.py',files['app.py'],project=PythonProject(files))
    assert any(f.cwe=='CWE-1336' and f.trace for f in fs)
    assert not any(f.cwe=='CWE-1336' for f in analyze_python('app.py',files['app.py'],project=PythonProject(files),disabled_features=['local_imports']))


def test_template_flow_uses_existing_correlation_evidence():
    _,result=sample(code='from flask import request,render_template_string\nrender_template_string(request.args["template"])')
    assert len(result.correlation_groups)==1
    assert result.summary['vulnerability_findings']==1
    assert result.findings[0].cwe=='CWE-1336'
