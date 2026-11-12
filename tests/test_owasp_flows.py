"""Original regression examples; no OWASP corpus source is bundled or executed."""
import json
from pathlib import Path

import pytest

from scanner.models import ProjectProfile, ScanContext
from scanner.owasp_benchmark import evaluate, family_digest, load_files, prepare
from scanner.plugins.sast import SASTScanner
from scanner.python_analysis import analyze_python
from scanner.rule_loader import RuleLoader


@pytest.mark.parametrize('code,cwe', [
    ('from flask import request\nimport codecs\ncodecs.open(request.values.get("f"))', 'CWE-22'),
    ('from flask import request\nv={}\nv["x"]=request.form.get("q")\nexec(v["x"])', 'CWE-94'),
    ('from flask import request\nv={"x": request.form.get("q")}\ndef use(v):\n exec(v["x"])\nuse(v)', 'CWE-94'),
    ('from flask import request\nimport configparser\nc=configparser.ConfigParser()\nc.set("s","k",request.args.get("q"))\nexec(c.get("s","k"))', 'CWE-94'),
    ('from flask import request\nx=request.form.getlist("q")\nexec(x[0])', 'CWE-94'),
    ('from flask import request\nx=[]\nx.append("fixed")\nx.append(request.args.get("q"))\nx.pop(0)\nexec(x[0])', 'CWE-94'),
    ('from flask import request\nx=request.args.get("q")\nmatch input():\n case "a":\n  y=x\n case _:\n  y="fixed"\nexec(y)', 'CWE-94'),
    ('from flask import request\nx=request.args.get("q")\ny=x if input() else "fixed"\nexec(y)', 'CWE-94'),
    ('from flask import request\nfrom lxml import etree\nroot=etree.XML("<data/>")\nroot.xpath(request.args.get("query"))', 'CWE-643'),
    ('from flask import request,redirect\nredirect(request.args.get("next"))', 'CWE-601'),
    ('from flask import Flask,request\na=Flask(__name__)\n@a.route("/")\ndef view():\n text="value: "\n text+=request.args.get("q")\n return text', 'CWE-79'),
    ('from flask import Flask,request\na=Flask(__name__)\n@a.route("/")\ndef view():\n return request.args.get("q") if input() else "fixed"', 'CWE-79'),
])
def test_supported_flows(code, cwe):
    found = analyze_python('service.py', code)
    assert any(f.cwe == cwe and f.trace for f in found)


@pytest.mark.parametrize('code', [
    'from flask import request\nv={}\nv["x"]=request.args.get("q")\nv["x"]="fixed"\nexec(v["x"])',
    'from flask import request\nv={"x":request.args.get("q"),"y":"fixed"}\nexec(v["y"])',
    'from flask import request\nx=[]\nx.append("a")\nx.append(request.args.get("q"))\nx.append("b")\nx.pop(0)\nexec(x[1])',
    'from flask import request\nx=[]\nx.append(request.args.get("q"))\nx.pop()\nx.append("fixed")\nexec(x[0])',
    'from flask import request\nx=request.args.get("q")\nn=12\nif 3*9-n>10:\n x="fixed"\nexec(x)',
    'from flask import request\nx=request.args.get("q")\nmatch "a":\n case "a":\n  x="fixed"\n case _:\n  x=request.args.get("other")\nexec(x)',
    'from flask import request\nx=request.args.get("q")\nexec("fixed" if 5>2 else x)',
    'from flask import request\nimport os\nos.path.exists(request.args.get("path"))',
    'from flask import Flask,request\na=Flask(__name__)\n@a.route("/")\ndef view():\n return {"value":request.args.get("q")}',
    'from flask import Flask,request,make_response\na=Flask(__name__)\n@a.route("/")\ndef view():\n return make_response(("fixed",{"X-Info": request.args.get("q")}))',
    'from flask import Flask,request\nimport html\na=Flask(__name__)\n@a.route("/")\ndef view():\n return html.escape(request.args.get("q"))',
    'from flask import request\nfrom lxml import etree\nr=etree.XML("<data/>")\nr.xpath("//item[@id=$value]",value=request.args.get("id"))',
    'from flask import request,redirect\nfrom urllib.parse import urlparse\nx=request.args.get("next")\nu=urlparse(x)\nif u.netloc not in ["example.org"] or u.scheme!="https":\n raise ValueError()\nredirect(x)',
    'from flask import request,redirect\nfrom urllib.parse import urlparse\nx=request.args.get("next")\nu=urlparse(x)\nif u.hostname in ["example.org"] and u.scheme=="https":\n redirect(x)',
])
def test_safe_near_misses(code):
    assert analyze_python('service.py', code) == []


def test_redirect_scheme_only_is_not_enough():
    code='from flask import request,redirect\nfrom urllib.parse import urlparse\nx=request.args.get("next")\nu=urlparse(x)\nif u.scheme!="https":\n raise ValueError()\nredirect(x)'
    assert any(f.cwe == 'CWE-601' for f in analyze_python('service.py', code))


def test_inferred_factory_registration_is_disclosed():
    code='from flask import request\ndef register(app):\n @app.route("/")\n def view():\n  return request.args.get("q")'
    findings=analyze_python('service.py', code)
    assert len(findings) == 1
    assert findings[0].confidence == 'medium'
    assert 'inferred' in findings[0].description


def test_no_flask_route_guess_for_unrelated_library():
    assert analyze_python('service.py', 'from custom import request\ndef register(app):\n @app.route("/")\n def view():\n  return request.args.get("q")') == []


def test_mixed_sanitized_returns_keep_unsafe_branch():
    code='from flask import request\nimport html\ndef transform(x, flag):\n if flag:\n  return html.escape(x)\n return x\nfrom flask import Flask\na=Flask(__name__)\n@a.route("/")\ndef view():\n return transform(request.args.get("q"), input())'
    assert any(f.cwe == 'CWE-79' for f in analyze_python('service.py', code))


def test_ablations_disable_the_intended_mechanism():
    helper='import os\ndef action(x):\n os.system(x)\naction(input())'
    assert analyze_python('service.py', helper)
    assert not analyze_python('service.py', helper, disabled_features=['interprocedural'])
    html='from flask import Flask,request\nimport html\na=Flask(__name__)\n@a.route("/")\ndef v():\n return html.escape(request.args.get("q"))'
    assert not analyze_python('service.py', html)
    assert analyze_python('service.py', html, disabled_features=['sanitizers'])
    files={'entry.py':'from helper import action\naction(input())','helper.py':'import os\ndef action(x):\n os.system(x)'}
    def scan(disabled):
        return SASTScanner().scan(ScanContext(files, {}, ProjectProfile(), RuleLoader(), {'analysis_disabled_features':disabled}))
    assert scan([])
    assert not scan(['local_imports'])
    with pytest.raises(ValueError):
        analyze_python('service.py', '', disabled_features=['typo'])


def test_split_groups_and_source_integrity(tmp_path):
    (tmp_path/'testcode').mkdir()
    (tmp_path/'helpers').mkdir()
    (tmp_path/'expectedresults-0.1.csv').write_text('# labels\nBenchmarkTest00001,codeinj,true,94\nBenchmarkTest00002,codeinj,false,94\nBenchmarkTest00003,codeinj,true,94\n')
    samples=[('00001','family-a','exec(input())'), ('00002','family-a','exec("fixed")'), ('00003','family-b','exec(input())')]
    for number, family, body in samples:
        (tmp_path/f'testcode/BenchmarkTest{number}.py').write_text(f'# /benchmark/{family}/BenchmarkTest{number}\n{body}\n')
    manifest=prepare(tmp_path)
    assert manifest == prepare(tmp_path)
    a,b,c=manifest['cases']
    assert a['family']==b['family']==c['family']  # exact normalized AST duplicates also connect route templates
    assert a['split']==b['split']==c['split']=='development'
    result=evaluate(tmp_path, manifest, 'development')
    assert result['summary']['tp']==2 and result['summary']['tn']==1
    (tmp_path/'testcode/BenchmarkTest00001.py').write_text('pass')
    with pytest.raises(ValueError, match='source changed'):
        load_files(tmp_path, manifest, 'development')


def test_bandit_error_is_not_a_true_negative(tmp_path):
    (tmp_path/'testcode').mkdir()
    (tmp_path/'helpers').mkdir()
    (tmp_path/'expectedresults-0.1.csv').write_text('BenchmarkTest00001,codeinj,false,94\n')
    (tmp_path/'testcode/BenchmarkTest00001.py').write_text('# /benchmark/group/BenchmarkTest00001\npass')
    manifest=prepare(tmp_path)
    raw=tmp_path/'bandit.json'
    raw.write_text(json.dumps({'results':[],'errors':[{'filename':'stage/testcode/BenchmarkTest00001.py'}]}))
    result=evaluate(tmp_path, manifest, 'development', bandit_json=raw)
    assert result['summary']['errors']==1
    assert result['summary']['tn']==0


@pytest.mark.parametrize('rule,cwes,expected', [
    ('generic-code-rule', ['CWE-20: input', 'CWE-94: code'], 'tp'),
    ('insecure-hash-md5', ['CWE-327: crypto'], 'tp'),
    ('insecure-cipher', ['CWE-327: crypto'], 'fn'),
])
def test_semgrep_metadata_and_scoped_hash_mapping(tmp_path, rule, cwes, expected):
    (tmp_path/'testcode').mkdir()
    (tmp_path/'helpers').mkdir()
    cwe='94' if rule=='generic-code-rule' else '328'
    (tmp_path/'expectedresults-0.1.csv').write_text(f'BenchmarkTest00001,category,true,{cwe}\n')
    (tmp_path/'testcode/BenchmarkTest00001.py').write_text('# /benchmark/group/BenchmarkTest00001\npass')
    manifest=prepare(tmp_path)
    raw=tmp_path/'semgrep.json'
    raw.write_text(json.dumps({'results':[{'path':'stage/testcode/BenchmarkTest00001.py', 'check_id':rule,
                                          'start':{'line':2},'extra':{'metadata':{'cwe':cwes}}}], 'errors':[]}))
    result=evaluate(tmp_path,manifest,'development',semgrep_json=raw)
    assert result['cases'][0]['outcome']==expected
