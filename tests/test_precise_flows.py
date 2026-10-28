"""Original regressions for generalized flows, context-specific boundaries and cross-file calls."""
import json
import pytest
from scanner.python_analysis import analyze_python
from scanner.python_project import PythonProject
from scanner.advisories import advisory_severity, group_advisories, group_severity
from scanner.models import Severity, Finding, Category, ScanResult
from scanner.finding_utils import normalize_findings, partition_findings


@pytest.mark.parametrize('code,cwe', [
    ('import argparse,os\np=argparse.ArgumentParser()\np.add_argument("thing")\na=p.parse_args()\nos.system(a.thing)', 'CWE-78'),
    ('import sys,subprocess\nsubprocess.run(sys.argv[1],shell=True)', 'CWE-78'),
    ('import os\nclass Runner:\n def __init__(self,value):\n  self.value=value\n def go(self):\n  os.system(self.value)\nr=Runner(input())\nr.go()', 'CWE-78'),
    ('import os\ndef source():\n return input()\ndef wrapper():\n return source().strip()\nos.system(wrapper())', 'CWE-78'),
    ('from flask import Flask,send_file\napp=Flask(__name__)\n@app.get("/f/<path:item>")\ndef read(item):\n return send_file(item)', 'CWE-22'),
    ('from flask import request\nfrom pathlib import Path\nPath(request.args["f"]).read_text()', 'CWE-22'),
    ('from flask import request\nfrom pathlib import Path\np=Path("/srv") / request.args["f"]\np.read_bytes()', 'CWE-22'),
    ('from flask import request\nfrom pathlib import Path\np=Path(request.args["f"]).resolve()\nbase=Path(request.args["base"]).resolve()\nif p.is_relative_to(base):\n p.read_bytes()', 'CWE-22'),
    ('from flask import request\nimport os\np=os.path.abspath(request.args["f"])\nif p.startswith("/srv/data"):\n open(p)', 'CWE-22'),
    ('from flask import request\nimport requests\nrequests.get(url=request.args["url"])', 'CWE-918'),
    ('import html,os\nos.system(html.escape(input()))', 'CWE-78'),
    ('import shlex,os\nos.system(shlex.quote(input())+input())', 'CWE-78'),
    ('from flask import request\nfrom fastapi.responses import HTMLResponse\nimport html\nx=request.args["text"]\nif condition:\n x=html.escape(x)\nHTMLResponse(x)','CWE-79'),
    ('from flask import request\nfrom werkzeug.utils import secure_filename\nimport pickle\npickle.load(open(secure_filename(request.args["f"]),"rb"))', 'CWE-502'),
    ('from fastapi import FastAPI,Query\nfrom typing import Optional\nimport sqlite3\na=FastAPI()\n@a.get("/q")\ndef route(q:Optional[str]=Query(None)):\n db=sqlite3.connect(":memory:")\n db.execute(f"select {q}")','CWE-89'),
    ('from pyramid.view import view_config\nimport os\n@view_config(route_name="run")\ndef run(req):\n os.system(req.params["q"])','CWE-78'),
    ('from sanic import Sanic\nimport os\na=Sanic("x")\n@a.get("/run")\ndef run(request):\n os.system(request.args["q"])','CWE-78'),
    ('import cherrypy,os\nclass Api:\n @cherrypy.expose\n def run(self,**fields):\n  os.system(fields.get("q"))','CWE-78'),
    ('import os\ndef outer(value):\n def inner(command):\n  os.system(command)\n inner(value)\nouter(input())','CWE-78'),
    ('from fastapi import FastAPI\nfrom pydantic import BaseModel\nimport os\na=FastAPI()\nclass Payload(BaseModel):\n command:str\n@a.post("/go")\ndef go(payload:Payload):\n os.system(payload.command)','CWE-78'),
    ('import socket,threading,pickle\ndef handler(channel,address):\n pickle.loads(channel.recv(200))\ns=socket.socket()\nchannel,addr=s.accept()\nthreading.Thread(target=handler,args=(channel,addr))','CWE-502'),
])
def test_original_positive_flows(code,cwe):
    assert any(f.cwe==cwe for f in analyze_python('service.py',code))


@pytest.mark.parametrize('code', [
    'import argparse,subprocess\np=argparse.ArgumentParser()\na=p.parse_args()\nsubprocess.run(["echo",a.value],shell=False)',
    'import os\nclass Runner:\n def __init__(self,value):\n  self.value=value\n def go(self):\n  os.system(self.value)\nuntrusted=Runner(input())\ntrusted=Runner("echo safe")\ntrusted.go()',
    'import os\ndef sanitize(x):\n return "echo safe"\nos.system(sanitize(input()))',
    'import os\nclass Unknown:\n def parse_args(self):\n  return "x"\np=Unknown()\nos.system(p.parse_args())',
    'import shlex,os\nos.system("echo "+shlex.quote(input()))',
    'from flask import request\nfrom werkzeug.utils import secure_filename\nopen("/srv/"+secure_filename(request.args["f"]))',
    'from flask import request\nfrom pathlib import Path\np=(Path("/srv") / request.args["f"]).resolve()\nif not p.is_relative_to(Path("/srv").resolve()):\n raise ValueError()\np.read_text()',
    'from flask import request\nimport os\np=os.path.realpath(request.args["f"])\nroot=os.path.realpath("/srv")\nif os.path.commonpath([root,p]) != root:\n raise ValueError()\nopen(p)',
    'from flask import request\nimport requests\nrequests.post("https://fixed.example/api",data=request.get_json())',
    'from flask import request\nfrom fastapi.responses import HTMLResponse\nimport html\nHTMLResponse(html.escape(request.args["text"]))',
    'import os\np=input("Choose a local file: ")\nopen(p)',
    'import os\nclass Unknown:\n def get(self,x):\n  return "safe"\nr=Unknown()\nos.system(r.get("cmd"))',
    'from fastapi import FastAPI\nfrom pydantic import BaseModel\nimport sqlite3\na=FastAPI()\nclass Payload(BaseModel):\n number:int\n@a.post("/go")\ndef go(payload:Payload):\n db=sqlite3.connect(":memory:")\n db.execute(f"select {payload.number}")',
])
def test_original_near_misses(code):
    assert analyze_python('service.py',code)==[]


def test_cross_file_flow_has_correct_source_and_sink_files():
    files={'api.py':'from flask import request\nfrom logic import run\nrun(request.args["cmd"])',
           'logic.py':'import os\ndef run(command):\n os.system(command)'}
    project=PythonProject(files)
    findings=analyze_python('api.py',files['api.py'],project=project)
    finding=next(f for f in findings if f.cwe=='CWE-78')
    assert finding.file_path=='logic.py' and finding.line_number==3
    assert finding.trace==[{'role':'source','file_path':'api.py','line_number':3},{'role':'sink','file_path':'logic.py','line_number':3}]


def test_cross_file_relative_return_and_safe_shadow():
    files={'pkg/api.py':'from flask import request\nfrom .helpers import adapt\nimport os\nos.system(adapt(request.args["cmd"]))',
           'pkg/helpers.py':'def adapt(value):\n return value.strip()'}
    findings=analyze_python('pkg/api.py',files['pkg/api.py'],project=PythonProject(files))
    assert any(f.cwe=='CWE-78' for f in findings)
    files['pkg/helpers.py']='def adapt(value):\n return "echo safe"'
    assert not analyze_python('pkg/api.py',files['pkg/api.py'],project=PythonProject(files))


def test_aliases_group_transitively_and_choose_authoritative_severity():
    records=[{'id':'PYSEC-X','aliases':['CVE-X'],'severity':[]},
             {'id':'GHSA-X','aliases':['CVE-X'],'database_specific':{'severity':'HIGH'}},
             {'id':'OTHER-X','aliases':['PYSEC-X']}]
    groups=list(group_advisories(records))
    assert len(groups)==1
    canonical,aliases,members=groups[0]
    assert canonical=='CVE-X' and set(aliases)=={'CVE-X','PYSEC-X','GHSA-X','OTHER-X'}
    assert group_severity(members)==(Severity.HIGH,'advisory-metadata')


def test_cvss_vector_is_scored_and_unknown_is_explicit():
    assert advisory_severity({'severity':[{'type':'CVSS_V3','score':'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}]})==(Severity.CRITICAL,'cvss-base-score')
    assert advisory_severity({})==(Severity.MEDIUM,'provisional-unknown')
    assert advisory_severity({'severity':[{'type':'CVSS_V3','score':'bad'}]})==(Severity.MEDIUM,'provisional-unknown')


def test_context_findings_are_retained_but_do_not_inflate_application_counts():
    def f(path):
        return Finding('match',Severity.CRITICAL,Category.SECRET_EXPOSURE,'ai','pattern',path,rule_id='SECRET')
    result=ScanResult('owner/repo','main',findings=normalize_findings([f('config.py'),f('tests/test_data.py'),f('examples/demo.py')]))
    partition_findings(result)
    assert len(result.findings)==1 and len(result.context_findings)==2
    assert result.findings[0].evidence_kind=='credential-pattern-unverified'
    assert result.summary['vulnerability_findings']==1
    assert len(result.to_dict()['context_findings'])==2


def test_github_scan_pins_revision_and_encodes_special_file_names(monkeypatch):
    from scanner.github_client import GitHubClient
    client=GitHubClient('fake-token')
    calls=[]
    def get(endpoint,params=None):
        calls.append(endpoint)
        return {'sha':'abc123'} if '/commits/' in endpoint else {'tree':[]}
    monkeypatch.setattr(client,'_get',get)
    assert client.get_tree('owner','repo','feature/scan')==[]
    assert client.revision=='abc123'
    assert calls==['/repos/owner/repo/commits/feature%2Fscan','/repos/owner/repo/git/trees/abc123?recursive=1']
    monkeypatch.setattr(client,'_get_raw',lambda url:url)
    assert client.get_file_content('owner','repo','src/a#b.py','abc123').endswith('/abc123/src/a%23b.py')


def test_source_from_test_caller_stays_contextual_in_application_helper():
    files={'tests/test_api.py':'from logic import run\nrun(input())','logic.py':'import os\ndef run(x):\n os.system(x)'}
    findings=analyze_python('tests/test_api.py',files['tests/test_api.py'],project=PythonProject(files))
    result=ScanResult('owner/repo','main',findings=normalize_findings(findings))
    partition_findings(result)
    assert not result.findings and result.context_findings[0].scope=='test'


def test_path_validator_cannot_trust_an_attacker_controlled_root():
    source='from flask import request\nimport os\ndef valid(base,p):\n base=os.path.realpath(base)\n p=os.path.realpath(p)\n return p.startswith(base+os.sep)\np=request.args["p"]\nif valid(request.args["root"],p):\n open(p)'
    assert any(f.cwe=='CWE-22' for f in analyze_python('service.py',source))
