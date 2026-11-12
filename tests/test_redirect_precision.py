"""Origin influence is distinct from input merely appearing in a URL path/query."""
import pytest

from scanner.python_analysis import analyze_python


def redirects(body, disabled_features=()):
    code = 'from flask import request,redirect\nvalue=request.args["next"]\n' + body
    return [f for f in analyze_python('service.py',code,disabled_features=disabled_features) if f.cwe=='CWE-601']


@pytest.mark.parametrize('expression', [
    '"/search?q="+value', '"https://trusted.invalid/items/"+value',
    'f"/lookup/{value}"', '"".join(["/docs/",value])',
    '"/#"+value', '"/?"+value',
])
def test_literal_prefix_keeps_observed_input_out_of_origin(expression):
    assert not redirects('redirect('+expression+')')
    assert redirects('redirect('+expression+')', disabled_features={'sanitizers'})


@pytest.mark.parametrize('expression', [
    '"/"+value', '"https://trusted.invalid"+value', '"https://"+value',
    'value+"/safe/"', 'f"{value}/safe"', '"".join([value,"/safe/"])',
    '("/safe/"+value).replace("/safe/","")', '("/safe/"+value)[6:]',
    '("/safe/"+value).split("/")[-1]', '("/safe/"+value).lstrip("/safe")',
])
def test_incomplete_authorities_and_prefix_removal_still_alert(expression):
    assert redirects('redirect('+expression+')')


@pytest.mark.parametrize('body', [
    'url="/safe/"+value\nurl=value\nredirect(url)',
    'url="/safe/"+value\nif condition:\n url="https://"\nurl+=value\nredirect(url)',
    'url="/safe/"+value\nif condition:\n url=value\nredirect(url)',
    'url="/safe/"+value\nwhile condition:\n url=value\nredirect(url)',
    'url="/safe/"+value\nredirect((url:=value))',
    'url="/safe/"+value\ndef change():\n pass\nchange()\nredirect(url)',
])
def test_reassignment_branches_and_unmodeled_local_calls_drop_proof(body):
    assert redirects(body)


@pytest.mark.parametrize('body', [
    'url="/safe/"+value\ncopy=url\nurl=value\nredirect(copy)',
    'url="/safe/"+value\nurl+=value\nredirect(url)',
    'if condition:\n url="/one/"+value\nelse:\n url="/two/"+value\nredirect(url)',
])
def test_alias_snapshots_and_all_branch_proofs_remain_valid(body):
    assert not redirects(body)


def query_code(change='', join='sep.join([self._url, self.request.query])'):
    return ('from tornado.web import RequestHandler\nclass Endpoint(RequestHandler):\n'
          ' def get(self):\n  sep="&" if "?" in self._url else "?"\n'
          + change + '  target=' + join + '\n  self.redirect(target)')


def query_join(change='', join='sep.join([self._url, self.request.query])'):
    return [f for f in analyze_python('service.py',query_code(change,join),include_experimental=True) if f.cwe=='CWE-601']


def test_query_only_join_does_not_claim_input_controls_origin():
    assert not query_join()


@pytest.mark.parametrize('change,join', [
    ('  self._url=self.get_argument("next")\n', 'sep.join([self._url,self.request.query])'),
    ('  self._url="https://"\n', 'sep.join([self._url,self.request.query])'),
    ('  sep=""\n', 'sep.join([self._url,self.request.query])'),
    ('', 'sep.join([self.other_url,self.request.query])'),
    ('', 'sep.join([self.request.query,self._url])'),
    ('  if condition:\n   sep=""\n', 'sep.join([self._url,self.request.query])'),
    ('', 'custom.join([self._url,self.request.query])'),
])
def test_separator_proof_is_specific_to_an_unchanged_base(change,join):
    assert query_join(change,join)


def test_redirect_proof_does_not_sanitize_command_execution():
    code='import os\nurl="/safe/"+input()\nos.system(url)'
    assert any(f.cwe=='CWE-78' for f in analyze_python('service.py',code))


def test_function_scopes_do_not_reuse_other_local_prefixes():
    code=('from flask import request,redirect\ndef first():\n url="/safe/"+request.args["next"]\n redirect(url)\n'
          'def second():\n url=request.args["next"]\n redirect(url)')
    matches=[f for f in analyze_python('service.py',code) if f.cwe=='CWE-601']
    assert len(matches)==1 and matches[0].line_number==7


def test_unresolved_query_base_is_a_notice_and_ablation_restores_candidate():
    from scanner.models import Severity
    findings=analyze_python('service.py',query_code(),include_experimental=True)
    assert len(findings)==1 and findings[0].severity==Severity.INFO
    assert findings[0].cwe is None and findings[0].evidence_kind=='coverage-notice'
    assert findings[0].rule_id=='PY-REDIRECT-COVERAGE-001'
    assert findings[0].trace[0]['role']=='source' and findings[0].trace[-1]['role']=='sink'
    assert any(f.cwe=='CWE-601' for f in analyze_python('service.py',query_code(),include_experimental=True,disabled_features={'sanitizers'}))


@pytest.mark.parametrize('format',['json','sarif'])
def test_query_notice_survives_exports_without_vulnerability_count(format):
    import json
    from scanner.models import ScanResult
    from scanner.finding_utils import normalize_findings
    from scanner.reporters.json_reporter import generate_json_report
    from scanner.reporters.sarif import generate_sarif_report
    result=ScanResult(repo_full_name='local/review',branch='local',
                      findings=normalize_findings(analyze_python('service.py',query_code(),include_experimental=True)))
    assert result.summary['vulnerability_findings']==0
    data=json.loads((generate_json_report if format=='json' else generate_sarif_report)(result))
    if format=='json':
        assert data['findings'][0]['evidence_kind']=='coverage-notice'
    else:
        assert data['runs'][0]['results'][0]['level']=='none'
        assert data['runs'][0]['results'][0]['properties']['evidence_kind']=='coverage-notice'


def test_attribute_assignment_is_not_assumed_to_bypass_property_transforms():
    code=('from tornado.web import RequestHandler\nclass Endpoint(RequestHandler):\n'
          ' @property\n def target(self):\n  return self._target[6:]\n'
          ' @target.setter\n def target(self,value):\n  self._target=value\n'
          ' def get(self):\n  self.target="/safe/"+self.get_argument("next")\n  self.redirect(self.target)')
    assert any(f.cwe=='CWE-601' for f in analyze_python('service.py',code,include_experimental=True))
