"""Original fixtures for framework identity, destination arguments and redirect boundaries."""
import pytest

from scanner.python_analysis import analyze_python


@pytest.mark.parametrize('expression', [
    'self.redirect(self.request.uri.rstrip("/"))',
    'self.redirect(url=self.request.path)',
    'self.redirect(self.get_query_argument("next"))',
    'self.redirect(self.request.headers.get("Referer"))',
])
def test_tornado_redirect_sources_and_inherited_handlers(expression):
    code = ('from tornado.web import RequestHandler as Handler\n'
            'class Base(Handler):\n pass\n'
            'class Endpoint(Base):\n def get(self):\n  ' + expression)
    assert analyze_python('service.py', code, module='sast') == []
    findings = analyze_python('service.py', code, module='sast', include_experimental=True)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.cwe == 'CWE-601' and finding.rule_id == 'PY-SAST-REDIRECT-001'
    assert finding.line_number == 6 and finding.confidence == 'medium' and finding.maturity == 'experimental'
    assert finding.trace == [dict(role='source',file_path='service.py',line_number=6),
                             dict(role='sink',file_path='service.py',line_number=6)]


@pytest.mark.parametrize('response', ['HTTPMovedPermanently', 'HTTPFound', 'HTTPSeeOther',
                                      'HTTPTemporaryRedirect', 'HTTPPermanentRedirect'])
def test_aiohttp_typed_request_and_location_keyword(response):
    code = ('from aiohttp import web as http\n'
            'async def route(incoming: http.Request):\n'
            f' return http.{response}(location=incoming.path_qs.rstrip("/"))')
    assert analyze_python('service.py', code, module='sast') == []
    findings = analyze_python('service.py', code, module='sast', include_experimental=True)
    assert len(findings) == 1 and findings[0].cwe == 'CWE-601'


@pytest.mark.parametrize('tail', [
    'value, *pieces = self.request.uri.partition("?")\n  self.redirect(value)',
    'value, sep, query = self.request.uri.partition("?")\n  self.redirect(query)',
    'value, *pieces = self.request.uri.rpartition("?")\n  self.redirect("".join(pieces))',
    'value, *pieces = self.request.uri.partition("?")\n  self.redirect("/" + value.strip("/"))',
])
def test_partition_unpack_does_not_erase_taint_or_invent_url_sanitizer(tail):
    code = 'from tornado.web import RequestHandler\nclass Endpoint(RequestHandler):\n def get(self):\n  ' + tail
    assert any(f.cwe == 'CWE-601' for f in analyze_python('service.py', code, include_experimental=True))


@pytest.mark.parametrize('code', [
    'class Endpoint:\n def get(self):\n  self.redirect(self.request.uri)',
    'from aiohttp import web\nasync def route(request):\n return web.HTTPFound(request.path)',
    'from tornado.web import RequestHandler\nclass Endpoint(RequestHandler):\n def get(self):\n  self.redirect("/home")',
    'from tornado.web import RequestHandler\nclass Endpoint(RequestHandler):\n def get(self):\n  value=self.get_argument("next")\n  if value not in {"/home", "/account"}:\n   raise ValueError()\n  self.redirect(value)',
    'from tornado.web import RequestHandler\nclass Endpoint(RequestHandler):\n def get(self):\n  value=self.request.uri\n  value="/home"\n  self.redirect(value)',
    'from tornado.web import RequestHandler\nclass Endpoint(RequestHandler):\n def get(self):\n  value, *rest=self.request.uri.partition("?")\n  value="/home"\n  self.redirect(value)',
    'from tornado.web import RequestHandler\nclass Endpoint(RequestHandler):\n def redirect(self, url):\n  return None\n def get(self):\n  self.redirect(self.request.uri)',
    'from aiohttp import web\nasync def route(request: web.Request):\n return web.HTTPFound("/home", reason=request.path)',
    'from aiohttp import web\nasync def route(request: web.Request):\n web=custom\n return web.HTTPFound(request.path)',
    'from flask import request, redirect\nredirect("/home", code=request.args["status"])',
    'from tornado.web import RequestHandler\nclass Base(RequestHandler):\n def redirect(self, url):\n  return None\nclass Endpoint(Base):\n def get(self):\n  self.redirect(self.request.uri)',
    'from tornado.web import RequestHandler\nclass Base(RequestHandler):\n def get_argument(self, name):\n  return "safe"\nclass Endpoint(Base):\n def get(self):\n  self.redirect(self.get_argument("next"))',
    'from tornado.web import RequestHandler\nclass Endpoint(RequestHandler):\n def get(self):\n  self.get_argument=unknown\n  self.redirect(self.get_argument("next"))',
])
def test_safe_destinations_and_unresolved_frameworks_stay_quiet(code):
    assert analyze_python('service.py', code, include_experimental=True) == []


def test_framework_source_reaches_other_sinks_without_url_only_sanitization():
    code = ('from tornado.web import RequestHandler\nimport os\n'
            'class Endpoint(RequestHandler):\n def post(self):\n'
            '  os.system(self.request.body.decode())')
    assert any(f.cwe == 'CWE-78' for f in analyze_python('service.py', code))


@pytest.mark.parametrize('api,keyword', [('flask.redirect','location'), ('django.shortcuts.redirect','to'),
                                         ('starlette.responses.RedirectResponse','url')])
def test_resolved_destination_keywords(api,keyword):
    module,name=api.rsplit('.',1)
    code=f'from {module} import {name}\nfrom flask import request\n{name}({keyword}=request.args["next"])'
    assert any(f.cwe == 'CWE-601' for f in analyze_python('service.py',code))


def test_sast_plugin_exposes_redirect_candidates_only_when_requested():
    from scanner.plugins.sast import SASTScanner
    from scanner.models import ScanContext
    from scanner.profiler import ProjectProfile
    from scanner.rule_loader import RuleLoader
    files={'service.py':'from tornado.web import RequestHandler\nclass Endpoint(RequestHandler):\n def get(self):\n  self.redirect(self.request.uri)'}
    def scan(experimental):
        return SASTScanner().scan(ScanContext(files=files,repo_info={},project_profile=ProjectProfile(),
                                             rule_loader=RuleLoader(),config={'include_experimental':experimental}))
    assert not scan(False)
    candidates=[f for f in scan(True) if f.rule_id=='PY-SAST-REDIRECT-001']
    assert len(candidates)==1 and candidates[0].maturity=='experimental'


@pytest.mark.parametrize('statement,expected', [
    ('db.execute(f"select * from records where name = \'{value}\'")', True),
    ('db.execute("select * from records where name = ?", (value,))', False),
])
def test_inherited_tornado_json_body_sql_boundary(statement,expected):
    code=('from tornado.web import RequestHandler\nimport json,sqlite3\n'
          'class Base(RequestHandler):\n pass\nclass Endpoint(Base):\n def post(self):\n'
          '  value=json.loads(self.request.body)["name"]\n'
          '  db=sqlite3.connect(":memory:")\n  ' + statement)
    assert any(f.cwe=='CWE-89' for f in analyze_python('service.py',code)) is expected


def test_partition_literal_separator_is_not_attacker_controlled():
    code='import os\nhead, separator, tail = input().partition("?")\nos.system(separator)'
    assert analyze_python('service.py',code)==[]
