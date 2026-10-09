"""Original small web/network fixtures; never import or execute scanned code."""

import pytest

from scanner.python_analysis import analyze_python


@pytest.mark.parametrize("code,cwe", [
    ('import socket, pickle\nwith socket.socket() as channel:\n payload = channel.recv(1024)\n pickle.loads(payload)', 'CWE-502'),
    ('import socket, pickle\nclass Reader:\n def load(self):\n  with socket.socket() as stream:\n   self.decode(stream.recv(1024))\n def decode(self, payload):\n  return pickle.loads(payload)', 'CWE-502'),
    ('from django.views import View as Base\nfrom django.http import HttpResponse as Reply\nclass Search(Base):\n def get(self, incoming):\n  query = incoming.GET.get("q", "")\n  return Reply(f"<p>{query}</p>")', 'CWE-79'),
    ('from django.http import HttpRequest, HttpResponse\ndef search(request: HttpRequest):\n return HttpResponse(content=request.POST["q"], content_type="text/html; charset=utf-8")', 'CWE-79'),
    ('from flask import request\nfrom fastapi.responses import HTMLResponse\nHTMLResponse(request.args.get("q"))', 'CWE-79'),
    ('from django.views import View\nimport os\nclass Runner(View):\n def post(self, request):\n  os.system(request.POST["cmd"])', 'CWE-78'),
    ('from http.server import BaseHTTPRequestHandler\nimport pickle\nclass Handler(BaseHTTPRequestHandler):\n def do_POST(self):\n  pickle.loads(self.rfile.read(1024))', 'CWE-502'),
    ('from http.server import BaseHTTPRequestHandler\nimport os\nclass Handler(BaseHTTPRequestHandler):\n def do_GET(self):\n  os.system(self.path)', 'CWE-78'),
    ('from tornado.web import RequestHandler\nimport os\nclass Handler(RequestHandler):\n def post(self):\n  os.system(self.get_body_argument("cmd"))', 'CWE-78'),
])
def test_resolved_web_and_network_flows(code, cwe):
    findings = analyze_python("app.py", code, module="sast")
    assert len(findings) == 1
    assert findings[0].cwe == cwe
    assert findings[0].confidence == "high"
    assert findings[0].maturity == "stable"
    assert findings[0].line_number
    assert "from line" in findings[0].description


@pytest.mark.parametrize("code", [
    'import pickle\ndef read(channel):\n pickle.loads(channel.recv(1024))',
    'import socket, pickle\nwith socket.socket() as channel:\n channel.recv(1024)\n pickle.loads(b"trusted")',
    'import socket, json\nwith socket.socket() as channel:\n json.loads(channel.recv(1024))',
    'import socket, pickle\ndef read(socket):\n with socket.socket() as channel:\n  pickle.loads(channel.recv(1024))',
    'import socket, pickle\nwith socket.socket() as channel:\n channel = cache\n pickle.loads(channel.recv(1024))',
    'from django.http import HttpResponse\ndef search(request):\n return HttpResponse(request.GET["q"])',
    'from django.http import HttpResponse\nclass View:\n pass\nclass Search(View):\n def get(self, request):\n  return HttpResponse(request.GET["q"])',
    'from django.http import HttpRequest, HttpResponse\nfrom django.utils.html import escape\ndef search(request: HttpRequest):\n return HttpResponse(escape(request.GET["q"]))',
    'from django.http import HttpRequest, HttpResponse\nimport html\ndef search(request: HttpRequest):\n safe = html.escape(request.GET["q"])\n return HttpResponse(f"<p>{safe}</p>")',
    'from django.http import HttpResponse\nHttpResponse("trusted")',
    'from django.http import HttpResponse\nHttpResponse(input(), content_type="text/plain")',
    'from django.http import HttpResponse\nHttpResponse(input(), "text/plain")',
    'from django.http import HttpResponse\nHttpResponse(input(), headers={"Content-Type": "text/plain"})',
    'from django.http import HttpResponse\nHttpResponse(input(), **options)',
    'from django.http import JsonResponse\nJsonResponse({"value": input()})',
    'from starlette.responses import HTMLResponse\nHTMLResponse(input(), media_type="application/json")',
    'from starlette.responses import HTMLResponse\ndef render(HTMLResponse):\n return HTMLResponse(input())',
    'import pickle\nclass Handler:\n def do_POST(self):\n  pickle.loads(self.rfile.read(1024))',
    'import os\nclass Handler:\n def post(self):\n  os.system(self.get_argument("cmd"))',
])
def test_web_network_near_misses_stay_quiet(code):
    assert analyze_python("safe.py", code, module="sast") == []


@pytest.mark.parametrize("format", ["json", "sarif"])
def test_new_html_findings_reach_reports_without_cross_module_duplicates(tmp_path, monkeypatch, format):
    import json
    from scanner.cli import main

    (tmp_path / "app.py").write_text(
        'from django.http import HttpRequest, HttpResponse\ndef search(request: HttpRequest):\n return HttpResponse(request.GET["q"])',
        encoding="utf-8",
    )
    report = tmp_path / f"report.{format}"
    monkeypatch.setattr("sys.argv", ["ai-sec-scan", "--local", str(tmp_path), "--modules", "ai,sast",
                                    "--format", format, "--output", str(report)])
    main()
    data = json.loads(report.read_text(encoding="utf-8"))
    if format == "json":
        assert len(data["findings"]) == 1
        assert data["findings"][0]["rule_id"] == "PY-SAST-XSS-001"
        assert data["findings"][0]["fingerprint"]
    else:
        results = data["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "PY-SAST-XSS-001"
        assert results[0]["partialFingerprints"]
