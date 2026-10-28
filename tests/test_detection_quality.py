"""Deterministic positive and near-miss cases; no network or scanned-code execution."""

import json
import pytest
import requests

from scanner.finding_utils import normalize_findings
from scanner.models import ProjectProfile, ScanContext, Severity
from scanner.plugins import ensure_plugins_loaded
from scanner.plugins.sca import SCAScanner
from scanner.python_analysis import analyze_python
from scanner.rule_loader import RuleLoader


def context(files, experimental=False):
    return ScanContext(files=files, repo_info={}, project_profile=ProjectProfile(),
                       rule_loader=RuleLoader(), config={"include_experimental": experimental})


@pytest.mark.parametrize("code", [
    'import os\ncommand = input()\nos.system(command)',
    'from os import system as execute\nexecute(input())',
    'from flask import request\nimport subprocess\nx = request.args.get("cmd")\nsubprocess.run(x, shell=True)',
    'import openai\nclient = openai.OpenAI()\nresponse = client.responses.create(input="hello")\ncode = response.output_text\nexec(code)',
    'from openai import OpenAI as Client\nclient = Client()\ndef run():\n response = client.chat.completions.create(messages=[])\n code = response.choices[0].message.content\n eval(code)',
    'import anthropic\nclient = anthropic.Anthropic()\nexec(client.messages.create(messages=[]).content[0].text)',
    'import pickle\npickle.loads(input())',
    'import yaml\nyaml.load(input(), Loader=yaml.UnsafeLoader)',
    'import torch\ntorch.load(input(), weights_only=False)',
    'import openai\nasync def run():\n response: str = await openai.responses.create(input="hello")\n exec(response.output_text)',
])
def test_evidenced_flows_alert(code):
    findings = analyze_python("app.py", code)
    assert len(findings) == 1
    assert findings[0].confidence == "high"
    assert findings[0].maturity == "stable"
    assert "from line" in findings[0].description


@pytest.mark.parametrize("code", [
    'import openai\nopenai.chat.completions.create(messages=[input()])',
    'response = image.generate()\nexec(response)',
    'import os\ncommand = input()\ncommand = "echo hello"\nos.system(command)',
    'import openai\ndef first():\n response = openai.responses.create(input="hi")\ndef second():\n response = "print(1)"\n exec(response)',
    'import openai\ndef run(openai):\n exec(openai.responses.create(input="hi"))',
    'def run(user_input):\n eval(user_input)',
    'import subprocess\nsubprocess.run(["echo", input()], shell=False)',
    'import subprocess\nsubprocess.run("echo hello", cwd=input(), shell=True)',
    'eval("1+1", {"value": input()})',
    'import pickle\npickle.load(open("trusted.pkl", "rb"))',
    'import yaml\nyaml.load(input(), Loader=yaml.SafeLoader)',
    'from yaml import load, CSafeLoader\nload(input(), Loader=CSafeLoader)',
    'import torch\ntorch.load(input(), weights_only=True)',
    'import torch\ntorch.load("weights.pt")',
    'import yaml\nyaml.load(input(), Loader=yaml.FullLoader)',
    'import openai\nexec(openai.responses.create(input="hi"))',
    'API_KEY = "documentation-label"\nTOKEN = "placeholder-token"',
    'def eval(value):\n return value\neval(input())',
    'commands = {"hello": "echo hello"}\nimport os\nos.system(commands[input()])',
    'import os\nx = input()\nif x in {"echo hello", "echo goodbye"}:\n os.system(x)',
    '# exec(openai.responses.create())\ntext = "pickle.loads(input())"',
])
def test_near_misses_do_not_alert(code):
    assert analyze_python("safe.py", code) == []


def test_prompt_is_review_only_and_opt_in():
    findings = analyze_python("app.py", 'import openai\nopenai.responses.create(input=input())', include_experimental=True)
    assert len(findings) == 1
    assert findings[0].maturity == "experimental"
    assert findings[0].confidence == "medium"


def test_syntax_failure_reports_incomplete_analysis():
    findings = analyze_python("broken.py", "def broken(")
    assert findings[0].severity == Severity.INFO
    assert findings[0].rule_id == "PY-PARSE-001"


def test_sast_alone_runs_ast_and_modules_deduplicate():
    ctx = context({"src/distribution.py": "import os\nos.system(input())"})
    scanners = ensure_plugins_loaded()
    sast = scanners["sast"].scan(ctx)
    assert len(sast) == 1 and sast[0].module == "sast"
    assert len(normalize_findings(sast + scanners["ai"].scan(ctx))) == 1


def test_broad_regex_and_agent_checks_are_opt_in():
    ctx = context({"app.py": 'DEBUG = True\nimage.generate()\neval("1+1")',
                   "mcp.json": '{"mcpServers":{"local":{"url":"http://localhost:8000"}}}',
                   "SKILL.md": "An example attack says: ignore previous instructions"})
    for module in ("ai", "sast", "agentic"):
        assert ensure_plugins_loaded()[module].scan(ctx) == []
    ctx.config["include_experimental"] = True
    assert ensure_plugins_loaded()["ai"].scan(ctx)


def test_ast_not_repeated_for_every_ai_ruleset():
    findings = ensure_plugins_loaded()["ai"].scan(context({"app.py": "import os\nos.system(input())"}))
    assert len(findings) == 1


def test_secret_evidence_is_redacted():
    secret = "ghp_" + "aB1cD2eF3gH4" * 3
    findings = ensure_plugins_loaded()["ai"].scan(context({"config.py": f'TOKEN = "{secret}"'}))
    assert len(findings) == 1
    assert secret not in json.dumps(findings[0].to_dict())
    assert "redacted" in findings[0].code_snippet


def test_sca_only_queries_exact_versions_in_correct_ecosystem(monkeypatch):
    queries = []
    scanner = SCAScanner()
    monkeypatch.setattr(scanner, "_query_osv", lambda name, version, ecosystem: queries.append((name, version, ecosystem)) or [])
    findings = scanner.scan(context({
        "requirements.txt": "same==1.2.3\nranged>=1.0\nunpinned\nother==2.0,!=2.0.1",
        "web/package.json": '{"dependencies":{"same":"1.2.3","ranged":"^1.0.0"}}',
        "go.mod": "require example.com/module v1.2.3",
    }))
    assert queries == [("same", "1.2.3", "PyPI"), ("same", "1.2.3", "npm"), ("example.com/module", "v1.2.3", "Go")]
    assert all(f.severity == Severity.INFO for f in findings)


def test_lockfiles_supply_exact_transitive_versions_and_sbom(monkeypatch):
    files = {"web/package.json": '{"dependencies":{"foo":"^1.0.0"}}',
             "web/package-lock.json": json.dumps({"packages": {"": {"name": "app"},
                 "node_modules/foo": {"version": "1.2.3"},
                 "node_modules/foo/node_modules/@scope/bar": {"version": "2.0.0"}}}),
             "service/Pipfile.lock": '{"default":{"foo":{"version":"==3.0.0"}}}'}
    scanner, queries = SCAScanner(), []
    monkeypatch.setattr(scanner, "_query_osv", lambda *args: queries.append(args) or [])
    assert scanner.scan(context(files)) == []
    assert queries == [("foo", "1.2.3", "npm"), ("@scope/bar", "2.0.0", "npm"), ("foo", "3.0.0", "PyPI")]
    sbom = scanner.generate_sbom(files)
    assert len(sbom["components"]) == 3
    assert any(component["purl"] == "pkg:npm/%40scope/bar@2.0.0" for component in sbom["components"])


def test_unresolved_sbom_does_not_invent_installed_version():
    sbom = SCAScanner().generate_sbom({"package.json": '{"dependencies":{"foo":"^1.0.0"}}'})
    component = sbom["components"][0]
    assert "version" not in component
    assert component["purl"] == "pkg:npm/foo"
    assert {p["name"]: p["value"] for p in component["properties"]}["theron:version_status"] == "unresolved"


def test_service_failure_is_not_clean_result(monkeypatch):
    scanner = SCAScanner()
    def unavailable(*args):
        raise requests.Timeout()
    monkeypatch.setattr(scanner, "_query_osv", unavailable)
    findings = scanner.scan(context({"requirements.txt": "foo==1.2.3"}))
    assert len(findings) == 1 and findings[0].rule_id == "SCA-LOOKUP-001"
    assert scanner._osv_cache == {}


def test_advisory_has_identity_and_does_not_claim_exploitability(monkeypatch):
    scanner = SCAScanner()
    monkeypatch.setattr(scanner, "_query_osv", lambda *args: [{"id": "TEST-001", "summary": "Test advisory", "database_specific": {"severity": "HIGH"}}])
    finding = scanner.scan(context({"requirements.txt": "foo==1.2.3"}))[0]
    assert finding.rule_id == "SCA-TEST-001"
    assert finding.severity == Severity.HIGH
    assert "exploitability have not been verified" in finding.description


@pytest.mark.parametrize("content", ["{", "[]"])
def test_malformed_manifest_does_not_crash(content):
    findings = SCAScanner().scan(context({"package-lock.json": content}))
    assert any(f.rule_id == "SCA-PARSE-001" for f in findings)


def test_package_presence_is_not_a_bug(monkeypatch):
    scanner = SCAScanner()
    monkeypatch.setattr(scanner, "_query_osv", lambda *args: [])
    assert scanner.scan(context({"requirements.txt": "langchain==1.2.3"})) == []


def test_query_payload_does_not_guess_other_ecosystems(monkeypatch):
    class Response:
        def raise_for_status(self):
            pass
        def json(self):
            return {"vulns": [{"id": "TEST", "withdrawn": "2020-01-01"}, {"id": "CURRENT"}]}
    calls = []
    monkeypatch.setattr(requests, "post", lambda url, **kw: calls.append(kw) or Response())
    assert SCAScanner()._query_osv("foo", "1.2.3", "npm") == [{"id": "CURRENT"}]
    assert len(calls) == 1
    assert calls[0]["json"]["package"]["ecosystem"] == "npm"


def test_pyproject_constraints_are_not_truncated_to_exact_versions():
    scanner = SCAScanner()
    dependencies = scanner._parse_pyproject('[project]\ndependencies = [\n "foo==1.2.3,!=1.2.4",\n "bar>=2.0",\n]', "pyproject.toml")
    assert len(dependencies) == 2
    assert all(scanner._exact_version(version) is None for _, version, _ in dependencies)


def test_registry_recovers_after_clear():
    from scanner.plugins import clear_registry, discover_plugins
    clear_registry()
    assert set(discover_plugins()) == {"ai", "sast", "sca", "agentic"}
    assert set(ensure_plugins_loaded()) == {"ai", "sast", "sca", "agentic"}


def test_go_replacement_is_not_queried_as_original_version():
    scanner = SCAScanner()
    deps = scanner._parse_go_mod("require example.com/pkg v1.0.0\nreplace example.com/pkg => ../fork", "go.mod")
    assert deps == [("example.com/pkg", None, "go.mod")]


def test_inline_pyproject_dependencies():
    import scanner.plugins.sca as sca
    if sca.tomllib is None:
        pytest.skip("Full TOML parser requires Python 3.11+")
    assert SCAScanner()._parse_pyproject('[project]\ndependencies = ["foo==1.2.3"]', "pyproject.toml") == [("foo", "==1.2.3", "pyproject.toml")]


def test_nonsecret_evidence_redacts_nearby_credentials():
    from scanner.utils.helpers import redact_secrets
    secret = "ghp_" + "abcdef123456" * 3
    assert secret not in redact_secrets(f'import os\nTOKEN = "{secret}"\nos.system(input())')


@pytest.mark.parametrize("fmt", ["json", "html", "sarif", "terminal"])
def test_local_cli_quality_and_report_only(tmp_path, monkeypatch, fmt, capsys):
    from scanner.cli import main
    (tmp_path / "app.py").write_text('import os\nos.system(input())', encoding="utf-8")
    (tmp_path / "oversized.py").write_text("#" * 500001, encoding="utf-8")
    output = tmp_path / f"report.{fmt}"
    monkeypatch.setattr("sys.argv", ["ai-sec-scan", "--local", str(tmp_path), "--modules", "sast", "--format", fmt, "--output", str(output)])
    main()
    if fmt == "json":
        data = json.loads(output.read_text())
        assert data["modules_run"] == ["sast"]
        assert {f["rule_id"] for f in data["findings"]} == {"PY-SAST-EXEC-001", "SCAN-COVERAGE-001"}
    elif fmt == "sarif":
        assert len(json.loads(output.read_text())["runs"][0]["results"]) == 2
    elif fmt == "html":
        assert "External input reaches" in output.read_text(encoding="utf-8")
    else:
        assert "Local scan" in capsys.readouterr().out


def test_html_report_cannot_close_script_with_source_text():
    from scanner.models import ScanResult
    from scanner.reporters.html import generate_html_report
    finding = analyze_python("app.py", 'import os\nos.system(input())')[0]
    finding.code_snippet = '</script><script>alert("source")</script>'
    html = generate_html_report(ScanResult(repo_full_name="<img src=x>", branch="<script>", findings=[finding]))
    assert '<script>alert("source")' not in html
    assert "\\u003c/script>" in html
    assert "&lt;img src=x&gt;" in html


def test_github_scan_reports_skipped_files_and_scans_directory_names(monkeypatch):
    from scanner.engine import ScanEngine
    class GitHub:
        def __init__(self, token):
            pass
        def get_repo_info(self, *args):
            return {"default_branch": "main"}
        def get_tree(self, *args):
            return [{"type": "blob", "path": path, "size": size} for path, size in
                    [("src/distribution.py", 40), ("large.py", 500001), ("missing.py", 40)]]
        def get_file_content(self, owner, repo, path, branch):
            if path == "missing.py":
                raise requests.Timeout()
            return "import os\nos.system(input())"
    monkeypatch.setattr("scanner.engine.GitHubClient", GitHub)
    result = ScanEngine("fake-token").scan_repo("owner", "repo", modules=["sast"])
    assert result.files_scanned == 1
    assert len(result.findings) == 3
    assert sum(f.rule_id == "SCAN-COVERAGE-001" for f in result.findings) == 2


@pytest.mark.parametrize("threshold", ["critical", "high", "medium", "low"])
def test_opt_in_fail_thresholds_and_report_only(threshold):
    from scanner.cli import _should_fail
    from scanner.models import ScanResult
    finding = analyze_python("app.py", "exec(input())")[0]
    result = ScanResult(repo_full_name="a/b", branch="main", findings=[finding])
    assert not _should_fail([result], None)
    assert _should_fail([result], threshold)
    finding.status = "existing"
    assert not _should_fail([result], threshold)
