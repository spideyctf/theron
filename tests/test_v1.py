import json
from pathlib import Path

from scanner.finding_utils import normalize_findings
from scanner.models import Category, Finding, ProjectProfile, ScanContext, ScanResult, Severity
from scanner.python_analysis import analyze_python
from scanner.reporters.sarif import generate_sarif_report
from scanner.plugins import ensure_plugins_loaded
from scanner.rule_loader import RuleLoader


def _finding(path="src/app.py"):
    return Finding(
        title="Unsafe call", severity=Severity.HIGH, category=Category.SAST,
        module="ai", description="test", file_path=path, line_number=3,
        code_snippet="3: eval(response)", rule_id="TEST-001",
    )


def test_fingerprint_dedup_and_accepted_status():
    finding = _finding()
    first = normalize_findings([finding])[0]
    result = normalize_findings([_finding(), _finding()], {"accepted_fingerprints": [first.fingerprint]})
    assert len(result) == 1
    assert result[0].status == "existing"
    assert result[0].fingerprint == first.fingerprint


def test_excluded_path_is_not_reported():
    assert normalize_findings([_finding("vendor/app.py")], {"exclude": ["vendor/*"]}) == []


def test_python_ast_detects_data_flow_but_not_plain_text():
    risky = '''\
import openai
def run(user_input):
    response = openai.chat.completions.create(messages=[user_input])
    eval(response.choices[0].message.content)
'''
    safe = 'message = "openai.chat.completions.create(user_input)"\n'
    rule_ids = {finding.rule_id for finding in analyze_python("app.py", risky)}
    assert "PY-AI-PROMPT-001" not in rule_ids
    assert "PY-AI-EXEC-001" in rule_ids
    assert analyze_python("safe.py", safe) == []


def test_sarif_exposes_fingerprint_and_status():
    finding = normalize_findings([_finding()])[0]
    sarif = json.loads(generate_sarif_report(ScanResult(repo_full_name="a/b", branch="main", findings=[finding])))
    result = sarif["runs"][0]["results"][0]
    assert result["partialFingerprints"]["theron/v1"] == finding.fingerprint
    assert result["properties"]["status"] == "new"


def test_javascript_rules_are_marked_advisory():
    root = Path(__file__).resolve().parents[1]
    context = ScanContext(
        files={"app.js": "eval(userInput)"}, repo_info={}, project_profile=ProjectProfile(),
        rule_loader=RuleLoader(root / "rules"), config={"include_experimental": True},
    )
    findings = ensure_plugins_loaded()["sast"].scan(context)
    assert findings
    assert all(finding.maturity == "advisory" for finding in findings)
