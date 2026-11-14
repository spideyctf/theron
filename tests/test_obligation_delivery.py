import json
from pathlib import Path
import pytest
from tests.obligation_delivery_fixture import build


def test_backend_shared_fixture_preserves_all_required_conditions():
    result=build()
    stored=json.loads((Path(__file__).parent/'fixtures/obligation-report.json').read_text())
    assert stored==result.to_dict()
    assert {f.obligation['domain'] for f in result.findings if f.obligation}=={'authorization','crypto','protocol'}


@pytest.mark.parametrize('fmt',['json','sarif'])
def test_api_download_preserves_required_condition_and_assumptions(monkeypatch,fmt):
    from fastapi.testclient import TestClient
    from scanner.web import create_app
    from tests.test_web import wait_for
    class Engine:
        def __init__(self,token,config):pass
        def scan_repo(self,*args,**kwargs):return build()
    monkeypatch.setenv('GITHUB_TOKEN','inert-test-value')
    with TestClient(create_app(scanner_factory=Engine)) as client:
        job=wait_for(client,client.post('/api/scans',json={'repository':'owner/obligations','modules':['sast']}).json()['id'],'completed')
        assert job['result']==build().to_dict()
        response=client.get(f"/api/scans/{job['id']}/report?format={fmt}")
        assert response.status_code==200
        for finding in build().findings:
            if finding.obligation:
                assert finding.rule_id in response.text
                assert finding.obligation['required'] in response.text


def test_html_evidence_is_generated_and_escaped():
    from scanner.reporters.html import generate_html_report
    result=build()
    assert (Path(__file__).parent/'fixtures/obligation-report.html').read_text(encoding='utf-8')==generate_html_report(result)
    result.findings[0].obligation['required']='<img src=x onerror=alert(1)>'
    html=generate_html_report(result)
    assert '<img src=x onerror=alert(1)>' not in html
