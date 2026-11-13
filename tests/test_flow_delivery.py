"""Collection -> findings -> correlation -> API/downloads -> shared UI fixture."""
import json
from pathlib import Path

import pytest

from tests.flow_delivery_fixture import build,CODE


def test_shared_asgi_archive_report_preserves_classifications():
    _,result=build()
    stored=json.loads((Path(__file__).parent/'fixtures/flow-delivery-report.json').read_text())
    assert stored==result.to_dict()
    from scanner.reporters.html import generate_html_report
    assert (Path(__file__).parent/'fixtures/flow-delivery-report.html').read_text(encoding='utf-8')==generate_html_report(result)
    assert result.summary['vulnerability_findings']==2
    assert result.summary['total_findings']==3
    assert len(result.correlation_groups)==1
    assert len(result.correlation_groups[0]['finding_fingerprints'])==2
    assert any(f.rule_id=='PY-SAST-ARCHIVE-REVIEW-001' and f.severity.value=='INFO' for f in result.findings)


@pytest.mark.parametrize('fmt',['json','html','sarif'])
def test_local_collection_and_all_exports_keep_flows(tmp_path,monkeypatch,fmt):
    from scanner.cli import main
    (tmp_path/'.vscode').mkdir()
    (tmp_path/'.vscode/mcp.json').write_text(json.dumps({'servers':{'local':{'type':'stdio','command':'python','args':['server.py']}}}))
    (tmp_path/'server.py').write_text(CODE)
    output=tmp_path/('report.'+fmt)
    monkeypatch.setattr('sys.argv',['ai-sec-scan','--local',str(tmp_path),'--modules','sast','--format',fmt,'--output',str(output)])
    main()
    text=output.read_text(encoding='utf-8')
    assert 'PY-SAST-ARCHIVE-001' in text and 'PY-SAST-PATH-001' in text
    assert 'PY-SAST-ARCHIVE-REVIEW-001' in text and 'server.py' in text
    if fmt=='json':
        data=json.loads(text)
        assert data['summary']['vulnerability_findings']==2 and len(data['correlation_groups'])==1


def test_api_and_downloads_use_same_backend_generated_evidence(monkeypatch):
    from fastapi.testclient import TestClient
    from scanner.web import create_app
    from tests.test_web import wait_for
    monkeypatch.setenv('GITHUB_TOKEN','original-test-token-not-live')
    class Engine:
        def __init__(self,token,config):
            self.config=config
        def scan_repo(self,*args,**kwargs):
            return build()[1]
    with TestClient(create_app(scanner_factory=Engine)) as client:
        start=client.post('/api/scans',json={'repository':'owner/project','modules':['sast']})
        job=wait_for(client,start.json()['id'],'completed')
        assert job['result']['summary']['vulnerability_findings']==2
        for fmt in ['json','sarif']:
            response=client.get(f"/api/scans/{job['id']}/report?format={fmt}")
            assert response.status_code==200
            assert 'PY-SAST-ARCHIVE-001' in response.text and 'PY-SAST-ARCHIVE-REVIEW-001' in response.text
