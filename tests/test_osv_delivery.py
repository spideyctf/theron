import json
from pathlib import Path
import pytest
from tests.osv_delivery_fixture import build,RECORD


def test_shared_fixture_and_exports_preserve_dependency_evidence():
    from scanner.reporters.html import generate_html_report
    from scanner.reporters.sarif import generate_sarif_report
    result=build()
    fixtures=Path(__file__).parent/'fixtures'
    assert json.loads((fixtures/'osv-report.json').read_text())==result.to_dict()
    assert (fixtures/'osv-report.html').read_text(encoding='utf-8')==generate_html_report(result)
    sarif=json.loads(generate_sarif_report(result))
    assert sarif['runs'][0]['results'][0]['properties']['dependency']==result.findings[0].dependency


@pytest.mark.parametrize('fmt',['json','sarif','html'])
def test_cli_advisory_pipeline_reaches_every_export(tmp_path,monkeypatch,fmt):
    from scanner.cli import main
    from scanner.plugins.sca import SCAScanner
    monkeypatch.setattr(SCAScanner,'_query_osv',lambda *args:[RECORD])
    (tmp_path/'requirements.txt').write_text('demo==1.0')
    output=tmp_path/('report.'+fmt)
    monkeypatch.setattr('sys.argv',['ai-sec-scan','--local',str(tmp_path),'--modules','sca','--format',fmt,'--output',str(output)])
    main();text=output.read_text(encoding='utf-8')
    assert 'TEST-OSV-001' in text and 'reachability unverified' in text and '1.1' in text


@pytest.mark.parametrize('fmt',['json','sarif'])
def test_api_downloads_preserve_the_same_package_evidence(monkeypatch,fmt):
    from fastapi.testclient import TestClient
    from scanner.web import create_app
    from tests.test_web import wait_for
    class Engine:
        def __init__(self,*args,**kwargs):pass
        def scan_repo(self,*args,**kwargs):return build()
    monkeypatch.setenv('GITHUB_TOKEN','inert-test-value')
    with TestClient(create_app(scanner_factory=Engine)) as client:
        job=wait_for(client,client.post('/api/scans',json={'repository':'owner/osv-fixture','modules':['sca']}).json()['id'],'completed')
        assert job['result']==build().to_dict()
        response=client.get(f"/api/scans/{job['id']}/report?format={fmt}")
        assert response.status_code==200 and 'fixed_versions' in response.text and 'reachability unverified' in response.text
