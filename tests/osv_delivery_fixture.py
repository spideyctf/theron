"""Original advisory fixture, never a claim about an actual package or CVE."""
from scanner.models import ScanResult
from scanner.plugins.sca import SCAScanner
from scanner.finding_utils import normalize_findings

RECORD={'id':'TEST-OSV-001','aliases':['TEST-ALIAS-001'],'summary':'Original test advisory',
    'database_specific':{'severity':'HIGH','cwe_ids':['CWE-79']},
    'affected':[{'package':{'name':'demo','ecosystem':'PyPI'},'ranges':[{'events':[{'introduced':'0'},{'fixed':'1.1'}]}]}]}


def build():
    scanner=SCAScanner()
    scanner._query_osv=lambda *args:[RECORD]
    fs=normalize_findings(scanner._check_osv([('demo','1.0','requirements.txt')]))
    for f in fs:f.dependency['queried_at']='2026-11-14T00:00:00+00:00'
    return ScanResult(repo_full_name='owner/osv-fixture',branch='main',commit_sha='a'*40,files_scanned=1,modules_run=['sca'],findings=fs)
