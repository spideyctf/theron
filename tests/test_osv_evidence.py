import pytest
import requests
from scanner.plugins.sca import SCAScanner


def reply(payload):
    class Response:
        def raise_for_status(self):pass
        def json(self):return payload
    return Response()


def test_all_pages_are_read_and_duplicate_ids_are_not_duplicate_findings(monkeypatch):
    calls=[]
    pages=iter([{'vulns':[{'id':'A'}],'next_page_token':'next'}, {'vulns':[{'id':'A'},{'id':'B'}]}])
    def post(url,json,timeout):
        calls.append((url,json,timeout));return reply(next(pages))
    monkeypatch.setattr(requests,'post',post)
    assert SCAScanner()._query_osv('demo','1.0','PyPI')==[{'id':'A'},{'id':'B'}]
    assert 'page_token' not in calls[0][1] and calls[1][1]['page_token']=='next'
    assert all(url=='https://api.osv.dev/v1/query' for url,_,_ in calls)


@pytest.mark.parametrize('second',[
 {'vulns':[],'next_page_token':'next'}, {'vulns':[],'next_page_token':12},
 {'vulns':[{'id':'bad','affected':[{'ranges':['bad']}]}]},
 {'vulns':[{'id':'bad','aliases':'CVE-X'}]},
])
def test_incomplete_or_malformed_later_pages_are_never_cached_as_complete(monkeypatch,second):
    pages=iter([{'vulns':[{'id':'A'}],'next_page_token':'next'},second])
    monkeypatch.setattr(requests,'post',lambda *a,**k:reply(next(pages)))
    scanner=SCAScanner()
    fs=scanner._check_osv([('demo','1.0','requirements.txt')])
    assert len(fs)==1 and fs[0].rule_id=='SCA-LOOKUP-001' and scanner._osv_cache=={}


def test_fixed_versions_and_cwes_keep_package_identity_and_uncertainty(monkeypatch):
    record={'id':'GHSA-example','aliases':['CVE-example'],'database_specific':{'severity':'HIGH','cwe_ids':['CWE-79']},
        'affected':[{'package':{'name':'html_sanitizer','ecosystem':'PyPI'},'ranges':[{'events':[{'introduced':'0'},{'fixed':'2.4.2'}]}]},
                    {'package':{'name':'other','ecosystem':'PyPI'},'ranges':[{'events':[{'fixed':'99.0'}]}]}]}
    scanner=SCAScanner();monkeypatch.setattr(scanner,'_query_osv',lambda *a:[record])
    f=scanner._check_osv([('html-sanitizer','2.3.0','requirements.txt')])[0]
    assert f.cwe=='CWE-79' and f.dependency['fixed_versions']==['2.4.2']
    assert 'reachability unverified' in f.dependency['matching']
    assert f.to_dict()['dependency']['advisory_ids']==['CVE-example','GHSA-example']


def test_page_limit_is_a_coverage_failure(monkeypatch):
    scanner=SCAScanner();scanner.MAX_OSV_PAGES=1
    monkeypatch.setattr(requests,'post',lambda *a,**k:reply({'next_page_token':'more'}))
    fs=scanner._check_osv([('demo','1.0','requirements.txt')])
    assert fs[0].rule_id=='SCA-LOOKUP-001'
