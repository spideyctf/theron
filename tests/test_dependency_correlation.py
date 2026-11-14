import pytest
from tests.dependency_correlation_fixture import build,edges,CASES


@pytest.mark.parametrize('name,kwargs,expected',CASES,ids=[r[0] for r in CASES])
def test_three_layer_context_matches_declared_controls_without_new_vulnerabilities(name,kwargs,expected):
    _,result=build(**kwargs)
    before=[f.to_dict() for f in result.findings]
    assert bool(edges(result))==expected
    for edge in edges(result):
        assert edge['classification']=='inferred'
        assert edge['evidence'][0]['role']=='import-declaration'
        assert edge['evidence'][1]['role']=='dependency-declaration'
    _,disabled=build(**kwargs,enabled=False)
    assert not edges(disabled) and not disabled.correlation_groups
    assert [f.to_dict() for f in disabled.findings]==before


def test_combined_group_keeps_original_findings_and_ownership_uncertainty():
    _,result=build()
    assert len(result.findings)==2 and len(result.correlation_groups)==1
    group=result.correlation_groups[0]
    assert len(group['finding_fingerprints'])==2
    assert any('distribution ownership' in s for s in group['limitations'])
