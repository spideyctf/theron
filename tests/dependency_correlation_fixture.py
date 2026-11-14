"""Original three-layer controls: configuration, import spelling, exact OSV declaration."""
from tests.test_correlation import sample
from tests.osv_delivery_fixture import build as advisory
from scanner.finding_utils import normalize_findings
from scanner.correlation import correlate


def build(code='import demo\nexec(input())',extra=None,enabled=True,package='demo',manifest='requirements.txt'):
    files,result=sample(code=code,extra={manifest:package+'==1.0',**(extra or {})})
    finding=advisory().findings[0]
    finding.file_path=manifest;finding.dependency['manifest']=manifest;finding.dependency['package']=package
    result.findings=normalize_findings(result.findings+[finding])
    correlate(result,files,enabled=enabled)
    return files,result


def edges(result):
    return [e for g in result.correlation_groups for e in g['relationships'] if e['kind']=='entrypoint_import_matches_dependency_declaration']


CASES=[
 ('direct-import',dict(code='import demo\nexec(input())'),True),
 ('aliased-import',dict(code='import demo as client\nexec(input())'),True),
 ('from-import',dict(code='from demo.client import connect\nexec(input())'),True),
 ('dependency-only',dict(code='import demo\nprint("ok")'),True),
 ('unrelated-import',dict(code='import unrelated\nexec(input())'),False),
 ('comment-only',dict(code='# import demo\nexec(input())'),False),
 ('local-shadow',dict(extra={'demo.py':'pass'}),False),
 ('namespace-shadow',dict(extra={'demo/local.py':'pass'}),False),
 ('conditional-import',dict(code='if flag:\n import demo\nexec(input())'),False),
 ('stdlib-collision',dict(code='import json\nexec(input())',package='json'),False),
 ('namespace-mismatch',dict(code='import demo_pkg\nexec(input())',package='demo-pkg'),False),
 ('nonancestor-manifest',dict(manifest='other/requirements.txt'),False),
 ('nearer-manifest',dict(extra={'.vscode/mcp.json':'{"servers":{"local":{"type":"stdio","command":"python","args":["nested/server.py"]}}}',
     'nested/server.py':'import demo\nexec(input())','nested/pyproject.toml':'[project]\nname="nested"\nversion="1.0"'}),False),
]
