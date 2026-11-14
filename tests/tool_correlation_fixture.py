"""Original controls; TEST-OSV identifiers and declared metadata are fictional."""
from copy import deepcopy
import json

from scanner.correlation import correlate
from scanner.finding_utils import normalize_findings,partition_findings
from scanner.models import ScanResult
from scanner.plugins.sca import SCAScanner
from scanner.python_analysis import analyze_python
from tests.osv_delivery_fixture import RECORD

CODE='''from mcp.server.fastmcp import FastMCP
from helpers import parse
app=FastMCP("demo")
@app.tool(name="inspect_text")
def inspect_text(text):
    exec(input())
    return parse(text)
'''
HELPER='''import yaml as parser
def parse(text):
    return parser.load(text)
'''


def build(code=CODE,helper=HELPER,extra=None,metadata=True,enabled=True,package='PyYAML',version='1.0.0'):
    files={'.vscode/mcp.json':json.dumps({'servers':{'local':{'type':'stdio','command':'python','args':['server.py']}}}),
           'server.py':code,'helpers.py':helper,'requirements.txt':f'{package}=={version}\n'}
    if metadata:
        files.update({'evidence/PyYAML-1.0.0.dist-info/METADATA':f'Metadata-Version: 2.1\nName: {package}\nVersion: {version}\n',
                      'evidence/PyYAML-1.0.0.dist-info/RECORD':'yaml/__init__.py,,\nyaml/parser.py,,\n'})
    files.update(extra or {})
    record=deepcopy(RECORD);record['affected'][0]['package']['name']=package
    scanner=SCAScanner();scanner._query_osv=lambda *args:[record]
    findings=scanner._check_osv([(package,version,'requirements.txt')])
    for f in findings:f.dependency['queried_at']='2026-11-15T00:00:00+00:00'
    findings += [f for path,text in files.items() if path.endswith('.py') for f in analyze_python(path,text,module='sast')]
    result=ScanResult(repo_full_name='owner/tool-evidence-fixture',branch='main',commit_sha='b'*40,
        findings=normalize_findings(findings),files_scanned=len(files),modules_run=['sast','sca'])
    partition_findings(result);correlate(result,files,enabled=enabled)
    return files,result


def groups(result):return [g for g in result.correlation_groups if g['id'].startswith('mcp-tool-')]


def edges(result,kind):return [e for g in groups(result) for e in g['relationships'] if e['kind']==kind]


CASES=[
 ('helper-metadata',{},True),
 ('direct-import-alias',dict(code=CODE.replace('from helpers import parse','from yaml import load as parse')),True),
 ('async-handler',dict(code=CODE.replace('def inspect_text','async def inspect_text')),True),
 ('same-name-only',dict(helper=HELPER.replace('yaml','demo'),package='demo',metadata=False),True),
 ('different-name-without-metadata',dict(metadata=False),False),
 ('unregistered-handler',dict(code=CODE.replace('@app.tool(name="inspect_text")\n','')),False),
 ('unused-import',dict(helper=HELPER.replace('return parser.load(text)','return text')),False),
 ('local-shadow',dict(extra={'yaml.py':'pass'}),False),
 ('namespace-shadow',dict(extra={'yaml/extra.py':'pass'}),False),
 ('wrong-version',dict(extra={'evidence/PyYAML-1.0.0.dist-info/METADATA':'Name: PyYAML\nVersion: 2.0\n'}),False),
 ('ambiguous-owner',dict(extra={'other/other-1.dist-info/METADATA':'Name: other\nVersion: 1\n','other/other-1.dist-info/RECORD':'yaml/__init__.py,,\n'}),False),
 ('stdlib',dict(helper=HELPER.replace('yaml','json'),package='json',metadata=False),False),
 ('replaced-framework',dict(code=CODE.replace('app=FastMCP("demo")','app=custom()')),False),
 ('wrapped-helper',dict(helper=HELPER.replace('def parse','@custom\ndef parse')),False),
 ('replaced-api',dict(helper=HELPER.replace('def parse','parser.load=custom\ndef parse')),False),
 ('malformed-record',dict(extra={'evidence/PyYAML-1.0.0.dist-info/RECORD':'../yaml/__init__.py,,\n'}),False),
]
