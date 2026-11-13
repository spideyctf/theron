"""Original observed and conditional flows for exports/UI; target code stays inert."""
import json
from scanner.models import ScanContext, ScanResult, ProjectProfile
from scanner.rule_loader import RuleLoader
from scanner.plugins.sast import SASTScanner
from scanner.finding_utils import normalize_findings
from scanner.correlation import correlate

CODE='''import os
from flask import request
def convert(record):
    operation=getattr(os,record['operation'])
    return operation(record['argument'])
def route():
    operation=getattr(os,request.args['operation'])
    return operation(request.args['argument'])
'''
ENTRY=dict(file='server.py',function='convert',parameter='record',reason='Caller supplies an untrusted operation record')


def build():
    files={'server.py':CODE,'.vscode/mcp.json':json.dumps({'servers':{'local':{'type':'stdio','command':'python','args':['server.py']}}})}
    context=ScanContext(files,{},ProjectProfile(),RuleLoader(),dict(analysis_entrypoints=[ENTRY]))
    result=ScanResult(repo_full_name='owner/project',branch='main',commit_sha='a'*40,files_scanned=2,
        findings=normalize_findings(SASTScanner().scan(context)),modules_run=['sast'])
    correlate(result,files)
    return result
