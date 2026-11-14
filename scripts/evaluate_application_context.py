"""Replay archived advisory candidates with source observations and an explicit binding."""
import base64
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess

from scanner.correlation import correlate
from scanner.finding_utils import normalize_findings, partition_findings
from scanner.models import ProjectProfile, ScanContext, ScanResult
from scanner.plugins.sast import SASTScanner
from scanner.plugins.sca import SCAScanner
from scanner.rule_loader import RuleLoader

ROOT=Path(__file__).resolve().parents[1]
PREVIOUS=ROOT/'docs/evaluation/lock-entrypoints-development-2026-11-15'
OUT=ROOT/'docs/evaluation/application-context-2026-11-15'


def main():
    receipts=json.loads((PREVIOUS/'source-receipts.json').read_text())
    files={}
    for receipt in receipts['records']:
        raw=base64.b64decode((ROOT/'.benchmark-cache/real-correlation-2026-11-15/blobs'/(receipt['git_blob_sha']+'.b64')).read_text())
        assert hashlib.sha256(raw).hexdigest()==receipt['sha256']
        assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==receipt['git_blob_sha']
        files[receipt['path']]=raw.decode('utf-8-sig')
    archive=json.loads((PREVIOUS/'osv-records.json').read_text())
    lookup={(r['package'],r['version'],r['ecosystem']):r['records'] for r in archive if r['status']=='complete'}
    scanner=SCAScanner()
    scanner._query_osv=lambda name,version,ecosystem:lookup[(name,version,ecosystem)]
    context=ScanContext(files,{},ProjectProfile(),RuleLoader(),{})
    findings=normalize_findings(SASTScanner().scan(context)+scanner.scan(context))
    result=ScanResult(repo_full_name=receipts['repository'],branch=receipts['revision'],commit_sha=receipts['revision'],
                      files_scanned=len(files),modules_run=['sast','sca'],findings=findings)
    partition_findings(result)
    all_findings=result.findings+result.context_findings
    original=json.loads((PREVIOUS/'results.json').read_text())['result']
    expected={f['fingerprint'] for f in original['findings']+original['context_findings'] if f.get('dependency')}
    assert {f.fingerprint for f in all_findings if f.dependency}==expected
    config='mcp-config.json';target='word_mcp_server.py'
    binding=dict(config_file=config,pointer='/mcpServers/word-document-server',entrypoint=target,kind='absolute-python',
        config_sha256=hashlib.sha256(files[config].encode()).hexdigest(),entrypoint_sha256=hashlib.sha256(files[target].encode()).hexdigest(),
        reason='Assistant source-review claim: map the declared absolute word_mcp_server.py to the same-named collected project entry script. Original machine path, installation and runtime identity remain unverified.')
    before=[f.to_dict() for f in all_findings]
    correlate(result,files,bindings=[binding])
    assert before==[f.to_dict() for f in result.findings+result.context_findings]
    reviews=[dict(fingerprint=f.fingerprint,package=f.dependency['package'],advisory_ids=f.dependency['advisory_ids'],
                  version=f.dependency['version'],review=f.dependency['application_review']) for f in all_findings if f.dependency]
    assert len(reviews)==26 and all(not r['review']['vulnerability_confirmed'] for r in reviews)
    value=dict(implementation_revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        development_exposed=True,independent_labels=False,runtime_tests_performed=False,
        archived_osv_sha256=hashlib.sha256((PREVIOUS/'osv-records.json').read_bytes()).hexdigest(),
        advisory_candidates_preserved=True,correlation_preserves_findings=True,
        statuses=dict(Counter(r['review']['status'] for r in reviews)),reviews=reviews,binding=binding,
        resolutions=result.correlation_resolutions,groups=result.correlation_groups)
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/'results.json').write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')
    print('Reviewed',len(reviews),'candidates:',value['statuses'])
    print('Declaration status:',result.correlation_resolutions[0]['status'],'groups:',len(result.correlation_groups))


if __name__=='__main__':main()
