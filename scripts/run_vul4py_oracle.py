"""One upstream security+functional test pair, confined to the existing namespace runner."""
import base64
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import zipfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import run_obligation_oracles as runner

OUT=ROOT/'docs/evaluation/mechanisms-2026-11-14'
CACHE=ROOT/'.benchmark-cache/vul4py-pilot'
CASE='CVE-2024-34078'


def main():
    deps=Path(tempfile.mkdtemp(prefix='theron-vul4py-deps-'));wheels={}
    for wheel in Path('/tmp/theron-vul4py-wheels').glob('*.whl'):
        wheels[wheel.name]=hashlib.sha256(wheel.read_bytes()).hexdigest()
        with zipfile.ZipFile(wheel) as archive:
            if any(not (deps/p).resolve().is_relative_to(deps) for p in archive.namelist()):raise ValueError('Unsafe wheel path')
            archive.extractall(deps)
    lock=OUT/'vul4py/runtime-dependencies.json'
    if lock.exists() and json.loads(lock.read_text())!=wheels:raise ValueError('Wheel lock changed')
    if not wheels:raise ValueError('No dependency wheels')
    lock.write_text(json.dumps(wheels,indent=2)+'\n')
    runner.DEPS=deps
    rows=json.loads((OUT/'vul4py-runtime-sources.json').read_text())['records']
    for r in rows:
        dest=CACHE/r['id']/r['role']/r['path']
        raw=base64.b64decode(dest.with_name(dest.name+'.b64').read_text())
        assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==r['git_blob_sha']
        dest.write_bytes(raw);r['source_sha256']=hashlib.sha256(raw).hexdigest()
    (OUT/'vul4py-runtime-sources.json').write_text(json.dumps(dict(records=rows),indent=2)+'\n')
    for r in json.loads((OUT/'vul4py/source-receipts.json').read_text())['records']:
        if r['id']!=CASE or r.get('expected_absent') or r.get('error'):continue
        assert hashlib.sha256((CACHE/CASE/r['role']/r['path']).read_bytes()).hexdigest()==r['source_sha256']
    probe=runner.run(CACHE/CASE/'fixed','probe',probe=True)
    assert probe['exit_code']==0 and json.loads(probe['output'])==dict(windows_visible=False,home_visible=False,network_result=101)
    code="""import os,sys,pathlib
sys.dont_write_bytecode=True
root=pathlib.Path('/tmp/package/html_sanitizer');root.mkdir(parents=True)
for name in ['__init__.py','sanitizer.py']:os.symlink('/target/html_sanitizer/'+name,root/name)
os.symlink('/oracle/html_sanitizer/tests.py',root/'tests.py')
sys.path[:0]=['/tmp/package','/deps']
import pytest
raise SystemExit(pytest.main(['-p','no:cacheprovider','-q',str(root/'tests.py')+'::SanitizerTestCase::test_normalize_early',str(root/'tests.py')+'::SanitizerTestCase::test_01_sanitize']))
"""
    results=[]
    for role in ['vulnerable','fixed']:
        result=runner.run(CACHE/CASE/role,CASE,oracle=CACHE/CASE/'fixed',python_code=code)
        results.append(dict(id=CASE,role=role,result=result,oracle_kind='unmodified_upstream_security_and_functional_tests'))
        print(role,result['exit_code'],result['output'][-1500:],flush=True)
    report=dict(records=results,probe=probe,dependency_wheels=wheels,
        source_freeze='6eb6aee2e554c52a5f7519f0f7b6bed016f56f1a',
        harness_hash_format='SHA-256 of UTF-8 text normalized to LF without BOM',
        harness_sha256={p.name:hashlib.sha256(p.read_text(encoding='utf-8-sig').replace('\r\n','\n').encode()).hexdigest()
                        for p in [Path(__file__),ROOT/'scripts/run_obligation_oracles.py']},
        interpretation='Upstream tests selected after the preregistered static run, unchanged. Fixed security test and existing functional test run against both source revisions; no detector tuning. Runtime behavior does not count as static detection.')
    (OUT/'vul4py/runtime.json').write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':main()
