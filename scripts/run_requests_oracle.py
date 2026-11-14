"""Requests upstream assertion using an isolated local TLS transport, never badssl.com."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import run_obligation_oracles as runner


def main():
    out=ROOT/'docs/evaluation/evidence-2026-11-14'
    cache=ROOT/'.benchmark-cache/validated-oracles/CVE-2024-35195'
    deps=Path(tempfile.mkdtemp(prefix='theron-requests-deps-'));wheels={}
    for wheel in sorted(Path('/tmp/theron-requests-wheels').glob('*.whl')):
        wheels[wheel.name]=hashlib.sha256(wheel.read_bytes()).hexdigest()
        with zipfile.ZipFile(wheel) as archive:
            assert all((deps/n).resolve().is_relative_to(deps) for n in archive.namelist())
            archive.extractall(deps)
    lock=out/'requests-oracle-wheels.json'
    assert wheels
    if lock.exists():assert json.loads(lock.read_text())==wheels
    lock.write_text(json.dumps(wheels,indent=2)+'\n');runner.DEPS=deps
    for r in json.loads((out/'requests-context.json').read_text())['records']:
        assert hashlib.sha256((cache/r['role']/r['path']).read_bytes()).hexdigest()==r['source_sha256']
    probe=runner.run(cache/'fixed','probe',probe=True)
    assert probe['exit_code']==0 and json.loads(probe['output'])==dict(windows_visible=False,home_visible=False,network_result=101)
    records=[]
    for role in ['vulnerable','fixed']:
        for phase in ['security','functional']:
            tests=(['/oracle/tests/test_requests.py::TestPreparingURLs::test_different_connection_pool_for_tls_settings'] if phase=='security' else
                   ['/target/tests/test_requests.py::TestRequests::test_basic_building',
                    '/target/tests/test_requests.py::TestRequests::test_path_is_not_double_encoded'])
            code="""import sys,pathlib
sys.dont_write_bytecode=True
sys.path[:0]=['/target/src','/target','/deps','/harness']
import requests
assert requests.__file__.startswith('/target/src/')
print('TARGET_MODULE',requests.__file__)
pathlib.Path('/tmp/pytest.ini').write_text('[pytest]\\n')
"""
            if phase=='security':code+='from requests_offline_transport import install\nconnections=install()\n'
            code+='import pytest\nresult=pytest.main('+repr(['-c','/tmp/pytest.ini','--confcutdir=/tmp','--import-mode=importlib','-p','no:cacheprovider','-q',*tests])+')\n'
            if phase=='security':code+='print("OFFLINE_TLS_CONNECTIONS",len(connections))\nassert connections\n'
            code+='raise SystemExit(result)\n'
            result=runner.run(cache/role,'CVE-2024-35195',oracle=cache/'fixed',python_code=code)
            records.append(dict(role=role,phase=phase,result=result))
            print(role,phase,result['exit_code'],result['output'][-2200:],flush=True)
    paths=[Path(__file__),ROOT/'scripts/requests_offline_transport.py',ROOT/'scripts/run_obligation_oracles.py']
    (out/'requests-oracle.json').write_text(json.dumps(dict(records=records,probe=probe,dependency_wheels=wheels,harness_sha256={p.name:hashlib.sha256(p.read_text().replace('\r\n','\n').encode()).hexdigest() for p in paths},interpretation='Upstream test body unchanged, but transport is author-adapted: urllib3 socket creation returns an in-namespace socketpair connected to a real TLS peer with an ephemeral untrusted certificate and HTTP 421 response. DNS and TCP/external networking are not exercised. No badssl.com connection or host target execution. Not the original upstream integration environment, full suite, or complete TLS correctness proof.'),indent=2)+'\n')


if __name__=='__main__':main()
