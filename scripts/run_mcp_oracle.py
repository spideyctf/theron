"""Selected unmodified upstream MCP tests in a bounded, offline namespace."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import run_obligation_oracles as runner

OUT=ROOT/'docs/evaluation/evidence-2026-11-14'
CACHE=ROOT/'.benchmark-cache/validated-oracles/CVE-2025-53366'


def main():
    deps=Path(tempfile.mkdtemp(prefix='theron-mcp-deps-'));wheels={}
    for wheel in sorted(Path('/tmp/theron-mcp-oracle-wheels').glob('*.whl')):
        wheels[wheel.name]=hashlib.sha256(wheel.read_bytes()).hexdigest()
        with zipfile.ZipFile(wheel) as archive:
            if any(not (deps/name).resolve().is_relative_to(deps) for name in archive.namelist()):raise ValueError('Unsafe wheel path')
            archive.extractall(deps)
    lock=OUT/'mcp-oracle-wheels.json'
    if not wheels:raise ValueError('No dependency wheels')
    if lock.exists() and json.loads(lock.read_text())!=wheels:raise ValueError('Wheel hashes changed')
    lock.write_text(json.dumps(wheels,indent=2)+'\n');runner.DEPS=deps
    # Source is mounted directly; supply version metadata without running its build hooks.
    metadata=deps/'mcp-0.0.dist-info';metadata.mkdir()
    (metadata/'METADATA').write_text('Metadata-Version: 2.1\nName: mcp\nVersion: 0.0\n')
    receipts=json.loads((OUT/'mcp-oracle-context.json').read_text())['records']
    for r in receipts:
        if r.get('error'):
            if not r.get('recovered'):raise ValueError('Source retrieval error')
            continue
        raw=(CACHE/r['role']/r['path']).read_bytes()
        assert hashlib.sha256(raw).hexdigest()==r['source_sha256']
        assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==r['git_blob_sha']
    security=ROOT/'.benchmark-cache/vul4py-pilot/CVE-2025-53366/fixed'
    raw=(security/'tests/issues/test_malformed_input.py').read_bytes()
    expected=next(r['source_sha256'] for r in json.loads((ROOT/'docs/evaluation/mechanisms-2026-11-14/vul4py/source-receipts.json').read_text())['records']
                  if r.get('id')=='CVE-2025-53366' and r.get('role')=='fixed' and r.get('path')=='tests/issues/test_malformed_input.py')
    assert hashlib.sha256(raw).hexdigest()==expected
    probe=runner.run(CACHE/'fixed','probe',probe=True)
    assert probe['exit_code']==0 and json.loads(probe['output'])==dict(windows_visible=False,home_visible=False,network_result=101)
    records=[]
    for role in ['vulnerable','fixed']:
        for phase in ['security','functional']:
            code="""import sys,os,pathlib
sys.dont_write_bytecode=True
sys.path[:0]=['/target/src','/deps']
import mcp.shared.session
assert mcp.shared.session.__file__.startswith('/target/src/')
print('TARGET_MODULE',mcp.shared.session.__file__)
root=pathlib.Path('/tmp/oracle-tests');root.mkdir()
pathlib.Path('/tmp/pytest.ini').write_text('[pytest]\\n')
os.symlink('/oracle/tests/issues/test_malformed_input.py',root/'test_security.py')
os.symlink('/target/tests/server/test_session.py',root/'test_server.py')
os.symlink('/target/tests/shared/test_session.py',root/'test_shared.py')
import pytest
"""
            tests=(['/tmp/oracle-tests/test_security.py'] if phase=='security' else
                   ['/tmp/oracle-tests/test_server.py::test_server_session_initialize',
                    '/tmp/oracle-tests/test_shared.py::test_in_flight_requests_cleared_after_completion'])
            args=['-c','/tmp/pytest.ini','--confcutdir=/tmp/oracle-tests','--import-mode=importlib','-p','no:cacheprovider','-p','anyio.pytest_plugin','-q',*tests]
            code+='raise SystemExit(pytest.main('+repr(args)+'))\n'
            result=runner.run(CACHE/role,'CVE-2025-53366',oracle=security,python_code=code)
            records.append(dict(role=role,phase=phase,oracle_kind='selected_unmodified_upstream_tests',result=result))
            print(role,phase,result['exit_code'],result['output'][-1800:],flush=True)
    write=dict(records=records,probe=probe,dependency_wheels=wheels,security_test_sha256=expected,
        harness_sha256={p.name:hashlib.sha256(p.read_text().replace('\r\n','\n').encode()).hexdigest() for p in [Path(__file__),ROOT/'scripts/run_obligation_oracles.py']},
        interpretation='Selected upstream tests, with isolated pytest configuration, synthetic mcp 0.0 distribution metadata (source imported directly, no build hooks), and explicit AnyIO plugin; not the complete SDK suite or full Vul4Py acceptance. Both asyncio/trio use the pinned wheel environment. No target or install hooks executed on the host.')
    (OUT/'mcp-oracle.json').write_text(json.dumps(write,indent=2)+'\n')


if __name__=='__main__':main()
