"""Selected upstream interpreter capability tests in the bounded offline runner."""
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
    cache=ROOT/'.benchmark-cache/validated-oracles/CVE-2025-5120'
    deps=Path(tempfile.mkdtemp(prefix='theron-smolagents-deps-'));wheels={}
    for wheel in sorted(Path('/tmp/theron-smolagents-wheels').glob('*.whl')):
        wheels[wheel.name]=hashlib.sha256(wheel.read_bytes()).hexdigest()
        with zipfile.ZipFile(wheel) as archive:
            assert all((deps/n).resolve().is_relative_to(deps) for n in archive.namelist())
            archive.extractall(deps)
    lock=out/'smolagents-oracle-wheels.json'
    assert wheels
    if lock.exists():assert json.loads(lock.read_text())==wheels
    lock.write_text(json.dumps(wheels,indent=2)+'\n');runner.DEPS=deps
    for r in json.loads((out/'smolagents-context.json').read_text())['records']:
        assert hashlib.sha256((cache/r['role']/r['path']).read_bytes()).hexdigest()==r['source_sha256']
    probe=runner.run(cache/'fixed','probe',probe=True)
    assert probe['exit_code']==0 and json.loads(probe['output'])==dict(windows_visible=False,home_visible=False,network_result=101)
    records=[]
    for role in ['vulnerable','fixed']:
        for phase in ['security','functional']:
            tests=(['/oracle/tests/test_local_python_executor.py::TestLocalPythonExecutorSecurity::test_vulnerability_via_submodules_through_indirect_attribute_access'] if phase=='security' else
                   ['/target/tests/test_local_python_executor.py::TestEvaluatePythonCode::test_evaluate_assign'])
            code="""import sys,pathlib,os
sys.dont_write_bytecode=True
os.environ['OPENBLAS_NUM_THREADS']='1'
os.environ['OMP_NUM_THREADS']='1'
os.environ['HF_HUB_OFFLINE']='1'
sys.path[:0]=['/target/src','/target','/deps']
import smolagents.local_python_executor
assert smolagents.local_python_executor.__file__.startswith('/target/src/')
print('TARGET_MODULE',smolagents.local_python_executor.__file__)
pathlib.Path('/tmp/pytest.ini').write_text('[pytest]\\n')
import pytest
"""
            code+='raise SystemExit(pytest.main('+repr(['-c','/tmp/pytest.ini','--confcutdir=/tmp','--import-mode=importlib','-p','no:cacheprovider','-q',*tests])+'))\n'
            result=runner.run(cache/role,'CVE-2025-5120',oracle=cache/'fixed',python_code=code)
            records.append(dict(role=role,phase=phase,result=result))
            print(role,phase,result['exit_code'],result['output'][-2200:],flush=True)
    (out/'smolagents-oracle.json').write_text(json.dumps(dict(records=records,probe=probe,dependency_wheels=wheels,harness_sha256=hashlib.sha256(Path(__file__).read_text().replace('\r\n','\n').encode()).hexdigest(),interpretation='Selected unmodified upstream tests with isolated pytest configuration; three indirect module-access cases and a legitimate assignment control. No shell payload, network, model calls, or installation hooks executed on host. Shared WSL kernel, bounded per-process resources; not the full interpreter suite or comprehensive sandbox proof.'),indent=2)+'\n')


if __name__=='__main__':main()
