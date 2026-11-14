"""Selected upstream offline bundle-validation tests against both source revisions."""
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
    cache=ROOT/'.benchmark-cache/validated-oracles/CVE-2024-55655'
    deps=Path(tempfile.mkdtemp(prefix='theron-sigstore-deps-'));wheels={}
    for wheel in sorted(Path('/tmp/theron-sigstore-wheels').glob('*.whl')):
        wheels[wheel.name]=hashlib.sha256(wheel.read_bytes()).hexdigest()
        with zipfile.ZipFile(wheel) as archive:
            assert all((deps/n).resolve().is_relative_to(deps) for n in archive.namelist())
            archive.extractall(deps)
    lock=out/'sigstore-oracle-wheels.json'
    assert wheels
    if lock.exists():assert json.loads(lock.read_text())==wheels
    lock.write_text(json.dumps(wheels,indent=2)+'\n');runner.DEPS=deps
    for r in json.loads((out/'sigstore-context.json').read_text())['records']:
        assert hashlib.sha256((cache/r['role']/r['path']).read_bytes()).hexdigest()==r['source_sha256']
    probe=runner.run(cache/'fixed','probe',probe=True)
    assert probe['exit_code']==0 and json.loads(probe['output'])==dict(windows_visible=False,home_visible=False,network_result=101)
    records=[]
    for role in ['vulnerable','fixed']:
        for phase in ['security','functional']:
            test='test_bundle_missing_signed_time' if phase=='security' else 'test_bundle_roundtrip'
            tests=[f'/oracle/test/unit/test_models.py::TestBundle::{test}']
            code="""import sys,pathlib
sys.dont_write_bytecode=True
sys.path[:0]=['/target','/deps']
import sigstore.models
assert sigstore.models.__file__.startswith('/target/')
print('TARGET_MODULE',sigstore.models.__file__)
pathlib.Path('/tmp/pytest.ini').write_text('[pytest]\\n')
import pytest
"""
            code+='raise SystemExit(pytest.main('+repr(['-c','/tmp/pytest.ini','--confcutdir=/oracle/test','--import-mode=importlib','--skip-online','--skip-staging','-p','no:cacheprovider','-q',*tests])+'))\n'
            result=runner.run(cache/role,'CVE-2024-55655',oracle=cache/'fixed',python_code=code)
            records.append(dict(role=role,phase=phase,result=result))
            print(role,phase,result['exit_code'],result['output'][-2000:],flush=True)
    (out/'sigstore-oracle.json').write_text(json.dumps(dict(records=records,probe=probe,dependency_wheels=wheels,harness_sha256=hashlib.sha256(Path(__file__).read_text().replace('\r\n','\n').encode()).hexdigest(),interpretation='Selected unmodified upstream model-validation and round-trip tests with fixed upstream fixtures/conftests on both pinned source revisions. Explicit target import origin, pinned dependency wheels and offline/staging skips. No signing identities or network services; not full certificate-chain verification, a signing deployment, or complete upstream suite acceptance.'),indent=2)+'\n')


if __name__=='__main__':main()
