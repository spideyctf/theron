"""Selected upstream path-boundary and functional tests in an offline namespace."""
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
    cache=ROOT/'.benchmark-cache/validated-oracles/CVE-2023-32309'
    deps=Path(tempfile.mkdtemp(prefix='theron-pymdown-deps-'));wheels={}
    for wheel in sorted(Path('/tmp/theron-pymdown-wheels').glob('*.whl')):
        wheels[wheel.name]=hashlib.sha256(wheel.read_bytes()).hexdigest()
        with zipfile.ZipFile(wheel) as archive:
            assert all((deps/n).resolve().is_relative_to(deps) for n in archive.namelist())
            archive.extractall(deps)
    lock=out/'pymdown-oracle-wheels.json'
    assert wheels
    if lock.exists():assert json.loads(lock.read_text())==wheels
    lock.write_text(json.dumps(wheels,indent=2)+'\n');runner.DEPS=deps
    for r in json.loads((out/'pymdown-context.json').read_text())['records']:
        assert hashlib.sha256((cache/r['role']/r['path']).read_bytes()).hexdigest()==r['source_sha256']
    probe=runner.run(cache/'fixed','probe',probe=True)
    assert probe['exit_code']==0 and json.loads(probe['output'])==dict(windows_visible=False,home_visible=False,network_result=101)
    records=[]
    for role in ['vulnerable','fixed']:
        for phase in ['security','functional']:
            tests=(['/tmp/package/tests/test_extensions/test_snippets.py::TestSnippetsNested::test_restricted'] if phase=='security' else
                   ['/tmp/package/tests/test_extensions/test_snippets.py::TestSnippetsFile::test_user'])
            code="""import sys,pathlib,shutil,os
sys.dont_write_bytecode=True
root=pathlib.Path('/tmp/package');root.mkdir()
os.symlink('/target/pymdownx',root/'pymdownx')
shutil.copytree('/oracle/tests',root/'tests')
os.chdir(root)
sys.path[:0]=[str(root),'/deps']
pathlib.Path('/tmp/pytest.ini').write_text('[pytest]\\n')
import pytest
"""
            code+='raise SystemExit(pytest.main('+repr(['-c','/tmp/pytest.ini','-p','no:cacheprovider','-q',*tests])+'))\n'
            result=runner.run(cache/role,'CVE-2023-32309',oracle=cache/'fixed',python_code=code)
            records.append(dict(role=role,phase=phase,result=result))
            print(role,phase,result['exit_code'],result['output'][-2000:],flush=True)
    (out/'pymdown-oracle.json').write_text(json.dumps(dict(records=records,probe=probe,dependency_wheels=wheels,harness_sha256=hashlib.sha256(Path(__file__).read_text().replace('\r\n','\n').encode()).hexdigest(),interpretation='Two selected unmodified upstream tests with fixed-revision test fixtures on both source revisions. Functional control reads an allowed snippet file. The initial attempt used a new-option control unsupported by vulnerable code and is retained separately. No target build hooks; source readonly, test fixtures copied into ephemeral storage. Not the complete extension suite or full Vul4Py acceptance.'),indent=2)+'\n')


if __name__=='__main__':main()
