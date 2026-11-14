"""Historical YAML-load tests offline, with command execution replaced by a recorder."""
import hashlib
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import run_obligation_oracles as runner


def main():
    out=ROOT/'docs/evaluation/evidence-2026-11-14'
    cache=ROOT/'.benchmark-cache/validated-oracles/CVE-2017-16618'
    deps=Path(tempfile.mkdtemp(prefix='theron-owlmixin-deps-'))
    lock=json.loads((out/'mcp-oracle-wheels.json').read_text())
    for name,sha in lock.items():
        wheel=Path('/tmp/theron-mcp-oracle-wheels')/name
        assert hashlib.sha256(wheel.read_bytes()).hexdigest()==sha
        with zipfile.ZipFile(wheel) as archive:
            assert all((deps/n).resolve().is_relative_to(deps) for n in archive.namelist())
            archive.extractall(deps)
    legacy=ROOT/'.benchmark-cache/validated-oracles/PyYAML-3.12.tar.gz'
    assert hashlib.sha256(legacy.read_bytes()).hexdigest()==json.loads((out/'owlmixin-legacy-dependency.json').read_text())['sha256']
    with tarfile.open(legacy) as archive:
        for item in archive.getmembers():
            if not item.isfile() or not item.name.startswith('PyYAML-3.12/lib3/yaml/'):continue
            target=deps/item.name.removeprefix('PyYAML-3.12/lib3/')
            assert target.resolve().is_relative_to(deps)
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(archive.extractfile(item).read())
    runner.DEPS=deps
    for r in json.loads((out/'owlmixin-context.json').read_text())['records']:
        assert hashlib.sha256((cache/r['role']/r['path']).read_bytes()).hexdigest()==r['source_sha256']
    probe=runner.run(cache/'fixed','probe',probe=True)
    assert probe['exit_code']==0 and json.loads(probe['output'])==dict(windows_visible=False,home_visible=False,network_result=101)
    records=[]
    for role in ['vulnerable','fixed']:
        for phase in ['security','functional']:
            test='test_yaml_load_vulnerability' if phase=='security' else 'test'
            tests=[f'/oracle/tests/test_util.py::TestLoadYaml::{test}']
            code="""import sys,pathlib,collections,collections.abc,os
sys.dont_write_bytecode=True
sys.path[:0]=['/target','/deps']
collections.Hashable=collections.abc.Hashable
import owlmixin.util,yaml
assert owlmixin.util.__file__.startswith('/target/')
assert yaml.__version__=='3.12'
print('TARGET_MODULE',owlmixin.util.__file__)
calls=[]
def record(command):
    calls.append(command)
    return 0
os.system=record
pathlib.Path('/tmp/pytest.ini').write_text('[pytest]\\n')
import pytest
"""
            code+='result=pytest.main('+repr(['-c','/tmp/pytest.ini','--confcutdir=/tmp','--import-mode=importlib','-p','no:cacheprovider','-q',*tests])+')\n'
            code+='print("BLOCKED_SYSTEM_CALLS",len(calls))\n'
            if phase=='security':code+='assert len(calls)=='+('1' if role=='vulnerable' else '0')+'\n'
            code+='raise SystemExit(result)\n'
            result=runner.run(cache/role,'CVE-2017-16618',oracle=cache/'fixed',python_code=code)
            records.append(dict(role=role,phase=phase,result=result))
            print(role,phase,result['exit_code'],result['output'][-1800:],flush=True)
    (out/'owlmixin-oracle.json').write_text(json.dumps(dict(records=records,probe=probe,dependency_wheel_lock='mcp-oracle-wheels.json',legacy_dependency='owlmixin-legacy-dependency.json',harness_sha256=hashlib.sha256(Path(__file__).read_text().replace('\r\n','\n').encode()).hexdigest(),interpretation='Selected upstream YAML string tests on historical PyYAML 3.12. The os.system target is replaced by a recording stub, so the original test payload launches no command. collections.Hashable is aliased to collections.abc.Hashable for Python 3.13 dependency compatibility; target source remains unchanged. This is an adapted dependency environment, not the original supported interpreter/full suite or proof for modern PyYAML defaults.'),indent=2)+'\n')


if __name__=='__main__':main()
