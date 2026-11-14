"""Selected network utility regressions; new API failures are not security proofs."""
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
    cache=ROOT/'.benchmark-cache/validated-oracles/CVE-2024-32977'
    deps=Path(tempfile.mkdtemp(prefix='theron-octoprint-deps-'));wheels={}
    for wheel in sorted(Path('/tmp/theron-octoprint-wheels').glob('*.whl')):
        if wheel.name.startswith('netaddr-') and not wheel.name.startswith('netaddr-0.8.0-'):continue
        wheels[wheel.name]=hashlib.sha256(wheel.read_bytes()).hexdigest()
        with zipfile.ZipFile(wheel) as archive:
            assert all((deps/n).resolve().is_relative_to(deps) for n in archive.namelist())
            archive.extractall(deps)
    assert any(name.startswith('netaddr-0.8.0-') for name in wheels)
    lock=out/'octoprint-oracle-compatible-wheels.json'
    assert wheels
    if lock.exists():assert json.loads(lock.read_text())==wheels
    lock.write_text(json.dumps(wheels,indent=2)+'\n');runner.DEPS=deps
    for r in json.loads((out/'octoprint-context.json').read_text())['records']:
        assert hashlib.sha256((cache/r['role']/r['path']).read_bytes()).hexdigest()==r['source_sha256']
    probe=runner.run(cache/'fixed','probe',probe=True)
    assert probe['exit_code']==0 and json.loads(probe['output'])==dict(windows_visible=False,home_visible=False,network_result=101)
    records=[]
    for role in ['vulnerable','fixed']:
        for phase in ['new_api_regression','functional']:
            tests=(['/oracle/tests/util/test_net.py::test_get_http_client_ip'] if phase=='new_api_regression' else
                   ['/oracle/tests/util/test_net.py::test_strip_interface_tag','/oracle/tests/util/test_net.py::test_is_lan_address'])
            code="""import sys,pathlib
sys.dont_write_bytecode=True
sys.path[:0]=['/target/src','/deps']
import octoprint.util.net
assert octoprint.util.net.__file__.startswith('/target/src/')
print('TARGET_MODULE',octoprint.util.net.__file__)
pathlib.Path('/tmp/pytest.ini').write_text('[pytest]\\n')
import pytest
"""
            code+='raise SystemExit(pytest.main('+repr(['-c','/tmp/pytest.ini','--confcutdir=/tmp','--import-mode=importlib','--tb=short','-p','no:cacheprovider','-q',*tests])+'))\n'
            result=runner.run(cache/role,'CVE-2024-32977',oracle=cache/'fixed',python_code=code)
            records.append(dict(role=role,phase=phase,result=result))
            print(role,phase,result['exit_code'],result['output'][-2200:],flush=True)
    (out/'octoprint-oracle.json').write_text(json.dumps(dict(records=records,probe=probe,dependency_wheels=wheels,harness_sha256=hashlib.sha256(Path(__file__).read_text().replace('\r\n','\n').encode()).hexdigest(),interpretation='Selected unmodified fixed-revision upstream network-utility tests on both source revisions. netifaces2 supplies the netifaces interface; LAN interfaces are mocked by upstream tests. get_http_client_ip is a new API absent in vulnerable source: resulting AttributeError is an API mismatch, not a security reproduction. This does not verify deployed reverse-proxy trust, login behavior, or the full OctoPrint suite.'),indent=2)+'\n')


if __name__=='__main__':main()
