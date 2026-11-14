"""Run pinned sqlparse upstream regressions offline; no security-impact inference."""
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
    cache=ROOT/'.benchmark-cache/validated-oracles/CVE-2023-30608'
    deps=Path(tempfile.mkdtemp(prefix='theron-sqlparse-deps-'))
    lock=json.loads((out/'mcp-oracle-wheels.json').read_text())
    for name,sha in lock.items():
        wheel=Path('/tmp/theron-mcp-oracle-wheels')/name
        assert hashlib.sha256(wheel.read_bytes()).hexdigest()==sha
        with zipfile.ZipFile(wheel) as archive:
            assert all((deps/n).resolve().is_relative_to(deps) for n in archive.namelist())
            archive.extractall(deps)
    runner.DEPS=deps
    for r in json.loads((out/'sqlparse-context.json').read_text())['records']:
        assert hashlib.sha256((cache/r['role']/r['path']).read_bytes()).hexdigest()==r['source_sha256']
    probe=runner.run(cache/'fixed','probe',probe=True)
    assert probe['exit_code']==0 and json.loads(probe['output'])==dict(windows_visible=False,home_visible=False,network_result=101)
    records=[]
    for role in ['vulnerable','fixed']:
        for phase in ['patch_regression','functional_suite']:
            tests=['/oracle/tests/test_split.py::test_split_backslash'] if phase=='patch_regression' else ['/target/tests']
            code="import sys,pathlib;sys.dont_write_bytecode=True;sys.path[:0]=['/target','/deps'];pathlib.Path('/tmp/pytest.ini').write_text('[pytest]\\n');import pytest;raise SystemExit(pytest.main("+repr(['-c','/tmp/pytest.ini','-p','no:cacheprovider','-q',*tests])+"))"
            result=runner.run(cache/role,'CVE-2023-30608',oracle=cache/'fixed',python_code=code)
            records.append(dict(role=role,phase=phase,result=result))
            print(role,phase,result['exit_code'],result['output'][-2500:],flush=True)
    (out/'sqlparse-oracle.json').write_text(json.dumps(dict(records=records,probe=probe,dependency_wheel_lock='mcp-oracle-wheels.json',harness_sha256=hashlib.sha256(Path(__file__).read_text().replace('\r\n','\n').encode()).hexdigest(),interpretation='Unmodified upstream patch regression plus original per-revision functional suite. This patch test is not a resource-exhaustion security oracle; passing cannot establish ReDoS safety. No target setup hooks run. Configuration excludes upstream packaging options.'),indent=2)+'\n')


if __name__=='__main__':main()
