"""Bounded author-derived resource regression on the original SQL lexer."""
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
    out=ROOT/'docs/evaluation/evidence-2026-11-14';cache=ROOT/'.benchmark-cache/validated-oracles/CVE-2023-30608'
    deps=Path(tempfile.mkdtemp(prefix='theron-sql-resource-deps-'))
    for name,sha in json.loads((out/'mcp-oracle-wheels.json').read_text()).items():
        wheel=Path('/tmp/theron-mcp-oracle-wheels')/name
        assert hashlib.sha256(wheel.read_bytes()).hexdigest()==sha
        with zipfile.ZipFile(wheel) as archive:
            assert all((deps/n).resolve().is_relative_to(deps) for n in archive.namelist())
            archive.extractall(deps)
    runner.DEPS=deps
    for r in json.loads((out/'sqlparse-context.json').read_text())['records']:
        assert hashlib.sha256((cache/r['role']/r['path']).read_bytes()).hexdigest()==r['source_sha256']
    records=[]
    for role in ['vulnerable','fixed']:
        code="""import sys,signal,time,json
sys.dont_write_bytecode=True
sys.path[:0]=['/target','/deps']
import sqlparse,sqlparse.lexer
assert sqlparse.lexer.__file__.startswith('/target/')
print('TARGET_MODULE',sqlparse.lexer.__file__,flush=True)
def expired(signum,frame):raise TimeoutError('local lexer deadline')
signal.signal(signal.SIGALRM,expired)
signal.setitimer(signal.ITIMER_REAL,2.0)
start=time.perf_counter();completed=False
try:
    tokens=list(sqlparse.lexer.tokenize("'"+"\\\\"*40))
    completed=True
except TimeoutError:pass
finally:signal.setitimer(signal.ITIMER_REAL,0)
print(json.dumps(dict(completed=completed,seconds=time.perf_counter()-start,input_characters=41,deadline_seconds=2.0)),flush=True)
assert completed,'Unterminated quoted input exceeded the bounded lexer deadline'
"""
        result=runner.run(cache/role,'CVE-2023-30608',python_code=code)
        records.append(dict(role=role,phase='resource_adapter',result=result))
        print(role,result['exit_code'],result['output'][-1200:],flush=True)
    (out/'sqlparse-resource-oracle.json').write_text(json.dumps(dict(records=records,input=dict(prefix='single quote',repeated_character='backslash',repetitions=40,closing_quote=False),deadline_seconds=2.0,dependency_wheel_lock='mcp-oracle-wheels.json',functional_controls='sqlparse-oracle.json',harness_sha256=hashlib.sha256(Path(__file__).read_text().replace('\r\n','\n').encode()).hexdigest(),interpretation='Source-guided author-derived bounded lexer workload, not an upstream security test. A handled local deadline is distinct from namespace/collection failure. Paired completion times support this input-specific resource regression only; not a throughput benchmark, universal complexity proof, or deployed denial-of-service result.'),indent=2)+'\n')


if __name__=='__main__':main()
