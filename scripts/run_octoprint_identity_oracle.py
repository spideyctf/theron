"""Source-guided peer-identity adapter executing the original changed helper only."""
import ast
import hashlib
import json
from pathlib import Path
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import run_obligation_oracles as runner


def main():
    out=ROOT/'docs/evaluation/evidence-2026-11-14'
    cache=ROOT/'.benchmark-cache/vul4py-pilot/CVE-2024-32977'
    source_path='src/octoprint/server/util/flask.py'
    receipts=json.loads((ROOT/'docs/evaluation/mechanisms-2026-11-14/vul4py/source-receipts.json').read_text())['records']
    functions={}
    for role in ['vulnerable','fixed']:
        raw=(cache/role/source_path).read_bytes()
        expected=next(r['source_sha256'] for r in receipts if r.get('id')=='CVE-2024-32977' and r.get('role')==role and r.get('path')==source_path)
        assert hashlib.sha256(raw).hexdigest()==expected
        source=raw.decode('utf-8-sig');fn=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name=='get_remote_address')
        assert all(isinstance(d,ast.Call) and isinstance(d.func,ast.Name) and d.func.id=='deprecated' for d in fn.decorator_list)
        functions[role]=dict(path=source_path,start=fn.lineno,end=fn.end_lineno,source_sha256=expected,
                            function_sha256=hashlib.sha256(ast.get_source_segment(source,fn).encode()).hexdigest())
    runner.DEPS=Path(tempfile.mkdtemp(prefix='theron-peer-identity-empty-deps-'))
    records=[]
    for role in ['vulnerable','fixed']:
        for phase in ['security_adapter','functional_adapter']:
            code="""import sys,ast,json,pathlib
from types import SimpleNamespace
sys.dont_write_bytecode=True
path=pathlib.Path('/target/src/octoprint/server/util/flask.py')
source=path.read_text()
fn=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name=='get_remote_address')
assert all(isinstance(d,ast.Call) and isinstance(d.func,ast.Name) and d.func.id=='deprecated' for d in fn.decorator_list)
scope={'deprecated':lambda *args,**kwargs:lambda function:function}
exec(compile(ast.Module(body=[fn],type_ignores=[]),str(path),'exec'),scope)
print('TARGET_FUNCTION',str(path),fn.lineno,flush=True)
helper=scope['get_remote_address']
"""
            if phase=='security_adapter':
                code+="""request=SimpleNamespace(remote_addr='203.0.113.21',headers={'X-Forwarded-For':'127.0.0.1'})
actual=helper(request)
print(json.dumps(dict(remote_addr=request.remote_addr,forwarded_header=request.headers['X-Forwarded-For'],returned=actual)),flush=True)
assert actual==request.remote_addr,'Untrusted forwarded header replaced the transport peer identity'
"""
            else:
                code+="""for headers in [{},{'X-Forwarded-For':'203.0.113.21'}]:
    request=SimpleNamespace(remote_addr='203.0.113.21',headers=headers)
    assert helper(request)==request.remote_addr
print('LEGITIMATE_CASES_PASSED',2)
"""
            result=runner.run(cache/role,'CVE-2024-32977',python_code=code)
            records.append(dict(role=role,phase=phase,result=result))
            print(role,phase,result['exit_code'],result['output'][-1300:],flush=True)
    (out/'octoprint-identity-oracle.json').write_text(json.dumps(dict(records=records,functions=functions,functional_upstream_controls='octoprint-oracle.json',harness_sha256=hashlib.sha256(Path(__file__).read_text().replace('\r\n','\n').encode()).hexdigest(),interpretation='Author-derived adapter executes an AST-extracted, unmodified get_remote_address body from each hash-verified source file. The fixed helper deprecation-warning decorator is replaced by an identity decorator; no policy decorator is bypassed. Request data supplies a transport peer and a conflicting forwarded header; legitimate direct/agreed-identity controls also run. No Flask/server initialization or trusted-proxy middleware is exercised. This corroborates the helper-level identity change, not full authentication bypass, deployment configuration or complete upstream security tests.'),indent=2)+'\n')


if __name__=='__main__':main()
