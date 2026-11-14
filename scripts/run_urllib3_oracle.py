"""Author-derived TLS proxy hostname adapter against the pinned urllib3 methods."""
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
    cache=ROOT/'.benchmark-cache/validated-oracles/CVE-2021-28363'
    deps=Path(tempfile.mkdtemp(prefix='theron-urllib3-deps-'));wheels={}
    for wheel in sorted(Path('/tmp/theron-urllib3-wheels').glob('*.whl')):
        wheels[wheel.name]=hashlib.sha256(wheel.read_bytes()).hexdigest()
        with zipfile.ZipFile(wheel) as archive:
            assert all((deps/n).resolve().is_relative_to(deps) for n in archive.namelist())
            archive.extractall(deps)
    lock=out/'urllib3-oracle-wheels.json'
    assert wheels
    if lock.exists():assert json.loads(lock.read_text())==wheels
    lock.write_text(json.dumps(wheels,indent=2)+'\n');runner.DEPS=deps
    for r in json.loads((out/'urllib3-context.json').read_text())['records']:
        assert hashlib.sha256((cache/r['role']/r['path']).read_bytes()).hexdigest()==r['source_sha256']
    probe=runner.run(cache/'fixed','probe',probe=True)
    assert probe['exit_code']==0 and json.loads(probe['output'])==dict(windows_visible=False,home_visible=False,network_result=101)
    records=[]
    for role in ['vulnerable','fixed']:
        for phase in ['security_adapter','functional_adapter']:
            code="""import sys,pathlib,ssl,socket,threading,json,importlib.util
from types import SimpleNamespace
sys.dont_write_bytecode=True
sys.path[:0]=['/target/src','/deps']
spec=importlib.util.spec_from_file_location('urllib3.packages.six','/target/src/urllib3/packages/six.py')
six=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=six
spec.loader.exec_module(six)
def find_spec(self,fullname,path=None,target=None):
    return importlib.util.spec_from_loader(fullname,self) if self.find_module(fullname,path) is not None else None
six._SixMetaPathImporter.find_spec=find_spec
import urllib3.connection,trustme
assert urllib3.connection.__file__.startswith('/target/src/')
print('TARGET_MODULE',urllib3.connection.__file__)
"""
            code+='peer_name='+repr('different.invalid' if phase=='security_adapter' else 'expected.invalid')+'\n'
            code+="""ca=trustme.CA()
cert=ca.issue_cert(peer_name)
ca.cert_pem.write_to_path('/tmp/ca.pem')
server_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
cert.configure_cert(server_context)
client,server=socket.socketpair()
client.settimeout(3);server.settimeout(3)
def serve():
    try:
        with server_context.wrap_socket(server,server_side=True):pass
    except ssl.SSLError:pass
thread=threading.Thread(target=serve,daemon=True);thread.start()
connection=urllib3.connection.HTTPSConnection('destination.invalid',proxy_config=SimpleNamespace(ssl_context=None))
connection.cert_reqs='CERT_REQUIRED'
connection.ca_certs='/tmp/ca.pem'
accepted=False;hostname_rejected=False
try:
    wrapped=connection._connect_tls_proxy('expected.invalid',client)
    accepted=True
    wrapped.close()
except (ssl.SSLError,urllib3.exceptions.SSLError) as error:
    message=str(error).lower()
    hostname_rejected=any(part in message for part in ['hostname mismatch','not valid for',"doesn't match"])
    print('TLS_ERROR',str(error))
finally:
    client.close();thread.join(3)
print(json.dumps(dict(accepted=accepted,hostname_rejected=hostname_rejected,peer_name=peer_name)))
"""
            code+=('assert hostname_rejected and not accepted\n' if phase=='security_adapter' else 'assert accepted and not hostname_rejected\n')
            result=runner.run(cache/role,'CVE-2021-28363',python_code=code)
            records.append(dict(role=role,phase=phase,result=result))
            print(role,phase,result['exit_code'],result['output'][-1800:],flush=True)
    (out/'urllib3-oracle.json').write_text(json.dumps(dict(records=records,probe=probe,dependency_wheels=wheels,harness_sha256=hashlib.sha256(Path(__file__).read_text().replace('\r\n','\n').encode()).hexdigest(),interpretation='Author-derived adapter, not an unmodified upstream test: calls the original HTTPSConnection._connect_tls_proxy using a socketpair TLS peer and trustme CA. A trusted certificate with a mismatching hostname must fail; a matching hostname must succeed. The vendored six importer receives a PEP451 find_spec compatibility method for Python 3.13; TLS methods are unchanged. This distinguishes hostname checking from CA trust failure. No DNS/TCP or full HTTP proxy integration is exercised. Original upstream dummyserver tests remain unrun; the initial import failure is preserved separately.'),indent=2)+'\n')


if __name__=='__main__':main()
