from tests.test_security_obligations import findings

CODE='''from urllib3 import PoolManager
class Adapter:
 def __init__(self):
  self.manager=PoolManager()
 def choose(self,url):
  return self.manager.connection_from_url(url)
 def configure(self,conn,verify):
  if verify:
   conn.cert_reqs="CERT_REQUIRED"
  else:
   conn.cert_reqs="CERT_NONE"
 def send(self,url,verify=True):
  connection=self.choose(url)
  self.configure(connection,verify)
'''


def matches(code):return [f for f in findings(code) if f.rule_id.startswith('PY-OBL-TLS-POOL')]


def test_policy_independent_pool_then_mutation_retains_both_locations():
    fs=matches(CODE)
    assert len(fs)==1 and fs[0].severity.value=='MEDIUM' and fs[0].cwe=='CWE-295'
    assert fs[0].obligation['related_locations'][0]['role']=='pool-selection'


def test_policy_input_to_selection_is_not_assumed_missing():
    assert not matches(CODE.replace('self.choose(url)','self.choose(url,verify)'))


def test_replaced_connection_or_checker_is_not_a_resolved_mutation():
    assert not matches(CODE.replace('  self.configure(connection,verify)','  connection=custom\n  self.configure(connection,verify)'))
    assert not matches(CODE.replace('  self.configure(connection,verify)','  self.configure=custom\n  self.configure(connection,verify)'))


def test_unrelated_manager_and_constant_policy_do_not_establish_cross_policy_reuse():
    assert not matches(CODE.replace('from urllib3 import','from custom import'))
    assert not matches(CODE.replace('self.configure(connection,verify)','self.configure(connection,True)'))


def test_keyword_policy_and_connection_aliases_are_supported():
    code=CODE.replace('  self.configure(connection,verify)','  alias=connection\n  self.configure(conn=alias,verify=verify)')
    assert matches(code)


def test_constructor_parameter_or_local_assignment_shadows_imported_factory():
    assert not matches(CODE.replace('def __init__(self):','def __init__(self,PoolManager):'))
    assert not matches(CODE.replace('  self.manager=PoolManager()','  PoolManager=custom\n  self.manager=PoolManager()'))


def test_reassigned_or_deleted_manager_does_not_retain_library_contract():
    assert not matches(CODE.replace('  return self.manager.connection_from_url(url)',
                                   '  self.manager=custom\n  return self.manager.connection_from_url(url)'))
    assert not matches(CODE+'\n def replace(self,value):\n  self.manager=value\n')
    assert not matches(CODE+'\n def remove(self):\n  del self.manager\n')
