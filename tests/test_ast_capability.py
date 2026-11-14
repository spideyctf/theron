from tests.test_security_obligations import findings

CODE='''import ast
from typing import Callable
def accessor(obj,name):
 if name.startswith("__"):
  raise ValueError()
 return getattr(obj,name)
TOOLS={"getattr":accessor,"map":map,"filter":filter}
def lookup(node:ast.Name,tools:dict[str,Callable]):
 return tools[node.id]
def execute(code,tools):
 tree=ast.parse(code)
 return lookup(tree.body[0],tools)
class Executor:
 def __init__(self):
  self.tools={**TOOLS.copy()}
 def run(self,code):
  return execute(code,tools=self.tools)
'''


def scan(code):return [f for f in findings(code) if f.rule_id=='PY-OBL-AI-CAPABILITY-001']


def test_injected_raw_callable_has_registry_and_return_evidence():
    fs=scan(CODE)
    assert fs and fs[0].obligation['domain']=='sandbox' and fs[0].maturity=='advisory'


def test_wrapped_lookup_or_unbound_table_is_not_the_raw_lookup_condition():
    assert not scan(CODE.replace('return tools[node.id]','return policy_wrapper(tools[node.id])'))
    assert not scan(CODE.replace('self.tools={**TOOLS.copy()}','self.tools=custom'))


def test_ordinary_mapping_or_noninterpreter_use_stays_quiet():
    assert not scan(CODE.replace('ast.Name','str'))
    assert not scan(CODE.replace('tree=ast.parse(code)','tree=custom(code)'))


def test_custom_function_types_are_not_assumed_builtin_capabilities():
    assert not scan(CODE.replace('import ast','import ast\nmap=custom'))
