from tests.test_security_obligations import findings

BASE='''from anyio.streams.memory import MemoryObjectReceiveStream
from mcp.shared.message import SessionMessage
from pydantic import BaseModel
class Session:
 def __init__(self,stream:MemoryObjectReceiveStream[SessionMessage],model:type[BaseModel]):
  self.incoming=stream
  self.model=model
 async def receive(self):
  async for message in self.incoming:
{body}
'''


def scan(body):
    return [f for f in findings(BASE.format(body='\n'.join('   '+line for line in body.splitlines()))) if f.rule_id=='PY-OBL-MCP-VALIDATION-001']


def test_validation_failure_has_a_stream_and_action_location():
    fs=scan('value=self.model.model_validate(message.data)\nawait self.process(value)')
    assert fs and fs[0].cwe=='CWE-248' and fs[0].obligation['domain']=='availability'


def test_continuing_per_message_handler_is_recognized():
    assert not scan('try:\n value=self.model.model_validate(message.data)\nexcept ValueError:\n await self.error(message)')


def test_rethrowing_handler_is_not_a_recovery_boundary():
    assert scan('try:\n value=self.model.model_validate(message.data)\nexcept Exception:\n raise')


def test_nonvalidation_handler_or_unrelated_input_does_not_hide_the_gap():
    assert scan('try:\n value=self.model.model_validate(message.data)\nexcept KeyError:\n pass')
    assert not scan('value=self.model.model_validate(other.data)')


def test_other_stream_contract_is_not_assumed_to_be_external_mcp_data():
    code=BASE.format(body='   value=self.model.model_validate(message.data)').replace('from mcp.shared.message','from custom')
    assert not any(f.rule_id=='PY-OBL-MCP-VALIDATION-001' for f in findings(code))


def test_validation_inside_except_is_not_caught_by_its_sibling_handler():
    assert scan('try:\n await self.other()\nexcept ValueError:\n value=self.model.model_validate(message.data)')
