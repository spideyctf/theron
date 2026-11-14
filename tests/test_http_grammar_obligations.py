import pytest
from tests.test_security_obligations import findings

CHUNK='''from waitress.utilities import BadRequest
class Reader:
 def received(self,data):
  remaining=self.count
  chunk=data[:remaining]
  pos=data.find(b"\\r\\n")
  line=data[:pos]
{guard}
  size=int(line.strip(),16)
  self.count=size
'''


def scan(code):return [f for f in findings(code) if f.rule_id.startswith('PY-OBL-HTTP-NUMERIC')]


def test_crlf_chunk_size_needs_lexical_validation_before_integer_parsing():
    code=CHUNK.format(guard='  error=BadRequest("invalid")')
    fs=scan(code)
    assert len(fs)==1 and fs[0].cwe=='CWE-444' and fs[0].severity.value=='MEDIUM'


@pytest.mark.parametrize('guard',[
 '  if not hex_pattern.fullmatch(line):\n   raise BadRequest("invalid")',
 '  if not hex_pattern.match(line):\n   return BadRequest("invalid")',
])
def test_visible_rejecting_lexical_guards_suppress_the_specific_antipattern(guard):
    assert not scan(CHUNK.format(guard=guard))


def test_non_rejecting_test_does_not_establish_a_lexical_boundary():
    fs=scan(CHUNK.format(guard='  if not hex_pattern.match(line):\n   error=BadRequest("invalid")'))
    assert fs and fs[0].severity.value=='MEDIUM'


def test_unknown_validator_is_reviewed_and_not_assumed_broken():
    fs=scan(CHUNK.format(guard='  if not valid_size(line):\n   raise BadRequest("invalid")'))
    assert fs and all(f.severity.value=='INFO' for f in fs)


def test_unrelated_numeric_or_shadowed_integer_operations_stay_quiet():
    assert not scan(CHUNK.format(guard='  error=BadRequest("invalid")').replace('from waitress.utilities','from unrelated'))
    assert not scan(CHUNK.format(guard='  int=safe_int\n  error=BadRequest("invalid")'))
    assert not scan(CHUNK.format(guard='  error=BadRequest("invalid")').replace('self.count=size','self.metadata=size'))


def test_content_length_does_not_rely_only_on_python_decimal_conversion():
    code='from waitress.receiver import ChunkedReceiver\ndef parse(headers):\n reader=ChunkedReceiver(buffer)\n return int(headers.get("CONTENT_LENGTH",0))'
    assert any(f.severity.value=='MEDIUM' for f in scan(code))


CODING='''from gunicorn.http.body import Body,ChunkedReader
def choose(self):
 chunked=False
 for name,value in self.headers:
  if name=="TRANSFER-ENCODING":
   if value.lower()=="chunked":
    chunked=True
{reject}
 if chunked:
  self.body=Body(ChunkedReader(self,self.unreader))
'''


def coding(code):return [f for f in findings(code) if f.rule_id=='PY-OBL-HTTP-CODING-001']


def test_unknown_transfer_codings_cannot_be_silently_ignored():
    assert coding(CODING.format(reject=''))


def test_explicit_rejection_or_different_value_identity_is_not_the_antipattern():
    assert not coding(CODING.format(reject='   else:\n    raise ValueError()'))
    assert not coding(CODING.format(reject='').replace('value.lower()','other.lower()'))
    assert not coding(CODING.format(reject='').replace('self.headers','self.options'))


def test_protocol_ablation_disables_new_grammar_checks():
    fs=findings(CODING.format(reject=''),disabled_features={'protocol_obligations'})
    assert not any(f.rule_id.startswith('PY-OBL-HTTP') for f in fs)
