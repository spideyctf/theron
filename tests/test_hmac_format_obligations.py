from tests.test_security_obligations import findings

CODE='''import hmac
class Signer:
 def __init__(self,key):
  forbidden=[b"-----BEGIN PUBLIC KEY-----",b"ssh-rsa"]
  if any(marker in key for marker in forbidden):
   raise ValueError()
  self.secret=key
 def sign(self,data):
  return hmac.new(self.secret,data).digest()
'''


def matches(code):return [f for f in findings(code) if f.rule_id.startswith('PY-OBL-HMAC-FORMAT')]


def test_incomplete_public_key_blacklist_keeps_hmac_storage_evidence():
    fs=matches(CODE)
    assert len(fs)==1 and fs[0].severity.value=='MEDIUM'
    assert 'ecdsa-sha2-nistp256' in fs[0].obligation['observed']
    assert fs[0].obligation['related_locations'][0]['role']=='key-storage'


def test_ordinary_secret_use_does_not_imply_asymmetric_interoperability():
    assert not matches(CODE.replace('b"-----BEGIN PUBLIC KEY-----",b"ssh-rsa"','b"forbidden-test-value"'))


def test_broad_markers_cover_the_listed_representations():
    assert not matches(CODE.replace('b"-----BEGIN PUBLIC KEY-----",b"ssh-rsa"','b"-----BEGIN",b"ssh-",b"ecdsa-"'))


def test_unrelated_or_shadowed_hmac_contract_is_not_trusted():
    assert not matches(CODE.replace('import hmac','from custom import hmac'))
    assert not matches(CODE.replace('return hmac.new','hmac=object()\n  return hmac.new'))


def test_unknown_additional_guard_retains_only_a_review_notice():
    code=CODE.replace('  self.secret=key','  if rejects_public_keys(key):\n   raise ValueError()\n  self.secret=key')
    fs=matches(code)
    assert fs and all(f.severity.value=='INFO' for f in fs)


def test_key_replacement_is_not_assumed_to_preserve_public_input():
    fs=matches(CODE.replace('  self.secret=key','  key=random_secret()\n  self.secret=key'))
    assert fs and all(f.severity.value=='INFO' for f in fs)
