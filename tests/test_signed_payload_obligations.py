"""Original inert controls; no target module or token executes."""
import pytest
from tests.test_security_obligations import findings

TEMPLATE='''from jwcrypto.jws import JWS
from jwcrypto.common import json_decode,base64url_decode
def verify(raw,key):
 header,body,signature=raw.split('.')
 verifier=JWS()
{body}
'''


def scan(body):
    code=TEMPLATE.format(body='\n'.join(' '+line for line in body.splitlines()))
    return [f for f in findings(code) if f.rule_id.startswith('PY-OBL-JWS-PAYLOAD')]


def test_independently_parsed_claims_are_not_the_verified_payload():
    fs=scan('verifier.deserialize(raw,key)\nclaims=json_decode(base64url_decode(body))\nreturn claims')
    assert len(fs)==1 and fs[0].obligation['domain']=='crypto' and fs[0].maturity=='advisory'
    assert not fs[0].trace and fs[0].cwe=='CWE-347'


@pytest.mark.parametrize('body',[
 'verifier.deserialize(raw,key)\nclaims=json_decode(verifier.payload)\nreturn claims',
 'verifier.deserialize(raw,key)\nclaims=json_decode(base64url_decode(body))\nverified=json_decode(verifier.payload)\nif claims!=verified:\n raise ValueError()\nreturn claims',
 'claims=json_decode(base64url_decode(body))\nreturn claims',
 'verifier.deserialize(raw,None)\nreturn json_decode(base64url_decode(body))',
 'verifier=object()\nverifier.deserialize(raw,key)\nreturn json_decode(base64url_decode(body))',
 'verifier.deserialize=lambda *a: None\nverifier.deserialize(raw,key)\nreturn json_decode(base64url_decode(body))',
 'raw=other\nverifier.deserialize(raw,key)\nreturn json_decode(base64url_decode(body))',
])
def test_bound_or_unresolved_claims_do_not_become_identity_mismatch_claims(body):
    assert not scan(body)


@pytest.mark.parametrize('body',[
 'alias=verifier\nalias.deserialize(raw,key)\nclaims=json_decode(base64url_decode(body))\nreturn header,claims',
 'verifier.deserialize(raw,key=key)\nreturn json_decode(base64url_decode(body))',
 'verifier.deserialize(raw,key)\nclaims=json_decode(base64url_decode(body))\nif claims==json_decode(verifier.payload):\n pass\nreturn claims',
])
def test_aliases_and_non_rejecting_comparisons_keep_the_mismatch(body):
    assert scan(body)


def test_returned_header_alone_is_not_a_payload_identity_claim():
    assert not scan('verifier.deserialize(raw,key)\nreturn json_decode(base64url_decode(header))')


def test_crypto_ablation_disables_identity_analysis():
    code=TEMPLATE.format(body=' verifier.deserialize(raw,key)\n return json_decode(base64url_decode(body))')
    assert not any(f.rule_id.startswith('PY-OBL-JWS-PAYLOAD') for f in findings(code,disabled_features={'crypto_obligations'}))
