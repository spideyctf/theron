"""Original controls, inspected as AST only. No fixture application executes."""
import pytest
from scanner.python_analysis import analyze_python
from scanner.python_project import PythonProject

AUTH='''from rest_framework.generics import GenericAPIView, get_object_or_404
from rest_framework.permissions import BasePermission, IsAuthenticated, AllowAny
class Owner(BasePermission):
 def has_object_permission(self,request,view,obj):
  return obj.owner==request.user
class View(GenericAPIView):
 permission_classes=[Owner]
 def get_object(self):
{body}
'''


def findings(code, **kwargs):
    files={'app.py':code}
    return analyze_python('app.py',code,module='sast',project=PythonProject(files),**kwargs)


def auth(body,policy='Owner'):
    code=AUTH.format(body='\n'.join('  '+line for line in body.splitlines()))
    return [f for f in findings(code.replace('permission_classes=[Owner]','permission_classes=['+policy+']')) if f.rule_id.startswith('PY-OBL-AUTH')]


def test_declared_object_policy_bypass_has_required_check_and_action_evidence():
    fs=auth('obj=get_object_or_404(self.get_queryset(),pk=1)\nreturn obj')
    assert len(fs)==1 and fs[0].cwe=='CWE-863' and fs[0].maturity=='advisory'
    assert fs[0].obligation['domain']=='authorization' and fs[0].obligation['action']['line_number']==10
    assert fs[0].evidence_kind=='static-obligation' and not fs[0].trace


@pytest.mark.parametrize('body',[
 'obj=get_object_or_404(self.get_queryset(),pk=1)\nself.check_object_permissions(self.request,obj)\nreturn obj',
 'obj=get_object_or_404(self.get_queryset(),pk=1)\nalias=obj\nself.check_object_permissions(self.request,alias)\nreturn obj',
 'obj=get_object_or_404(self.get_queryset(),pk=1)\ncheck=self.check_object_permissions\ncheck(self.request,obj)\nreturn obj',
 'obj=get_object_or_404(self.get_queryset(),pk=1)\nif unknown:\n raise ValueError()\nself.check_object_permissions(self.request,obj)\nreturn obj',
])
def test_same_object_checks_and_early_rejection_are_not_bypasses(body):
    assert not auth(body)


@pytest.mark.parametrize('body',[
 'obj=get_object_or_404(self.get_queryset(),pk=1)\nother=get_object_or_404(self.get_queryset(),pk=2)\nself.check_object_permissions(self.request,other)\nreturn obj',
 'obj=get_object_or_404(self.get_queryset(),pk=1)\nself.check_object_permissions(self.request,obj)\nobj=get_object_or_404(self.get_queryset(),pk=2)\nreturn obj',
 'obj=get_object_or_404(self.get_queryset(),pk=1)\nif unknown:\n self.check_object_permissions(self.request,obj)\nreturn obj',
 'obj=get_object_or_404(self.get_queryset(),pk=1)\nself.check_object_permissions(other_request,obj)\nreturn obj',
])
def test_checks_must_cover_every_path_and_the_same_subject_and_object(body):
    assert any(f.cwe=='CWE-863' for f in auth(body))


@pytest.mark.parametrize('policy',['IsAuthenticated','AllowAny',''])
def test_authentication_only_or_no_object_policy_is_not_a_missing_object_check(policy):
    assert not auth('return get_object_or_404(self.get_queryset(),pk=1)',policy)


def test_unresolved_policy_is_an_explicit_notice():
    fs=auth('return get_object_or_404(self.get_queryset(),pk=1)','UnknownPermission')
    assert fs and all(f.severity.value=='INFO' and f.cwe is None for f in fs)


def test_caught_permission_error_is_not_proved_safe():
    fs=auth('obj=get_object_or_404(self.get_queryset(),pk=1)\ntry:\n self.check_object_permissions(self.request,obj)\nexcept Exception:\n pass\nreturn obj')
    assert fs  # Unresolved exception paths retain an explicit review outcome.


def test_custom_check_hook_is_not_assumed_to_enforce_framework_permissions():
    code=AUTH.format(body='  return get_object_or_404(self.get_queryset(),pk=1)')+' def check_object_permissions(self,request,obj):\n  pass\n'
    fs=[f for f in findings(code) if f.rule_id.startswith('PY-OBL-AUTH')]
    assert fs and all(f.severity.value=='INFO' for f in fs)


def test_authorization_ablation_removes_only_obligation_check():
    code=AUTH.format(body='  return get_object_or_404(self.get_queryset(),pk=1)')
    assert not any(f.rule_id.startswith('PY-OBL-AUTH') for f in findings(code,disabled_features={'auth_obligations'}))


@pytest.mark.parametrize('root',['import jwt','from jose import jwt'])
def test_explicit_signature_verification_disable_is_an_advisory_setting(root):
    fs=findings(root+'\njwt.decode(token,key,algorithms=["RS256"],options={"verify_signature":False})')
    match=next(f for f in fs if f.rule_id=='PY-OBL-JWT-VERIFY-001')
    assert match.maturity=='advisory' and match.obligation['domain']=='crypto'


def test_untrusted_algorithm_selection_is_not_a_fixed_allowlist():
    code='import jwt\nfrom flask import request\njwt.decode(request.args["token"],key,algorithms=request.get_json()["algorithms"])'
    assert any(f.rule_id=='PY-OBL-JWT-ALG-001' and f.trace[0]['role']=='source' for f in findings(code))


@pytest.mark.parametrize('call',[
 'jwt.decode(token,key,algorithms=["RS256"])',
 'jwt.decode(token,key,algorithms=["HS256"])',
 'jwt.decode(token,key)',
])
def test_compatible_or_unresolved_configurations_are_not_key_confusion_claims(call):
    assert not any(f.rule_id.startswith('PY-OBL-JWT') for f in findings('import jwt\n'+call))


def test_mixed_algorithm_families_preserve_runtime_rejection_uncertainty():
    fs=findings('import jwt\njwt.decode(token,key,algorithms=["RS256","HS256"])')
    f=next(f for f in fs if f.rule_id=='PY-OBL-JWT-MIX-001')
    assert 'unverified' in f.description and f.maturity=='advisory'


def test_known_public_key_is_not_a_symmetric_secret():
    fs=findings('import jwt\njwt.decode(token,"ssh-rsa AAAA",algorithms=["HS256"])')
    assert any(f.rule_id=='PY-OBL-JWT-KEY-001' for f in fs)


def test_shadowed_jwt_api_is_not_a_library_decoder():
    assert not any(f.rule_id.startswith('PY-OBL-JWT') for f in findings('import jwt\njwt=object()\njwt.decode(token,key,options={"verify_signature":False})'))


PROTO='''from h11._receivebuffer import ReceiveBuffer
from h11._events import Data
class Reader:
 def __init__(self):
  self.pending={initial}
 def read(self,buf:ReceiveBuffer):
{body}
 def next_chunk(self):
  self.pending={pending}
  return Data(data=b"x",chunk_end=True)
'''


def proto(body,initial='0',pending='2'):
    code=PROTO.format(initial=initial,pending=pending,body='\n'.join('  '+line for line in body.splitlines()))
    return [f for f in findings(code) if f.rule_id.startswith('PY-OBL-HTTP')]


def test_raw_footer_bytes_cannot_be_discarded_using_only_their_length():
    fs=proto('data=buf.maybe_extract_at_most(self.pending)\nself.pending-=len(data)')
    assert len(fs)==1 and fs[0].cwe=='CWE-444' and fs[0].obligation['domain']=='protocol'


def test_exact_delimiter_check_before_advancing_state_is_recognized():
    assert not proto('data=buf.maybe_extract_at_most(self.pending)\nif data!=b"\\r\\n":\n raise ValueError()\nself.pending-=len(data)')


def test_length_check_is_not_a_content_check():
    assert proto('data=buf.maybe_extract_at_most(self.pending)\nif len(data)!=2:\n raise ValueError()\nself.pending-=len(data)')


def test_fragmented_prefix_validation_tracks_remaining_bytes():
    body='data=buf.maybe_extract_at_most(len(self.pending))\nif data!=self.pending[:len(data)]:\n raise ValueError()\nself.pending=self.pending[len(data):]'
    assert not proto(body,initial='b""',pending='b"\\r\\n"')


def test_nonterminating_mismatch_branch_does_not_validate_footer():
    assert proto('data=buf.maybe_extract_at_most(self.pending)\nif data!=b"\\r\\n":\n pass\nself.pending-=len(data)')


def test_unrelated_buffer_apis_do_not_become_http_framing_findings():
    code=PROTO.format(initial='0',pending='2',body='  data=buf.maybe_extract_at_most(self.pending)\n  self.pending-=len(data)').replace('from h11._receivebuffer import ReceiveBuffer','from custom import ReceiveBuffer')
    assert not any(f.rule_id.startswith('PY-OBL-HTTP') for f in findings(code))


def test_protocol_ablation_preserves_other_rules():
    code=PROTO.format(initial='0',pending='2',body='  data=buf.maybe_extract_at_most(self.pending)\n  self.pending-=len(data)')
    assert not any(f.rule_id.startswith('PY-OBL-HTTP') for f in findings(code,disabled_features={'protocol_obligations'}))


def test_keyword_permission_checks_are_recognized():
    assert not auth('obj=get_object_or_404(self.get_queryset(),pk=1)\nself.check_object_permissions(request=self.request,obj=obj)\nreturn obj')


@pytest.mark.parametrize('mutation',['self.request=object()','self.check_object_permissions=lambda *args: None'])
def test_replaced_subject_or_checker_is_not_trusted(mutation):
    assert auth('obj=get_object_or_404(self.get_queryset(),pk=1)\n'+mutation+'\nself.check_object_permissions(self.request,obj)\nreturn obj')


def test_read_only_policy_does_not_become_a_missing_write_guard():
    code=AUTH.format(body='  return get_object_or_404(self.get_queryset(),pk=1)')
    code=code.replace('GenericAPIView,','RetrieveAPIView,').replace('class View(GenericAPIView)','class View(RetrieveAPIView)')
    code=code.replace('return obj.owner==request.user','return request.method in ("GET","HEAD","OPTIONS") or obj.owner==request.user')
    assert not any(f.rule_id.startswith('PY-OBL-AUTH') for f in findings(code))


def test_write_capable_view_still_requires_conditional_owner_permission():
    code=AUTH.format(body='  return get_object_or_404(self.get_queryset(),pk=1)')
    code=code.replace('return obj.owner==request.user','return request.method in ("GET","HEAD","OPTIONS") or obj.owner==request.user')
    assert any(f.cwe=='CWE-863' for f in findings(code))


def test_foreign_lookup_model_is_not_assumed_to_use_the_views_object_policy():
    fs=auth('return get_object_or_404(OtherModel,pk=1)')
    assert fs and all(f.severity.value=='INFO' for f in fs)


def test_wrong_object_check_locations_are_preserved():
    fs=auth('obj=get_object_or_404(self.get_queryset(),pk=1)\nother=get_object_or_404(self.get_queryset(),pk=2)\nself.check_object_permissions(self.request,other)\nreturn obj')
    locations=fs[0].obligation['related_locations']
    assert any(p['role']=='policy' for p in locations)
    assert any(p['role']=='check' and p['matches_returned_object'] is False and p['matches_subject'] is True for p in locations)


def test_unknown_options_expansion_does_not_prove_disabled_verification():
    assert not any(f.rule_id=='PY-OBL-JWT-VERIFY-001' for f in findings('import jwt\njwt.decode(token,key,options={"verify_signature":False,**overrides})'))


def test_unverified_token_header_does_not_supply_a_trusted_algorithm_allowlist():
    code='import jwt\nfrom flask import request\ntoken=request.args["token"]\nheader=jwt.get_unverified_header(token)\njwt.decode(token,key,algorithms=[header["alg"]])'
    assert any(f.rule_id=='PY-OBL-JWT-ALG-001' for f in findings(code))


def test_loaded_then_serialized_public_key_is_not_an_hmac_secret():
    code='import jwt\nfrom cryptography.hazmat.primitives.serialization import load_pem_public_key\nkey=load_pem_public_key(pem)\nraw=key.public_bytes(encoding,format)\njwt.decode(token,raw,algorithms=["HS256"])'
    assert any(f.rule_id=='PY-OBL-JWT-KEY-001' for f in findings(code))


def test_crypto_ablation_leaves_existing_checks_enabled():
    fs=findings('import jwt\njwt.decode(token,key,options={"verify_signature":False})',disabled_features={'crypto_obligations'})
    assert not any(f.rule_id.startswith('PY-OBL-JWT') for f in fs)


def test_validated_footer_alias_retains_its_content_check():
    assert not proto('data=buf.maybe_extract_at_most(self.pending)\nif data!=b"\\r\\n":\n raise ValueError()\nalias=data\nself.pending-=len(alias)')


def test_footer_reassignment_invalidates_the_old_byte_check():
    assert proto('data=buf.maybe_extract_at_most(self.pending)\nif data!=b"\\r\\n":\n raise ValueError()\ndata=buf.maybe_extract_at_most(self.pending)\nself.pending-=len(data)')


def test_shadowed_length_function_does_not_establish_parser_safety():
    fs=proto('len=lambda value: 1\ndata=buf.maybe_extract_at_most(self.pending)\nself.pending-=len(data)')
    assert fs and all(f.severity.value=='INFO' for f in fs)
