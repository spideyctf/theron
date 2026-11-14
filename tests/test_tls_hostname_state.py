import pytest
from tests.test_security_obligations import findings

CODE='''from urllib3.util.ssl_ import create_urllib3_context,ssl_wrap_socket
def wrap(peer,hostname):
 context=create_urllib3_context()
 return ssl_wrap_socket(sock=peer,server_hostname=hostname,ssl_context=context)
'''


def scan(code):return [f for f in findings(code) if f.rule_id.startswith('PY-OBL-TLS-HOSTNAME-001')]


def test_unchecked_context_return_has_creation_and_action_locations():
    fs=scan(CODE)
    assert len(fs)==1 and fs[0].cwe is None and fs[0].obligation['domain']=='tls'
    assert fs[0].severity.value=='INFO' and fs[0].evidence_kind=='coverage-notice'
    assert [p['role'] for p in fs[0].obligation['related_locations']]==['context-creation','return']


def test_native_enable_and_context_alias_follow_state():
    assert not scan(CODE.replace(' return',' alias=context\n alias.check_hostname=True\n return'))
    assert scan(CODE.replace(' return',' context.check_hostname=True\n context.check_hostname=False\n return'))


def test_correct_manual_check_precedes_return():
    code=CODE.replace(' return ssl_wrap_socket',' socket=ssl_wrap_socket')+' import ssl\n ssl.match_hostname(socket.getpeercert(),hostname)\n return socket\n'
    # Local imports are conservatively unresolved; a module import resolves the matcher.
    code='import ssl\n'+code.replace(' import ssl\n','')
    assert not scan(code)
    assert scan(code.replace('socket.getpeercert(),hostname','socket.getpeercert(),other'))
    assert scan(code.replace(' ssl.match_hostname(socket.getpeercert(),hostname)\n return socket',' return socket\n ssl.match_hostname(socket.getpeercert(),hostname)'))


@pytest.mark.parametrize('replacement',[
    ' context=custom()',
    ' create_urllib3_context=custom\n context=create_urllib3_context()',
])
def test_unresolved_or_shadowed_factory_does_not_keep_a_library_contract(replacement):
    assert not scan(CODE.replace(' context=create_urllib3_context()',replacement))


def test_parameter_shadowing_and_unrelated_libraries_stay_quiet():
    assert not scan(CODE.replace('def wrap(peer,hostname):','def wrap(peer,hostname,create_urllib3_context):'))
    assert not scan(CODE.replace('urllib3.util.ssl_','custom'))
    assert not scan(CODE.replace('ssl_context=context','ssl_context=custom'))


def test_branch_enable_does_not_cover_the_alternate_path():
    assert scan(CODE.replace(' return',' if enabled:\n  context.check_hostname=True\n return'))


def test_replaced_socket_does_not_retain_return_lineage():
    code=CODE.replace(' return ssl_wrap_socket',' socket=ssl_wrap_socket')+' socket=custom\n return socket\n'
    assert not scan(code)


def test_proxy_factory_and_keyword_wrapper_use_the_same_obligation():
    code=CODE.replace('from urllib3.util.ssl_ import create_urllib3_context,ssl_wrap_socket',
        'from urllib3.util.proxy import create_proxy_ssl_context\nfrom urllib3.util.ssl_ import ssl_wrap_socket').replace('create_urllib3_context()','create_proxy_ssl_context(version,requirements,ca,directory,data)')
    assert scan(code)


def test_explicit_disable_is_an_advisory_but_post_handshake_enable_is_too_late():
    code=CODE.replace(' return',' context.check_hostname=False\n return')
    fs=scan(code)
    assert fs[0].severity.value=='MEDIUM' and fs[0].cwe=='CWE-295'
    late=code.replace(' return ssl_wrap_socket',' socket=ssl_wrap_socket')+' context.check_hostname=True\n return socket\n'
    assert scan(late)[0].severity.value=='MEDIUM'


def test_disabling_after_a_checked_handshake_does_not_erase_validation():
    code=CODE.replace(' return',' context.check_hostname=True\n return').replace(' return ssl_wrap_socket',' socket=ssl_wrap_socket')
    assert not scan(code+' context.check_hostname=False\n return socket\n')


def test_reassigned_hostname_does_not_validate_the_original_destination():
    code='import ssl\n'+CODE.replace(' return ssl_wrap_socket',' socket=ssl_wrap_socket')
    assert scan(code+' hostname="different.invalid"\n ssl.match_hostname(socket.getpeercert(),hostname)\n return socket\n')


def test_no_hostname_does_not_invent_an_expected_identity():
    assert not scan(CODE.replace('server_hostname=hostname','server_hostname=None'))


def test_tls_ablation_disables_the_new_domain():
    from scanner.python_analysis import analyze_python
    assert not [f for f in analyze_python('app.py',CODE,module='sast',disabled_features=('tls_obligations',))
                if f.rule_id.startswith('PY-OBL-TLS-HOSTNAME-001')]
