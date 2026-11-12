"""Original static-only controls for recurring API and propagation gaps."""
import pytest

from scanner.python_analysis import analyze_python
from scanner.python_project import PythonProject


def cwes(code):
    return {f.cwe for f in analyze_python('service.py', code)}


@pytest.mark.parametrize('call', ["hashlib.md5(b'x')", "hashlib.sha1(b'x')", "hashlib.new('MD5')", "hashlib.new(name='sha1')"])
def test_resolved_weak_hash(call):
    result = analyze_python('service.py', 'import hashlib\n' + call)
    assert len(result) == 1 and result[0].cwe == 'CWE-328'
    assert result[0].evidence_kind == 'static-configuration'
    assert result[0].confidence == 'medium'


@pytest.mark.parametrize('code', [
    "import hashlib\nhashlib.md5(b'x',usedforsecurity=False)",
    "import hashlib\nhashlib.new('sha256')",
    "from custom import hashlib\nhashlib.md5(b'x')",
    "import hashlib\nhashlib=object()\nhashlib.md5(b'x')",
    "# hashlib.md5(b'x')",
])
def test_hash_near_misses(code):
    assert not cwes(code)


@pytest.mark.parametrize('target', ["session['identity'] = request.args['name']", "session[request.args['key']] = 'user'"])
def test_session_boundary(target):
    assert 'CWE-501' in cwes('from flask import session,request\n' + target)


def test_session_constant_and_local_map():
    assert not cwes("from flask import session,request\nsession['theme']='dark'\ncache={}\ncache['x']=request.args['x']")


@pytest.mark.parametrize('generator,expected', [
    ('random.getrandbits(128)', True), ('random.Random().randint(1,100)', True),
    ('random.SystemRandom().getrandbits(128)', False), ('secrets.token_urlsafe(32)', False),
])
def test_randomness_requires_token_sink(generator, expected):
    code = f'''from flask import request
import random,secrets
value=str({generator})
tokens={{}}
if request.cookies.get('remember') == tokens['user']:
 pass
else:
 tokens['user']=value
'''
    assert ('CWE-338' in cwes(code)) == expected
    assert not cwes('import random,secrets\nsimulation=' + generator)


@pytest.mark.parametrize('features,expected', [
    ('p.setFeature(feature_external_ges,True)', True),
    ('p.setFeature(feature_external_ges,False)', False),
    ('p.setFeature(feature_external_ges,True)\np.setFeature(feature_external_ges,False)', False),
    ('', False),
])
def test_sax_parser_configuration(features, expected):
    code = f'''from flask import request
from xml.sax import make_parser
from xml.sax.handler import feature_external_ges
from xml.dom.minidom import parseString
p=make_parser()
{features}
parseString(request.data,p)
'''
    assert ('CWE-611' in cwes(code)) == expected


def test_sax_separate_instances_and_constant_input():
    code = '''from flask import request
import xml.sax,xml.sax.handler,xml.dom.minidom
p=xml.sax.make_parser()
q=xml.sax.make_parser()
p.setFeature(xml.sax.handler.feature_external_ges,True)
xml.dom.minidom.parseString(request.data,q)
xml.dom.minidom.parseString('<root/>',p)
'''
    assert not cwes(code)


@pytest.mark.parametrize('wrapper', ['base64.b64encode', 'base64.urlsafe_b64decode', 'safe_join'])
def test_wrappers_preserve_command_taint(wrapper):
    code = f'from flask import request\nimport base64,os\nfrom werkzeug.security import safe_join\nos.system({wrapper}(request.args["x"]))'
    assert 'CWE-78' in cwes(code)


def test_xpath_expression_argument_not_bound_value():
    assert 'CWE-643' in cwes("import elementpath\nfrom flask import request\nelementpath.select(None,request.args['query'])")
    assert not cwes("import elementpath\nfrom flask import request\nelementpath.select(None,'/item[@id=$v]',variables={'v':request.args['id']})")


@pytest.mark.parametrize('escaped', [False, True])
def test_ldap_filter_escaping(escaped):
    value = "escape_filter_chars(request.args['name'])" if escaped else "request.args['name']"
    code = f'''import ldap3
from ldap3.utils.conv import escape_filter_chars
from flask import request
c=ldap3.Connection(None)
v={value}
c.search('dc=example','(uid='+v+')')
'''
    assert ('CWE-90' in cwes(code)) != escaped


@pytest.mark.parametrize('secure,expected', [('False',True), ('True',False)])
def test_cookie_transport_setting(secure,expected):
    code = f"from flask import make_response\nr=make_response('ok')\nr.set_cookie('session','value',secure={secure})"
    assert ('CWE-614' in cwes(code)) == expected


@pytest.mark.parametrize('expression,expected', [
    ('f"/item[@id=\'{v}\']"', False),
    ('f\'/item[@id="{v}"]\'', True),
    ('v', True),
    ('f"/item[{v}]"', True),
])
def test_xpath_quote_guard_is_context_specific(expression, expected):
    code = f'''from flask import request
import elementpath,os
v=request.args['id']
if "'" in v:
 raise ValueError()
query={expression}
elementpath.select(None,query)
os.system(v)
'''
    assert ('CWE-643' in cwes(code)) == expected
    assert 'CWE-78' in cwes(code)


def test_xpath_quote_replacement_and_ablations():
    code = '''from flask import request
import elementpath
v=request.args['id'].replace("'", "&apos;")
elementpath.select(None,f"/item[@id='{v}']")
'''
    assert not cwes(code)
    assert analyze_python('service.py',code,disabled_features=['sanitizers'])
    assert 'CWE-643' in cwes(code.replace('.replace("\'", "&apos;")', '.replace("\'", "&apos;", 1)'))


@pytest.mark.parametrize('arguments,expected', [
    ("['sh','-c',v]", True), ("['echo',v]", False),
    ("['sh','-c','echo fixed',v]", False),
    ("['python','-c',v]", False),
])
def test_explicit_shell_command_position(arguments, expected):
    code = f'from flask import request\nimport subprocess\nv=request.args["x"]\nsubprocess.run({arguments},shell=False)'
    assert ('CWE-78' in cwes(code)) == expected


def test_explicit_shell_list_survives_platform_branch():
    code = '''from flask import request
import subprocess,os
args=[]
if os.name == 'nt':
 args.append('cmd.exe')
 args.append('/c')
else:
 args.append('sh')
 args.append('-c')
args.append(request.args['cmd'])
subprocess.run(args)
'''
    assert 'CWE-78' in cwes(code)


def test_imported_instance_receiver_resolves_in_caller_scope():
    files = {'entry.py': '''from flask import request
from wrapper import Wrapper
import os
w=Wrapper(request)
os.system(w.value())''', 'wrapper.py': '''class Wrapper:
 def __init__(self,req):
  self.req=req
 def value(self):
  return self.req.args.get('cmd')'''}
    findings = analyze_python('entry.py',files['entry.py'],project=PythonProject(files))
    assert any(f.cwe == 'CWE-78' and f.trace[0]['file_path'] == 'wrapper.py' for f in findings)
    assert not analyze_python('entry.py',files['entry.py'],project=PythonProject(files),disabled_features=['local_imports'])


def test_xpath_query_captures_value_before_later_overwrite():
    code = '''from flask import request
import elementpath
v=request.args['id']
query=f"/item[@id='{v}']"
v='fixed'
elementpath.select(None,query)
'''
    assert 'CWE-643' in cwes(code)
    assert 'CWE-643' in cwes(code.replace("v='fixed'", "v=v.replace(\"'\",'')"))


def test_xpath_repr_can_introduce_its_own_quotes():
    code = '''from flask import request
import elementpath
v=request.args['id'].replace("'",'')
query=f"/item[@id='{v!r}']"
elementpath.select(None,query)
'''
    assert 'CWE-643' in cwes(code)


def test_random_prefix_does_not_hide_external_command_input():
    assert 'CWE-78' in cwes('from flask import request\nimport os,random\nos.system(str(random.random())+request.args["cmd"])')


def test_dynamic_session_key_does_not_pollute_call_state():
    code = '''from flask import request,session
def helper(x):
 return x
key=request.args['key']
session[key]='value'
helper('fixed')
'''
    assert 'CWE-501' in cwes(code)
