"""Original static controls for ASGI, callback and tuple propagation."""
import pytest

from scanner.python_analysis import analyze_python
from scanner.python_project import PythonProject


def paths(code,**kwargs):
    return [f for f in analyze_python('app.py',code,**kwargs) if f.cwe=='CWE-22']


@pytest.mark.parametrize('field',['path','raw_path','query_string','headers'])
def test_typed_scope_fields_are_input(field):
    assert paths(f'from starlette.types import Scope\nfrom starlette.responses import FileResponse\ndef app(scope:Scope):\n return FileResponse(scope["{field}"])')


@pytest.mark.parametrize('code',[
 'from starlette.responses import FileResponse\ndef app(scope):\n return FileResponse(scope["path"])',
 'from custom import Scope\nfrom starlette.responses import FileResponse\ndef app(scope:Scope):\n return FileResponse(scope["path"])',
 'from starlette.types import Scope\nfrom starlette.responses import FileResponse\ndef app(scope:Scope):\n return FileResponse(scope["method"])',
 'from starlette.types import Scope\nfrom starlette.responses import FileResponse\ndef app(scope:Scope):\n scope["path"]="/srv/fixed"\n return FileResponse(scope["path"])',
])
def test_scope_names_and_clean_fields_are_not_guessed(code):
    assert not paths(code)


@pytest.mark.parametrize('wrapper',['anyio.to_thread.run_sync','asyncio.to_thread'])
def test_callback_return_tuple_keeps_slot_identity(wrapper):
    code=f'''import anyio,asyncio
from starlette.types import Scope
from starlette.responses import FileResponse
def lookup(value):
 return value, 'fixed'
async def app(scope:Scope):
 path, metadata = await {wrapper}(lookup,scope['path'])
 FileResponse(path)
 FileResponse(metadata)
'''
    fs=paths(code)
    assert len(fs)==1 and fs[0].line_number==8
    assert fs[0].trace[0]['line_number']==7
    assert not paths(code,disabled_features=['interprocedural'])


def test_callback_statement_visits_the_sink_even_without_return_use():
    code='import anyio\nfrom starlette.types import Scope\nfrom starlette.responses import FileResponse\ndef send(p):\n FileResponse(p)\nasync def app(scope:Scope):\n await anyio.to_thread.run_sync(send,scope["path"])'
    assert paths(code)


def test_unknown_thread_wrapper_is_not_invoked_as_known_api():
    code='from custom import to_thread\nfrom starlette.types import Scope\nfrom starlette.responses import FileResponse\ndef send(p):\n FileResponse(p)\nasync def app(scope:Scope):\n await to_thread(send,scope["path"])'
    assert not paths(code)


@pytest.mark.parametrize('boundary,expected',[('commonprefix',True),('commonpath',False)])
def test_path_guard_survives_callback_and_tuple(boundary,expected):
    code=f'''import os,anyio
from starlette.types import Scope
from starlette.responses import FileResponse
class App:
 def lookup(self,value):
  candidate=os.path.realpath(os.path.join('/srv/files',value))
  if os.path.{boundary}([candidate,'/srv/files']) != '/srv/files':
   raise ValueError()
  return candidate,None
 async def __call__(self,scope:Scope):
  path,meta=await anyio.to_thread.run_sync(self.lookup,scope['path'])
  return FileResponse(path)
'''
    assert bool(paths(code))==expected


def test_imported_tuple_source_keeps_source_file():
    files={'app.py':'from helper import lookup\nfrom starlette.types import Scope\nfrom starlette.responses import FileResponse\ndef app(scope:Scope):\n p,m=lookup(scope["path"])\n FileResponse(p)\n FileResponse(m)',
           'helper.py':'def lookup(p):\n return p,"fixed"'}
    fs=paths(files['app.py'],project=PythonProject(files))
    assert len(fs)==1 and fs[0].trace[0]['file_path']=='app.py'


def test_starred_path_segments_preserve_input():
    code='import os\nfrom starlette.types import Scope\nfrom starlette.responses import FileResponse\ndef app(scope:Scope):\n FileResponse(os.path.join(*scope["path"].split("/")))'
    assert paths(code)


def test_tuple_forwarding_and_mixed_guarded_returns():
    code='''import os
from starlette.types import Scope
from starlette.responses import FileResponse
def pair(p,flag):
 if flag:
  fixed=os.path.realpath(os.path.join('/srv',p))
  if os.path.commonpath([fixed,'/srv']) != '/srv':
   raise ValueError()
  return fixed,None
 return p,None
def forward(p,flag):
 return pair(p,flag)
def app(scope:Scope):
 p,m=forward(scope['path'],scope.get('flag'))
 FileResponse(p)
 FileResponse(m)
'''
    assert len(paths(code))==1


def test_unresolved_tuple_shape_keeps_an_explicit_coverage_notice():
    fs=analyze_python('app.py','import json\na,b=json.loads(input())')
    assert any(f.rule_id=='PY-TUPLE-001' and f.evidence_kind=='coverage-notice' for f in fs)


def test_direct_library_sink_callback_is_analyzed():
    code='import anyio\nfrom starlette.types import Scope\nfrom starlette.responses import FileResponse\nasync def app(scope:Scope):\n await anyio.to_thread.run_sync(FileResponse,scope["path"])'
    assert len(paths(code))==1


def test_transparent_callback_return_keeps_input():
    code='import asyncio\nfrom starlette.types import Scope\nfrom starlette.responses import FileResponse\nasync def app(scope:Scope):\n p=await asyncio.to_thread(str,scope["path"])\n FileResponse(p)'
    assert len(paths(code))==1


def test_callback_scheduler_keywords_do_not_become_function_arguments():
    code='import anyio\nfrom starlette.types import Scope\nfrom starlette.responses import FileResponse\ndef fixed():\n return "/srv/fixed",None\nasync def app(scope:Scope):\n p,m=await anyio.to_thread.run_sync(fixed,limiter=scope["path"])\n FileResponse(p)'
    assert not paths(code)


def test_async_callback_is_not_mistaken_for_thread_execution():
    code='import anyio\nfrom starlette.types import Scope\nfrom starlette.responses import FileResponse\nasync def callback(p):\n FileResponse(p)\nasync def app(scope:Scope):\n await anyio.to_thread.run_sync(callback,scope["path"])'
    fs=analyze_python('app.py',code)
    assert not any(f.cwe=='CWE-22' for f in fs)
    assert any(f.rule_id=='PY-CALLBACK-001' for f in fs)
