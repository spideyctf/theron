"""Original static fixture shared by backend/export/frontend checks."""
from tests.test_correlation import sample

CODE='''import os,anyio,tarfile,io
from starlette.types import Scope
from starlette.responses import FileResponse
from flask import request
def lookup(value):
 candidate=os.path.realpath(os.path.join('/srv/files',value))
 if os.path.commonprefix([candidate,'/srv/files']) != '/srv/files':
  raise ValueError()
 return candidate,None
async def application(scope:Scope):
 path,metadata=await anyio.to_thread.run_sync(lookup,scope['path'])
 return FileResponse(path)
def upload_archive():
 t=tarfile.open(fileobj=io.BytesIO(request.get_data()))
 t.extractall('/srv/uploads',filter='fully_trusted')
def review_archive():
 with tarfile.open('legacy.tar') as archive:
  archive.extractall('/srv/review')
'''


def build():
    return sample(code=CODE)
