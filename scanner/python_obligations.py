"""Bounded security obligations for resolved APIs. Target code is never executed."""
import ast
from dataclasses import dataclass, field

from scanner.models import Finding, Category, Severity
from scanner.utils.helpers import redact_secrets

DRF_REFERENCE='https://www.django-rest-framework.org/api-guide/permissions/#object-level-permissions'
JWT_REFERENCE='https://pyjwt.readthedocs.io/en/stable/api.html#jwt.decode'
HTTP_REFERENCE='https://www.rfc-editor.org/rfc/rfc9112.html#section-7.1'


def obligation(domain, required, observed, path, node, assumptions=()):
    return dict(domain=domain,required=required,observed=observed,
                action=dict(file_path=path,line_number=node.lineno),assumptions=list(assumptions))


def check_crypto_call(analyzer,node):
    name=analyzer._name(node.func)
    if name not in {'jwt.decode','jwt.api_jwt.decode','jwt.PyJWT.decode','jose.jwt.decode','jose.jws.verify'}:
        return
    def argument(keyword,index):
        return next((k.value for k in node.keywords if k.arg==keyword),node.args[index] if len(node.args)>index else None)
    def literal(value):
        if isinstance(value,ast.Name):
            value=analyzer.literal_sets.get(value.id,value)
        return value
    algorithms=argument('algorithms',2)
    options=literal(argument('options',3) if name!='jose.jws.verify' else None)
    def emit(rule,title,observed,cwe='CWE-347',source=None):
        analyzer._add(node,rule,title,Severity.HIGH if source else Severity.MEDIUM,Category.SAST,
            observed+' Application authentication use and runtime library behavior require validation.',
            'Verify signatures using a fixed, compatible algorithm/key configuration; keep unverified decoding separate from trusted claims.',
            cwe,confidence='medium',maturity='advisory',evidence_kind='static-obligation',
            source_line=source[1] if source else None,source_file=source[3] if source and len(source)>3 else None,
            obligation=obligation('crypto','Bind signature verification to a trusted algorithm and compatible key.',observed,
                                  analyzer.file_path,node,['A decode/verify call is not itself proof that its claims are used for authentication.']))
    if isinstance(options,ast.Dict) and all(k is not None for k in options.keys):
        settings={analyzer._constant(k):v for k,v in zip(options.keys,options.values) if k is not None}
        value=settings.get('verify_signature')
        if value is not None and analyzer._constant(value) is False:
            emit('PY-OBL-JWT-VERIFY-001','JWT signature verification is explicitly disabled',
                 'The resolved JWT decoder explicitly sets verify_signature=False.')
    selection_source=analyzer._source(algorithms)
    if selection_source and selection_source[0] in {'input','model'}:
        emit('PY-OBL-JWT-ALG-001','Untrusted data selects JWT verification algorithms',
             'Observed untrusted content reaches the algorithms argument.',source=selection_source)
        return
    values=literal(algorithms)
    if not isinstance(values,(ast.List,ast.Tuple,ast.Set)):
        return  # Missing/unknown algorithms can raise or be constrained by a JWK; do not guess.
    names=[analyzer._constant(v) for v in values.elts]
    if not names or not all(isinstance(v,str) for v in names):
        return
    hmac=any(n in {'HS256','HS384','HS512'} for n in names)
    asymmetric=any(n.startswith(('RS','PS','ES')) or n=='EdDSA' for n in names)
    key=argument('key',1)
    material=analyzer._constant(key)
    if isinstance(material,ast.AST):
        material=None
    if isinstance(key,ast.Constant) and isinstance(key.value,bytes):
        material=key.value.decode('ascii',errors='replace')
    public=(isinstance(material,str) and material.lstrip().startswith((
        '-----BEGIN PUBLIC KEY-----','-----BEGIN RSA PUBLIC KEY-----','-----BEGIN CERTIFICATE-----',
        'ssh-rsa ','ssh-ed25519 ','ecdsa-sha2-')))
    public=public or analyzer._name(key) in {'cryptography.PublicKey','cryptography.SerializedPublicKey'}
    if isinstance(key,ast.Call):
        public=public or analyzer._name(key.func) in {
            'cryptography.hazmat.primitives.serialization.load_pem_public_key',
            'cryptography.hazmat.primitives.serialization.load_ssh_public_key',
            'cryptography.hazmat.primitives.serialization.load_der_public_key'}
    if hmac and public:
        emit('PY-OBL-JWT-KEY-001','Asymmetric public-key material reaches HMAC verification',
             'A known public-key representation is supplied while HMAC verification is allowed. Modern libraries may reject it; acceptance is not assumed.')
    elif hmac and asymmetric:
        emit('PY-OBL-JWT-MIX-001','JWT allowlist mixes incompatible key families',
             'One key argument is paired with both symmetric and asymmetric algorithm families. Key interpretation and library rejection behavior are unverified.')


@dataclass(frozen=True)
class Value:
    kind: str
    token: tuple
    line: int


@dataclass
class State:
    values: dict=field(default_factory=dict)
    checked: set=field(default_factory=set)
    uncertain: bool=False
    checks: list=field(default_factory=list)

    def copy(self):
        return State(self.values.copy(),self.checked.copy(),self.uncertain,self.checks.copy())


class BoundedPaths:
    """Explore small statement paths; unknown loops/exception paths retain uncertainty."""
    def __init__(self,domain):
        self.domain=domain
        self.steps=0

    def walk(self,statements,states):
        for node in statements:
            following=[]
            for state in states:
                self.steps+=1
                if self.steps>2048:
                    raise OverflowError('obligation path budget')
                if isinstance(node,ast.If):
                    constant=node.test.value if isinstance(node.test,ast.Constant) else None
                    for truth,body in [(True,node.body),(False,node.orelse)]:
                        if constant is not None and bool(constant)!=truth:
                            continue
                        branch=state.copy()
                        self.domain.condition(node.test,truth,branch)
                        following.extend(self.walk(body,[branch]))
                elif isinstance(node,ast.Return):
                    self.domain.returned(node,state)
                elif isinstance(node,ast.Raise):
                    continue
                elif isinstance(node,(ast.For,ast.AsyncFor,ast.While)):
                    branch=state.copy(); branch.uncertain=True
                    following.append(branch.copy())
                    following.extend(self.walk(node.body,[branch]))
                elif isinstance(node,(ast.Try,getattr(ast,'TryStar',ast.Try))):
                    branch=state.copy(); branch.uncertain=True
                    normal=self.walk(node.body,[state.copy()])
                    normal=self.walk(node.orelse,normal)
                    for handler in node.handlers:
                        normal.extend(self.walk(handler.body,[branch.copy()]))
                    following.extend(self.walk(node.finalbody,normal))
                elif isinstance(node,(ast.With,ast.AsyncWith)):
                    following.extend(self.walk(node.body,[state]))
                elif isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                    following.append(state)
                else:
                    self.domain.statement(node,state)
                    following.append(state)
            unique={}
            for branch in following:
                key=(tuple(sorted(branch.values.items())),frozenset(branch.checked),branch.uncertain,tuple(branch.checks))
                unique.setdefault(key,branch)
            following=list(unique.values())
            if len(following)>32:
                raise OverflowError('obligation path budget')
            states=following
        return states


class Context:
    def __init__(self,path,content,tree,project,module):
        self.path,self.content,self.tree,self.module=path,content,tree,module
        self.classes=dict(project.class_definitions) if project else {}
        self.bindings={}
        for node in tree.body:
            if isinstance(node,ast.Import):
                for alias in node.names:
                    self.bindings[alias.asname or alias.name.split('.')[0]]=alias.name if alias.asname else alias.name.split('.')[0]
            elif isinstance(node,ast.ImportFrom):
                if project:
                    root=project.import_module(path,node.module,node.level)
                elif node.level:
                    from scanner.python_project import PythonProject
                    parts=PythonProject.module_name(path).split('.')
                    package=parts if path.endswith('/__init__.py') else parts[:-1]
                    root='.'.join(package[:len(package)-node.level+1]+([node.module] if node.module else []))
                else:root=node.module or ''
                for alias in node.names:
                    self.bindings[alias.asname or alias.name]=root+'.'+alias.name
            elif isinstance(node,ast.ClassDef):
                self.bindings[node.name]=node.name
                self.classes[node.name]=(path,node,self.bindings)
            elif isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                self.bindings[node.name]=''
            elif isinstance(node,(ast.Assign,ast.AnnAssign)):
                for target in node.targets if isinstance(node,ast.Assign) else [node.target]:
                    if isinstance(target,ast.Name):self.bindings[target.id]=''
        self.findings=[]

    def resolve(self,node,bindings=None):
        bindings=self.bindings if bindings is None else bindings
        if isinstance(node,ast.Name):return bindings.get(node.id,'')
        if isinstance(node,ast.Attribute):
            root=self.resolve(node.value,bindings)
            return root+'.'+node.attr if root else ''
        return ''

    def inherits(self,name,roots,seen=None):
        if name in roots:return True
        seen=set() if seen is None else seen
        if name in seen or name not in self.classes:return False
        seen.add(name)
        _,node,bindings=self.classes[name]
        return any(self.inherits(self.resolve(base,bindings),roots,seen) for base in node.bases)

    def attribute(self,name,attribute,seen=None):
        seen=set() if seen is None else seen
        if name in seen or name not in self.classes:return None
        seen.add(name)
        path,node,bindings=self.classes[name]
        for item in node.body:
            if isinstance(item,(ast.FunctionDef,ast.AsyncFunctionDef)) and item.name==attribute:
                return path,item,bindings
            if isinstance(item,(ast.Assign,ast.AnnAssign)):
                targets=item.targets if isinstance(item,ast.Assign) else [item.target]
                if any(isinstance(t,ast.Name) and t.id==attribute for t in targets):return path,item.value,bindings
        for base in node.bases:
            value=self.attribute(self.resolve(base,bindings),attribute,seen)
            if value is not None:return value
        return None

    def emit(self,node,rule,title,domain,required,observed,cwe,assumptions=(),uncertain=False,related_locations=()):
        reference={'authorization':DRF_REFERENCE,'protocol':HTTP_REFERENCE,'crypto':'https://jwcrypto.readthedocs.io/en/latest/jws.html'}[domain]
        snippet='\n'.join(self.content.splitlines()[max(0,node.lineno-1):node.end_lineno])
        self.findings.append(Finding(title=title,severity=Severity.INFO if uncertain else Severity.MEDIUM,
            category=Category.SAST,module='coverage' if uncertain else self.module,file_path=self.path,line_number=node.lineno,
            description=observed+' This is bounded static evidence, not verified deployment exploitability.',
            recommendation=required,cwe=None if uncertain else cwe,confidence='medium',maturity='advisory',
            evidence_kind='coverage-notice' if uncertain else 'static-obligation',code_snippet=redact_secrets(snippet),
            rule_id=rule+'-REVIEW' if uncertain else rule,references=[reference],
            obligation={**obligation(domain,required,observed,self.path,node,assumptions),
                        'related_locations':list(related_locations)}))


class ObjectPermissions:
    GENERICS={'rest_framework.generics.'+name for name in ['GenericAPIView','RetrieveAPIView','UpdateAPIView','DestroyAPIView',
        'RetrieveUpdateAPIView','RetrieveDestroyAPIView','RetrieveUpdateDestroyAPIView']}
    GENERICS|={'rest_framework.viewsets.'+name for name in ['GenericViewSet','ModelViewSet','ReadOnlyModelViewSet']}

    def __init__(self,context,view,method):
        self.context,self.view,self.method=context,view,method
        self.receiver=method.args.args[0].arg if method.args.args else 'self'
        self.request=method.args.args[1].arg if len(method.args.args)>1 else None

    def value(self,node,state):
        if isinstance(node,ast.Name):return state.values.get(node.id)
        if isinstance(node,ast.Attribute):
            if isinstance(node.value,ast.Name) and node.value.id==self.receiver and self.receiver not in state.values:
                key=self.receiver+'.'+node.attr
                if key in state.values:return state.values[key]
                if node.attr=='request':return Value('request',('request',),node.lineno)
                if node.attr=='queryset' and self.context.attribute(self.view,'queryset'):
                    return Value('queryset',('queryset',),node.lineno)
                if node.attr=='check_object_permissions':return Value('checker',('checker',),node.lineno)
            parent=self.value(node.value,state)
            if parent and parent.kind=='unresolved-object':return parent
            if parent and parent.kind in {'object','serializer','projection'}:
                return Value('projection',parent.token,parent.line)
        if isinstance(node,ast.Call):
            name=self.context.resolve(node.func)
            if name in {'django.shortcuts.get_object_or_404','rest_framework.generics.get_object_or_404'}:
                queryset=self.value(node.args[0],state) if node.args else None
                return Value('object' if queryset and queryset.kind=='queryset' else 'unresolved-object',
                             ('object',node.lineno,node.col_offset),node.lineno)
            if isinstance(node.func,ast.Attribute):
                own=isinstance(node.func.value,ast.Name) and node.func.value.id==self.receiver and self.receiver not in state.values
                if own and node.func.attr=='get_queryset':return Value('queryset',('queryset',node.lineno),node.lineno)
                if own and node.func.attr=='get_object' and self.context.attribute(self.view,'get_object') is None:
                    value=Value('object',('object',node.lineno,node.col_offset),node.lineno)
                    state.checked.add(value.token); return value
                if own and node.func.attr=='get_serializer':
                    argument=node.args[0] if node.args else next((k.value for k in node.keywords if k.arg=='instance'),None)
                    value=self.value(argument,state)
                    if value:return Value('unresolved-object' if value.kind=='unresolved-object' else 'serializer',value.token,value.line)
                parent=self.value(node.func.value,state)
                if parent and parent.kind=='queryset' and node.func.attr=='get':
                    return Value('object',('object',node.lineno,node.col_offset),node.lineno)
                if parent and parent.kind=='queryset' and node.func.attr in {'filter','all','select_related','prefetch_related'}:
                    return parent
            if name in {'rest_framework.response.Response','django.http.JsonResponse'}:
                argument=node.args[0] if node.args else next((k.value for k in node.keywords if k.arg=='data'),None)
                return self.value(argument,state)
        return None

    def statement(self,node,state):
        if isinstance(node,(ast.Assign,ast.AnnAssign)):
            value=self.value(node.value,state)
            for target in node.targets if isinstance(node,ast.Assign) else [node.target]:
                key=target.id if isinstance(target,ast.Name) else ast.unparse(target)
                if value:state.values[key]=value
                else:state.values[key]=None
        elif isinstance(node,ast.Expr) and isinstance(node.value,ast.Call):
            call=node.value
            checker=self.value(call.func,state)
            if checker and checker.kind=='checker' and len(call.args)<=2 and all(k.arg in {'request','obj'} for k in call.keywords):
                request_node=next((k.value for k in call.keywords if k.arg=='request'),call.args[0] if call.args else None)
                object_node=next((k.value for k in call.keywords if k.arg=='obj'),call.args[1] if len(call.args)>1 else None)
                request,value=self.value(request_node,state),self.value(object_node,state)
                state.checks.append((call.lineno,value.token if value else None,bool(request and request.kind=='request')))
                if request and request.kind=='request' and value and value.kind=='object':
                    state.checked.add(value.token)
            elif isinstance(call.func,ast.Attribute) and isinstance(call.func.value,ast.Name) and call.func.value.id==self.receiver:
                if self.context.attribute(self.view,call.func.attr) is not None:
                    state.uncertain=True  # An unresolved local helper may perform authorization.

    def condition(self,node,truth,state):
        pass

    @staticmethod
    def may_deny(hook,methods,context,bindings):
        """Exclude policies proved to allow all of this view's supported HTTP methods."""
        parameters=hook.args.posonlyargs+hook.args.args
        request=parameters[1].arg if len(parameters)>1 else None
        def literal(node,method):
            if isinstance(node,ast.Constant):return node.value
            if isinstance(node,ast.Attribute) and isinstance(node.value,ast.Name) and node.value.id==request and node.attr=='method':return method
            if context.resolve(node,bindings)=='rest_framework.permissions.SAFE_METHODS':return ('GET','HEAD','OPTIONS')
            if isinstance(node,(ast.Tuple,ast.List,ast.Set)):
                values=[literal(v,method) for v in node.elts]
                return tuple(values) if all(v is not None for v in values) else None
            if isinstance(node,ast.UnaryOp) and isinstance(node.op,ast.Not):
                v=literal(node.operand,method); return not v if v is not None else None
            if isinstance(node,ast.BoolOp):
                values=[literal(v,method) for v in node.values]
                if isinstance(node.op,ast.Or) and any(v is True for v in values):return True
                if isinstance(node.op,ast.And) and any(v is False for v in values):return False
                if all(v is not None for v in values):return all(values) if isinstance(node.op,ast.And) else any(values)
            if isinstance(node,ast.Compare) and len(node.ops)==len(node.comparators)==1:
                left,right=literal(node.left,method),literal(node.comparators[0],method)
                if left is not None and right is not None:
                    if isinstance(node.ops[0],ast.Eq):return left==right
                    if isinstance(node.ops[0],ast.NotEq):return left!=right
                    if isinstance(node.ops[0],(ast.In,ast.NotIn)) and isinstance(right,(tuple,str)):
                        return (left in right)==isinstance(node.ops[0],ast.In)
            return None
        def allowed(block,method):
            if not block:return False
            first,rest=block[0],block[1:]
            if isinstance(first,ast.Return):return literal(first.value,method) is True
            if isinstance(first,ast.Raise):return False
            if isinstance(first,ast.If):
                condition=literal(first.test,method)
                if condition is not None:return allowed((first.body if condition else first.orelse)+rest,method)
                return allowed(first.body+rest,method) and allowed(first.orelse+rest,method)
            if isinstance(first,ast.Expr) and isinstance(first.value,ast.Constant) and isinstance(first.value.value,str):return allowed(rest,method)
            return False
        return any(not allowed(hook.body,method) for method in methods)

    @classmethod
    def methods(cls,context,view,method):
        if method.name!='get_object':
            for d in method.decorator_list:
                if isinstance(d,ast.Call) and context.resolve(d.func)=='rest_framework.decorators.action':
                    value=next((k.value for k in d.keywords if k.arg=='methods'),None)
                    if value is None:return {'GET'}
                    if isinstance(value,(ast.List,ast.Tuple)) and all(isinstance(v,ast.Constant) and isinstance(v.value,str) for v in value.elts):return {v.value.upper() for v in value.elts}
        names=context.attribute(view,'http_method_names')
        if names and isinstance(names[1],(ast.List,ast.Tuple)) and all(isinstance(v,ast.Constant) and isinstance(v.value,str) for v in names[1].elts):return {v.value.upper() for v in names[1].elts}
        read={'rest_framework.generics.RetrieveAPIView','rest_framework.viewsets.ReadOnlyModelViewSet'}
        if context.inherits(view,read):return {'GET','HEAD','OPTIONS'}
        return {'GET','HEAD','OPTIONS','PUT','PATCH','DELETE','POST'}

    def returned(self,node,state):
        value=self.value(node.value,state)
        if value and value.kind in {'object','projection','serializer'} and value.token not in state.checked:
            policy=self.context.attribute(self.view,'permission_classes')
            locations=[dict(role='lookup',file_path=self.context.path,line_number=value.line)]
            if policy:locations.append(dict(role='policy',file_path=policy[0],line_number=policy[1].lineno))
            locations.extend(dict(role='check',file_path=self.context.path,line_number=line,
                matches_returned_object=token==value.token,matches_subject=subject) for line,token,subject in state.checks)
            self.context.emit(node,'PY-OBL-AUTH-001','Declared object permission check is missing on a return path',
                'authorization','Check the same requested object using the declared object-permission policy before exposing it.',
                'A DRF view with an identifiable object-level policy returns lookup-derived data without an observed check on that object.',
                'CWE-863',['Queryset filtering, alternate checks and deployment reachability may affect actual exposure.'],state.uncertain,locations)
        elif (value and value.kind=='unresolved-object') or (value is None and self.method.name=='get_object' and not (isinstance(node.value,ast.Constant) and node.value.value is None)):
            self.context.emit(node,'PY-OBL-AUTH-001','Returned object identity cannot be resolved',
                'authorization','Resolve the returned object and authorization helper before classifying this path.',
                'The declared object policy is known, but this return expression or helper is unsupported.',None,uncertain=True)

    @classmethod
    def analyze(cls,context):
        for node in context.tree.body:
            if not isinstance(node,ast.ClassDef) or not context.inherits(node.name,cls.GENERICS):continue
            policy=context.attribute(node.name,'permission_classes')
            methods=[n for n in node.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and (
                n.name=='get_object' or any(isinstance(d,ast.Call) and context.resolve(d.func)=='rest_framework.decorators.action'
                    and any(k.arg=='detail' and isinstance(k.value,ast.Constant) and k.value.value is True for k in d.keywords) for d in n.decorator_list))]
            if not methods:continue
            for method in methods:
                known,unknown=False,False
                http_methods=cls.methods(context,node.name,method)
                if policy is None or not isinstance(policy[1],(ast.List,ast.Tuple)):unknown=True
                else:
                    for p in policy[1].elts:
                        name=context.resolve(p,policy[2])
                        if name=='rest_framework.permissions.DjangoObjectPermissions':
                            known=known or bool(http_methods & {'POST','PUT','PATCH','DELETE'})
                        elif name in {'rest_framework.permissions.'+n for n in ['AllowAny','IsAuthenticated','IsAdminUser','IsAuthenticatedOrReadOnly','DjangoModelPermissions']}:continue
                        elif context.inherits(name,{'rest_framework.permissions.BasePermission'}):
                            hook=context.attribute(name,'has_object_permission')
                            if hook:
                                if isinstance(hook[1],ast.AsyncFunctionDef):unknown=True
                                elif cls.may_deny(hook[1],http_methods,context,hook[2]):known=True
                        else:unknown=True
                if context.attribute(node.name,'get_permissions') or context.attribute(node.name,'check_object_permissions'):
                    known,unknown=False,True
                if isinstance(method,ast.AsyncFunctionDef):
                    context.emit(method,'PY-OBL-AUTH-001','Async object-permission override requires review',
                        'authorization','Verify the async framework and permission-hook contract.',
                        'This check models synchronous DRF object-permission hooks; async behavior is unsupported.',None,uncertain=True)
                    continue
                if not known:
                    if unknown:context.emit(method,'PY-OBL-AUTH-001','Object permission policy cannot be resolved',
                        'authorization','Resolve the effective object-permission policy before classifying this override.',
                        'The DRF object lookup/action policy is missing, dynamic or unsupported.',None,uncertain=True)
                    continue
                domain=cls(context,node.name,method)
                initial=State()
                if domain.request:initial.values[domain.request]=Value('request',('request',),method.lineno)
                try:BoundedPaths(domain).walk(method.body,[initial])
                except OverflowError:context.emit(method,'PY-OBL-AUTH-001','Object permission path budget reached',
                    'authorization','Review paths outside the bounded analysis.', 'Object-permission path analysis is incomplete.',None,uncertain=True)


class ChunkFooter:
    def __init__(self,context,method,fields,buffers):
        self.context,self.method,self.fields,self.buffers=context,method,fields,buffers

    def field(self,node):
        return node.attr if isinstance(node,ast.Attribute) and isinstance(node.value,ast.Name) and node.value.id==self.method.args.args[0].arg else None

    def read(self,node):
        if not (isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name)
                and node.func.value.id in self.buffers and node.func.attr=='maybe_extract_at_most' and len(node.args)==1):return None
        count=node.args[0]
        if isinstance(count,ast.Call) and isinstance(count.func,ast.Name) and count.func.id=='len' and len(count.args)==1:count=count.args[0]
        key=self.field(count)
        if key in self.fields:return Value('footer',(key,node.lineno,node.col_offset),node.lineno)
        return None

    def builtin_len(self,node,state):
        return (isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='len'
                and 'len' not in self.context.bindings and 'len' not in state.values and len(node.args)==1)

    def value(self,node,state):
        if isinstance(node,ast.Name):return state.values.get(node.id)
        return self.read(node)

    def condition(self,node,truth,state):
        if isinstance(node,ast.UnaryOp) and isinstance(node.op,ast.Not):
            return self.condition(node.operand,not truth,state)
        if not (isinstance(node,ast.Compare) and len(node.ops)==len(node.comparators)==1):return
        if not ((isinstance(node.ops[0],ast.Eq) and truth) or (isinstance(node.ops[0],ast.NotEq) and not truth)):return
        for data,expected in [(node.left,node.comparators[0]),(node.comparators[0],node.left)]:
            value=self.value(data,state)
            if not value:continue
            full=isinstance(expected,ast.Constant) and expected.value==b'\r\n'
            prefix=(isinstance(expected,ast.Subscript) and self.field(expected.value)==value.token[0]
                    and self.fields[value.token[0]]=='bytes' and isinstance(expected.slice,ast.Slice)
                    and expected.slice.lower is None and expected.slice.step is None
                    and self.builtin_len(expected.slice.upper,state)
                    and self.value(expected.slice.upper.args[0],state)==value)
            if full or prefix:state.checked.add(value.token)

    def statement(self,node,state):
        if isinstance(node,(ast.Assign,ast.AnnAssign)):
            value=self.value(node.value,state)
            targets=node.targets if isinstance(node,ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target,ast.Name):
                    if value:
                        if self.read(node.value):state.checked.discard(value.token)
                        state.values[target.id]=value
                    else:state.values[target.id]=None
                if self.field(target) and isinstance(node.value,ast.Subscript) and isinstance(node.value.slice,ast.Slice):
                    self.advance(node,target,node.value.slice.lower,state)
        elif isinstance(node,ast.AugAssign) and isinstance(node.op,ast.Sub):
            self.advance(node,node.target,node.value,state)

    def advance(self,node,target,amount,state):
        key=self.field(target)
        if key not in self.fields:return
        if not self.builtin_len(amount,state):
            self.context.emit(node,'PY-OBL-HTTP-001','HTTP chunk-state update cannot be resolved',
                'protocol','Resolve the byte-count operation before classifying this parser transition.',
                'The known delimiter state is changed using an unsupported or shadowed length operation.',None,uncertain=True)
            return
        data=self.value(amount.args[0],state)
        if data is None:
            self.context.emit(node,'PY-OBL-HTTP-001','HTTP footer byte provenance cannot be resolved',
                'protocol','Resolve the byte transformations and validation before classifying this transition.',
                'A known delimiter state advances using bytes not tracked by the supported receive-buffer model.',None,uncertain=True)
            return
        if data and data.token[0]==key and data.token not in state.checked:
            self.context.emit(node,'PY-OBL-HTTP-001','HTTP chunk footer is consumed without an observed byte check',
                'protocol','Validate the exact CRLF footer, including fragmented prefixes, before advancing parser state.',
                'A resolved h11 receive-buffer read supplies footer bytes whose length advances a two-byte chunk delimiter state without an observed content check.',
                'CWE-444',['The h11 receive-buffer and chunk-event contracts identify this as HTTP/1.1 chunk framing.'],state.uncertain,
                [dict(role='read',file_path=self.context.path,line_number=data.line)])

    def returned(self,node,state):
        pass

    @classmethod
    def analyze(cls,context):
        for node in context.tree.body:
            if not isinstance(node,ast.ClassDef):continue
            chunk_events=[n for n in ast.walk(node) if isinstance(n,ast.Call) and context.resolve(n.func)=='h11._events.Data'
                          and any(k.arg in {'chunk_start','chunk_end'} for k in n.keywords)]
            if not chunk_events:continue
            assignments={}
            for n in ast.walk(node):
                if isinstance(n,(ast.Assign,ast.AnnAssign)):
                    for t in n.targets if isinstance(n,ast.Assign) else [n.target]:
                        if isinstance(t,ast.Attribute) and isinstance(t.value,ast.Name) and t.value.id=='self':
                            assignments.setdefault(t.attr,[]).append(n.value)
            fields={}
            for name,values in assignments.items():
                if all(isinstance(v,ast.Constant) and type(v.value) is int and v.value in {0,2} for v in values) and any(v.value==2 for v in values):fields[name]='count'
                elif all(isinstance(v,ast.Constant) and isinstance(v.value,bytes) and v.value in {b'',b'\r\n'}
                         or isinstance(v,ast.Subscript) and isinstance(v.value,ast.Attribute) and isinstance(v.value.value,ast.Name)
                         and v.value.value.id=='self' and v.value.attr==name and isinstance(v.slice,ast.Slice)
                         and v.slice.step is None and v.slice.upper is None and isinstance(v.slice.lower,ast.Call)
                         and isinstance(v.slice.lower.func,ast.Name) and v.slice.lower.func.id=='len'
                         and len(v.slice.lower.args)==1 for v in values) and any(isinstance(v,ast.Constant) and v.value==b'\r\n' for v in values):fields[name]='bytes'
            for method in node.body:
                if not isinstance(method,(ast.FunctionDef,ast.AsyncFunctionDef)) or not method.args.args:continue
                buffers={a.arg for a in method.args.args if context.resolve(a.annotation)=='h11._receivebuffer.ReceiveBuffer'}
                if not buffers:continue
                try:BoundedPaths(cls(context,method,fields,buffers)).walk(method.body,[State()])
                except OverflowError:context.emit(method,'PY-OBL-HTTP-001','HTTP framing path budget reached',
                    'protocol','Review parser paths outside the bounded analysis.','Chunk framing analysis is incomplete.',None,uncertain=True)


def analyze_structural_obligations(path,content,tree,project,disabled,module):
    context=Context(path,content,tree,project,module)
    if 'auth_obligations' not in disabled:ObjectPermissions.analyze(context)
    if 'protocol_obligations' not in disabled:
        ChunkFooter.analyze(context)
        HTTPGrammar.analyze(context)
    if 'crypto_obligations' not in disabled:
        SignedPayload.analyze(context)
        HMACKeyFormats.analyze(context)
    return context.findings


class SignedPayload:
    """Keep compact-token claims distinct from the payload accepted by a JWS verifier."""
    DECODERS={'json.loads','jwcrypto.common.json_decode','jwcrypto.common.base64url_decode',
              'base64.urlsafe_b64decode','base64.b64decode'}

    def __init__(self,context,method):
        self.context,self.method=context,method
        self.parameters={a.arg for a in method.args.posonlyargs+method.args.args+method.args.kwonlyargs}

    def value(self,node,state):
        if isinstance(node,ast.Name):return state.values.get(node.id)
        if isinstance(node,ast.Attribute) and node.attr=='payload':
            owner=self.value(node.value,state)
            if owner and owner.kind=='jws':
                verified=next((v for v in state.checked if v[:2]==('verified',owner.token)),None)
                if verified:return Value('verified-claims',(owner.token,verified[2]),node.lineno)
        if isinstance(node,ast.Subscript):
            owner=self.value(node.value,state)
            if owner and owner.kind=='segments' and isinstance(node.slice,ast.Constant) and node.slice.value==1:
                return Value('raw-claims',owner.token,node.lineno)
        if not isinstance(node,ast.Call):return None
        name=self.context.resolve(node.func)
        root=node.func
        while isinstance(root,ast.Attribute):root=root.value
        if isinstance(root,ast.Name) and root.id in state.values:name=''
        if name=='jwcrypto.jws.JWS':return Value('jws',(node.lineno,node.col_offset),node.lineno)
        if name in self.DECODERS and node.args:return self.value(node.args[0],state)
        if isinstance(node.func,ast.Attribute) and node.func.attr=='split' and len(node.args)==1 and isinstance(node.args[0],ast.Constant) and node.args[0].value=='.':
            source=self.value(node.func.value,state)
            if source and source.kind=='representation':return Value('segments',source.token,node.lineno)
        return None

    def statement(self,node,state):
        if isinstance(node,(ast.Assign,ast.AnnAssign)):
            value=self.value(node.value,state)
            for target in node.targets if isinstance(node,ast.Assign) else [node.target]:
                if isinstance(target,ast.Name):
                    if value is not None or target.id in state.values or target.id in self.context.bindings:
                        state.values[target.id]=value
                elif isinstance(target,(ast.Tuple,ast.List)):
                    for index,part in enumerate(target.elts):
                        if isinstance(part,ast.Name):
                            state.values[part.id]=(Value('raw-claims',value.token,node.lineno)
                                if value and value.kind=='segments' and len(target.elts)==3 and index==1 else None)
                elif isinstance(target,ast.Attribute):
                    owner=self.value(target.value,state)
                    if owner and owner.kind=='jws' and target.attr in {'payload','deserialize','verify'}:
                        # Replacing a verifier's payload/method invalidates its known contract.
                        state.checked={v for v in state.checked if not (v[0]=='verified' and v[1]==owner.token)}
                        for key,known in list(state.values.items()):
                            if known and known.kind=='jws' and known.token==owner.token:state.values[key]=None
        elif isinstance(node,ast.Expr) and isinstance(node.value,ast.Call):
            call=node.value
            if isinstance(call.func,ast.Attribute) and call.func.attr=='deserialize':
                owner=self.value(call.func.value,state)
                raw=self.value(call.args[0],state) if call.args else None
                key=next((k.value for k in call.keywords if k.arg=='key'),call.args[1] if len(call.args)>1 else None)
                if owner and owner.kind=='jws':
                    state.checked={v for v in state.checked if not (v[0]=='verified' and v[1]==owner.token)}
                if owner and owner.kind=='jws' and raw and raw.kind=='representation' and key is not None:
                    if not (isinstance(key,ast.Constant) and key.value is None):
                        state.checked.add(('verified',owner.token,raw.token))

    def condition(self,node,truth,state):
        if not (isinstance(node,ast.Compare) and len(node.ops)==len(node.comparators)==1):return
        equal=(isinstance(node.ops[0],ast.Eq) and truth) or (isinstance(node.ops[0],ast.NotEq) and not truth)
        if not equal:return
        left,right=self.value(node.left,state),self.value(node.comparators[0],state)
        for raw,bound in [(left,right),(right,left)]:
            if raw and bound and raw.kind=='raw-claims' and bound.kind=='verified-claims' and raw.token==bound.token[1]:
                state.checked.add(('bound',raw.token))

    def returned(self,node,state):
        values=node.value.elts if isinstance(node.value,(ast.Tuple,ast.List)) else [node.value]
        for expression in values:
            value=self.value(expression,state)
            if not value or value.kind!='raw-claims' or ('bound',value.token) in state.checked:continue
            verified=[v for v in state.checked if v[0]=='verified' and v[2]==value.token]
            if not verified:continue
            rule='PY-OBL-JWS-PAYLOAD-001'+('-REVIEW' if state.uncertain else '')
            if any(f.rule_id==rule and f.line_number==node.lineno for f in self.context.findings):continue
            if state.uncertain and any(f.rule_id=='PY-OBL-JWS-PAYLOAD-001' and f.line_number==node.lineno for f in self.context.findings):continue
            if not state.uncertain:
                self.context.findings[:]=[f for f in self.context.findings if not (f.rule_id=='PY-OBL-JWS-PAYLOAD-001-REVIEW' and f.line_number==node.lineno)]
            self.context.emit(node,'PY-OBL-JWS-PAYLOAD-001','Returned claims are parsed outside the verified JWS payload',
                'crypto','Return claims decoded from the verifier payload, or establish equality with that exact payload before returning them.',
                'A keyed JWS deserialization accepts one payload representation, while returned claims are independently decoded from a compact-token segment.',
                'CWE-347',['The resolved jwcrypto JWS API may accept compact and JSON representations.',
                    'A non-null verification key, caller trust boundary and claim use remain runtime assumptions.'],state.uncertain,
                [dict(role='claims-decoding',file_path=self.context.path,line_number=value.line)])

    @classmethod
    def analyze(cls,context):
        for method in ast.walk(context.tree):
            if not isinstance(method,(ast.FunctionDef,ast.AsyncFunctionDef)):continue
            if not any(isinstance(n,ast.Call) and context.resolve(n.func)=='jwcrypto.jws.JWS' for n in ast.walk(method)):continue
            domain=cls(context,method)
            initial=State(values={p:Value('representation',(p,),method.lineno) for p in domain.parameters})
            try:BoundedPaths(domain).walk(method.body,[initial])
            except OverflowError:context.emit(method,'PY-OBL-JWS-PAYLOAD-001','Signed payload path budget reached',
                'crypto','Review payload identity on paths outside the bounded analysis.',
                'Signed-payload path analysis is incomplete.',None,uncertain=True)


class HMACKeyFormats:
    """A finite public-key blacklist is not a complete symmetric-key type boundary."""
    FORMATS=(b'-----BEGIN PUBLIC KEY-----',b'-----BEGIN RSA PUBLIC KEY-----',
             b'-----BEGIN CERTIFICATE-----',b'ssh-rsa',b'ssh-ed25519',b'ssh-dss',
             b'ecdsa-sha2-nistp256',b'ecdsa-sha2-nistp384',b'ecdsa-sha2-nistp521')
    APIS={'hmac.new','cryptography.hazmat.primitives.hmac.HMAC'}

    @classmethod
    def analyze(cls,context):
        for owner in context.tree.body:
            if not isinstance(owner,ast.ClassDef):continue
            constructor=next((n for n in owner.body if isinstance(n,ast.FunctionDef) and n.name=='__init__'),None)
            if constructor is None or not constructor.args.args:continue
            receiver=constructor.args.args[0].arg
            fields=set()
            for method in owner.body:
                if not isinstance(method,ast.FunctionDef) or not method.args.args:continue
                for call in ast.walk(method):
                    if not (isinstance(call,ast.Call) and context.resolve(call.func) in cls.APIS and call.args):continue
                    root=call.func
                    while isinstance(root,ast.Attribute):root=root.value
                    if isinstance(root,ast.Name) and (root.id in {a.arg for a in method.args.args}
                        or any(isinstance(n,(ast.Assign,ast.AnnAssign)) and any(isinstance(t,ast.Name) and t.id==root.id
                            for t in (n.targets if isinstance(n,ast.Assign) else [n.target])) for n in ast.walk(method))):continue
                    secret=call.args[0]
                    if isinstance(secret,ast.Attribute) and isinstance(secret.value,ast.Name) and secret.value.id==method.args.args[0].arg:
                        fields.add(secret.attr)
            if not fields:continue
            lists={n.targets[0].id:n.value for n in ast.walk(constructor) if isinstance(n,ast.Assign)
                   and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and isinstance(n.value,(ast.List,ast.Tuple,ast.Set))}
            for guard in ast.walk(constructor):
                if not isinstance(guard,ast.If) or len(guard.body)!=1 or not isinstance(guard.body[0],ast.Raise):continue
                test=guard.test
                if not (isinstance(test,ast.Call) and isinstance(test.func,ast.Name) and test.func.id=='any'
                        and len(test.args)==1 and isinstance(test.args[0],ast.GeneratorExp)):continue
                generator=test.args[0]
                if len(generator.generators)!=1:continue
                comp=generator.generators[0];comparison=generator.elt
                if comp.ifs or not isinstance(comp.target,ast.Name) or not isinstance(comp.iter,ast.Name):continue
                if not (isinstance(comparison,ast.Compare) and len(comparison.ops)==1 and isinstance(comparison.ops[0],ast.In)
                        and isinstance(comparison.left,ast.Name) and comparison.left.id==comp.target.id
                        and isinstance(comparison.comparators[0],ast.Name)):continue
                key=comparison.comparators[0].id
                if key not in {a.arg for a in constructor.args.args[1:]}:continue
                values=lists.get(comp.iter.id)
                if values is None or not all(isinstance(v,ast.Constant) and isinstance(v.value,(str,bytes)) for v in values.elts):continue
                markers=[v.value.encode() if isinstance(v.value,str) else v.value for v in values.elts]
                if not any(marker in cls.FORMATS for marker in markers):continue
                omitted=[fmt.decode() for fmt in cls.FORMATS if not any(marker in fmt+b' AAAA' for marker in markers)]
                if not omitted:continue
                assignments=[n for n in ast.walk(constructor) if isinstance(n,ast.Assign) and n.lineno>guard.lineno
                    and isinstance(n.value,ast.Name) and n.value.id==key and any(isinstance(t,ast.Attribute)
                    and isinstance(t.value,ast.Name) and t.value.id==receiver and t.attr in fields for t in n.targets)]
                if not assignments:continue
                other_guards=[n for n in ast.walk(constructor) if isinstance(n,ast.If) and n is not guard
                    and any(isinstance(t,ast.Name) and t.id==key for t in ast.walk(n.test))
                    and any(isinstance(t,ast.Call) and not (isinstance(t.func,ast.Name) and t.func.id in {'isinstance','any','all','len'}) for t in ast.walk(n.test))]
                changed_key=[n for n in ast.walk(constructor) if isinstance(n,ast.Assign) and guard.lineno<n.lineno<max(a.lineno for a in assignments)
                    and any(isinstance(t,ast.Name) and t.id==key for t in n.targets)]
                context.emit(guard,'PY-OBL-HMAC-FORMAT-001','HMAC key blacklist omits recognized public-key formats',
                    'crypto','Use a complete key-format/type boundary before accepting asymmetric representations as HMAC secrets.',
                    'A finite public-key rejection list guards material stored for a resolved HMAC operation, but omits: '+', '.join(omitted)+'.',
                    'CWE-347',['This checks the visible finite blacklist, not all possible key-format parsers or caller restrictions.',
                        'Accepting omitted representations and an attacker-relevant verifier configuration require runtime validation.'],
                    uncertain=bool(other_guards or changed_key),
                    related_locations=[dict(role='key-storage',file_path=context.path,line_number=n.lineno) for n in assignments])


class HTTPGrammar:
    """Conservative parser anti-patterns tied to resolved HTTP library contracts."""
    HTTP_APIS={'waitress.utilities.BadRequest','waitress.receiver.ChunkedReceiver',
               'gunicorn.http.body.ChunkedReader'}

    @staticmethod
    def root(node):
        while isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr in {'strip','encode','decode'}:
            node=node.func.value
        return node

    @staticmethod
    def header(node):
        return (isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=='get'
                and node.args and isinstance(node.args[0],ast.Constant) and node.args[0].value in {'CONTENT_LENGTH','Content-Length','content-length'})

    @staticmethod
    def guards(node,parents,value):
        """Collect enclosing true predicates and preceding terminating rejection guards."""
        while node in parents:
            parent=parents[node]
            for field in ['body','orelse','finalbody']:
                block=getattr(parent,field,[])
                if isinstance(block,list) and node in block:
                    for previous in block[:block.index(node)]:
                        if isinstance(previous,ast.If) and previous.body and isinstance(previous.body[-1],(ast.Raise,ast.Return,ast.Break,ast.Continue)):
                            yield previous.test
                    if isinstance(parent,ast.If) and field=='body':yield parent.test
            node=parent

    @classmethod
    def analyze(cls,context):
        if not any(isinstance(n,ast.Call) and context.resolve(n.func) in cls.HTTP_APIS for n in ast.walk(context.tree)):return
        for method in ast.walk(context.tree):
            if not isinstance(method,ast.FunctionDef):continue
            parents={child:parent for parent in ast.walk(method) for child in ast.iter_child_nodes(parent)}
            nodes=list(ast.walk(method))
            crlf=any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='find'
                and n.args and isinstance(n.args[0],ast.Constant) and n.args[0].value==b'\r\n' for n in nodes)
            bindings={n.targets[0].id:n.value for n in nodes if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)}
            shadowed={a.arg for a in method.args.args} | set(bindings)
            for call in nodes:
                if not (isinstance(call,ast.Call) and isinstance(call.func,ast.Name) and call.func.id=='int'
                        and 'int' not in context.bindings and 'int' not in shadowed and call.args):continue
                raw=cls.root(call.args[0]);base=call.args[1] if len(call.args)>1 else None
                hexadecimal=isinstance(base,ast.Constant) and base.value==16
                decimal=base is None or isinstance(base,ast.Constant) and base.value==10
                header=cls.header(raw) or isinstance(raw,ast.Name) and cls.header(bindings.get(raw.id))
                assigned=parents.get(call)
                counter=False
                if hexadecimal and isinstance(assigned,ast.Assign) and len(assigned.targets)==1 and isinstance(assigned.targets[0],ast.Name):
                    size=assigned.targets[0].id
                    fields={t.attr for n in nodes if isinstance(n,ast.Assign) and isinstance(n.value,ast.Name) and n.value.id==size
                        for t in n.targets if isinstance(t,ast.Attribute)}
                    bound_names={name for name,v in bindings.items() if isinstance(v,ast.Attribute) and v.attr in fields}
                    counter=any(isinstance(n,ast.Subscript) and isinstance(n.slice,ast.Slice)
                        and isinstance(n.slice.upper,ast.Name) and n.slice.upper.id in bound_names for n in nodes)
                if not (decimal and header or hexadecimal and crlf and counter):continue
                predicates=list(cls.guards(call,parents,raw))
                lexical=False;unknown=False
                for predicate in predicates:
                    for check in ast.walk(predicate):
                        if not isinstance(check,ast.Call):continue
                        mentions=isinstance(raw,ast.Name) and any(isinstance(v,ast.Name) and v.id==raw.id for v in ast.walk(check))
                        if not mentions:continue
                        if isinstance(check.func,ast.Attribute) and check.func.attr in {'match','fullmatch','isdigit','isdecimal'}:
                            lexical=True
                        elif not (isinstance(check.func,ast.Name) and check.func.id in {'isinstance','len'}):unknown=True
                if lexical:continue  # Observed guard suppresses this anti-pattern; its language is not proved safe.
                context.emit(call,'PY-OBL-HTTP-NUMERIC-001','HTTP framing length uses permissive integer parsing',
                    'protocol','Validate the exact decimal or hexadecimal HTTP length grammar before integer conversion; reject signs, prefixes and whitespace.',
                    'A resolved HTTP parser converts a Content-Length or chunk-size value without an observed lexical rejection guard. Python integer conversion accepts extra forms.',
                    'CWE-444',['Only visible dominating guards and resolved HTTP library contracts are modelled; caller filtering remains unverified.',
                        'Recognizing a lexical guard does not certify its regular expression or all parser paths.'],uncertain=unknown)
            for branch in nodes:
                if not isinstance(branch,ast.If) or len(branch.body)!=1 or not isinstance(branch.body[0],ast.If):continue
                test=branch.test
                if not (isinstance(test,ast.Compare) and len(test.ops)==1 and isinstance(test.ops[0],ast.Eq)
                    and isinstance(test.comparators[0],ast.Constant) and test.comparators[0].value=='TRANSFER-ENCODING'):continue
                inner=branch.body[0];condition=inner.test
                if inner.orelse or not (isinstance(condition,ast.Compare) and len(condition.ops)==1 and isinstance(condition.ops[0],ast.Eq)
                    and isinstance(condition.comparators[0],ast.Constant) and condition.comparators[0].value=='chunked'
                    and isinstance(condition.left,ast.Call) and isinstance(condition.left.func,ast.Attribute)
                    and condition.left.func.attr=='lower'):continue
                loop=parents.get(branch)
                while loop is not None and not isinstance(loop,ast.For):loop=parents.get(loop)
                if not (loop and isinstance(loop.target,(ast.Tuple,ast.List)) and len(loop.target.elts)==2
                    and all(isinstance(v,ast.Name) for v in loop.target.elts)
                    and isinstance(loop.iter,ast.Attribute) and loop.iter.attr=='headers'
                    and isinstance(test.left,ast.Name) and test.left.id==loop.target.elts[0].id
                    and isinstance(condition.left.func.value,ast.Name) and condition.left.func.value.id==loop.target.elts[1].id):continue
                if not (len(inner.body)==1 and isinstance(inner.body[0],ast.Assign)
                    and isinstance(inner.body[0].value,ast.Constant) and inner.body[0].value.value is True):continue
                if not any(isinstance(n,ast.Call) and context.resolve(n.func)=='gunicorn.http.body.ChunkedReader' for n in nodes):continue
                context.emit(inner,'PY-OBL-HTTP-CODING-001','Unsupported transfer codings have no rejecting branch',
                    'protocol','Reject unsupported Transfer-Encoding values before choosing a request body reader.',
                    'The HTTP parser handles only the chunked value in its Transfer-Encoding branch and has no alternate rejection in that branch.',
                    'CWE-444',['This is a narrow branch-shape check, not a complete HTTP framing, proxy or deployment model.'])
