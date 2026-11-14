"""Library-specific security-state checks. Target code is inspected only as AST."""
import ast
from scanner.python_obligations import BoundedPaths,State,Value


class HTMLCanonicalization:
    CLEANERS={'lxml.html.clean.Cleaner','lxml_html_clean.Cleaner'}
    PARSERS={'lxml.html.fromstring','lxml.html.fragment_fromstring','lxml.html.soupparser.fromstring'}
    SERIALIZERS={'lxml.html.tostring','lxml.etree.tostring'}

    def __init__(self,context,method):
        self.context,self.method=context,method
        self.actions={}
        self.bindings=context.bindings.copy()
        for node in self.scoped(method.body):
            if isinstance(node,ast.Import):
                for alias in node.names:self.bindings[alias.asname or alias.name.split('.')[0]]=alias.name if alias.asname else alias.name.split('.')[0]
            elif isinstance(node,ast.ImportFrom) and not node.level:
                for alias in node.names:self.bindings[alias.asname or alias.name]=(node.module or '')+'.'+alias.name
        for node in self.scoped(method.body):
            if isinstance(node,(ast.Assign,ast.AnnAssign)):
                for target in node.targets if isinstance(node,ast.Assign) else [node.target]:
                    if isinstance(target,ast.Name) and target.id in self.bindings:self.bindings[target.id]=''

    def name(self,node,state):
        root=node
        while isinstance(root,ast.Attribute):root=root.value
        if isinstance(root,ast.Name) and root.id in state.values:return ''
        return self.context.resolve(node,self.bindings)

    def value(self,node,state):
        if isinstance(node,ast.Name):return state.values.get(node.id)
        if not isinstance(node,ast.Call):return None
        name=self.name(node.func,state)
        if name in self.CLEANERS:return Value('html-cleaner',(node.lineno,node.col_offset),node.lineno)
        if name in self.SERIALIZERS and node.args:
            tree=self.value(node.args[0],state)
            if tree and tree.kind=='cleaned-tree':return Value('cleaned-html',tree.token,tree.line)
        if name=='unicodedata.normalize' and len(node.args)>=2:
            form=node.args[0]
            text=self.value(node.args[1],state)
            if text and text.kind in {'cleaned-html','normalized-html'}:
                if isinstance(form,ast.Constant) and form.value in {'NFKC','NFKD'}:
                    identity=(node.lineno,node.col_offset)
                    self.actions[identity]=node
                    return Value('normalized-html',(text.line,identity),node.lineno)
                if isinstance(form,ast.Constant) and form.value in {'NFC','NFD'}:return text
        if name=='re.sub' and len(node.args)>=3:return self.value(node.args[2],state)
        if isinstance(node.func,ast.Attribute) and node.func.attr in {'strip','lstrip','rstrip'}:
            return self.value(node.func.value,state)
        if isinstance(node.func,ast.Attribute) and node.func.attr=='clean_html':
            cleaner=self.value(node.func.value,state)
            if cleaner and cleaner.kind=='html-cleaner':return Value('cleaned-html',(node.lineno,node.col_offset),node.lineno)
        return None

    def statement(self,node,state):
        if isinstance(node,(ast.Assign,ast.AnnAssign)):
            value=self.value(node.value,state)
            for target in node.targets if isinstance(node,ast.Assign) else [node.target]:
                if isinstance(target,ast.Name):state.values[target.id]=value

    def condition(self,node,truth,state):pass

    def returned(self,node,state):
        text=self.value(node.value,state)
        if not text or text.kind!='normalized-html':return
        action=self.actions[text.token[1]]
        if any(f.rule_id=='PY-OBL-HTML-ORDER-001' and f.line_number==action.lineno for f in self.context.findings):return
        self.context.emit(action,'PY-OBL-HTML-ORDER-001','Compatibility normalization follows HTML cleaning',
            'html','Apply compatibility normalization before HTML parsing/cleaning, or clean the transformed result again before returning it.',
            'Returned HTML derives from a resolved cleaner and is subsequently transformed with NFKC/NFKD normalization, which can introduce markup-significant characters.',
            'CWE-79',['The cleaner/serializer contracts are statically resolved; returned HTML rendering and attacker control remain caller assumptions.',
                'This checks transformation order, not the completeness of every cleaner policy or DOM mutation.'],state.uncertain,
            [dict(role='cleaning',file_path=self.context.path,line_number=text.token[0]),
             dict(role='return',file_path=self.context.path,line_number=node.lineno)])

    @staticmethod
    def scoped(nodes):
        for node in nodes:
            yield node
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):continue
            yield from HTMLCanonicalization.scoped(ast.iter_child_nodes(node))

    @classmethod
    def analyze(cls,context):
        if not context.imports_api(cls.CLEANERS) or not context.imports_api({'unicodedata.normalize'}):return
        for method in ast.walk(context.tree):
            if not isinstance(method,ast.FunctionDef):continue
            domain=cls(context,method)
            # Only seed a tree at an observed top-level in-place cleaner call.
            # Preceding loops do not require a claim about their DOM-edit semantics.
            checkpoint=None
            for index,node in enumerate(method.body):
                call=node.value if isinstance(node,ast.Expr) and isinstance(node.value,ast.Call) else None
                if not (call and isinstance(call.func,ast.Call) and context.resolve(call.func.func,domain.bindings) in cls.CLEANERS
                        and len(call.args)==1 and isinstance(call.args[0],ast.Name)):continue
                name=call.args[0].id
                writers=[n for n in cls.scoped(method.body[:index]) if isinstance(n,(ast.Assign,ast.AnnAssign))
                         and any(isinstance(t,ast.Name) and t.id==name for t in (n.targets if isinstance(n,ast.Assign) else [n.target]))]
                if not writers or any(not isinstance(n.value,ast.Call) or context.resolve(n.value.func,domain.bindings) not in cls.PARSERS for n in writers):continue
                initial=State(values={a.arg:None for a in method.args.posonlyargs+method.args.args+method.args.kwonlyargs})
                initial.values[name]=Value('cleaned-tree',(call.lineno,call.col_offset),call.lineno)
                checkpoint=(index,initial)
            # The ordinary path supports local Cleaner.clean_html return pipelines.
            index,initial=checkpoint if checkpoint else (-1,State(values={a.arg:None for a in method.args.args}))
            try:BoundedPaths(domain).walk(method.body[index+1:],[initial])
            except OverflowError:context.emit(method,'PY-OBL-HTML-ORDER-001','HTML transformation path budget reached',
                'html','Review HTML transformation order outside the bounded analysis.',
                'HTML cleaning/canonicalization analysis is incomplete.',None,uncertain=True)


class TLSPoolPolicy:
    """Identify mutable TLS policy applied after policy-independent pool selection."""
    MANAGERS={'urllib3.PoolManager','urllib3.poolmanager.PoolManager'}

    def __init__(self,context,method,lookups,mutators):
        self.context,self.method,self.lookups,self.mutators=context,method,lookups,mutators
        self.receiver=method.args.args[0].arg if method.args.args else 'self'
        self.parameters={a.arg for a in method.args.args[1:]}

    def own(self,node):
        return isinstance(node,ast.Attribute) and isinstance(node.value,ast.Name) and node.value.id==self.receiver

    def value(self,node,state):
        if isinstance(node,ast.Name):return state.values.get(node.id)
        if isinstance(node,ast.Call) and self.own(node.func) and node.func.attr in self.lookups:
            if self.receiver in state.values or self.receiver+'.'+node.func.attr in state.values:return None
            dependencies={n.id for arg in node.args+[kw.value for kw in node.keywords] for n in ast.walk(arg) if isinstance(n,ast.Name)}
            return Value('pooled-connection',(node.lineno,node.col_offset,frozenset(dependencies)),node.lineno)
        return None

    def statement(self,node,state):
        if isinstance(node,(ast.Assign,ast.AnnAssign)):
            value=self.value(node.value,state)
            for target in node.targets if isinstance(node,ast.Assign) else [node.target]:
                if isinstance(target,ast.Name):state.values[target.id]=value
                elif isinstance(target,ast.Attribute) and isinstance(target.value,ast.Name) and target.value.id==self.receiver:
                    state.values[self.receiver+'.'+target.attr]=None
        elif isinstance(node,ast.Expr) and isinstance(node.value,ast.Call):
            call=node.value
            if self.receiver in state.values:return
            if not self.own(call.func) or call.func.attr not in self.mutators:return
            if self.receiver+'.'+call.func.attr in state.values:return
            formal,conn_index,policy_index=self.mutators[call.func.attr]
            def argument(index):
                return next((k.value for k in call.keywords if k.arg==formal[index]),call.args[index] if len(call.args)>index else None)
            connection=self.value(argument(conn_index),state);policy=argument(policy_index)
            if not connection or connection.kind!='pooled-connection' or not isinstance(policy,ast.Name) or policy.id not in self.parameters:return
            if policy.id in connection.token[2]:return
            self.context.emit(call,'PY-OBL-TLS-POOL-001','TLS verification policy is applied after policy-independent pool selection',
                'tls','Partition connection pools by verification policy and TLS context before reusing connections.',
                'A resolved urllib3 pool is selected without the per-call verification argument, then a local helper mutates certificate requirements on that selected pool.',
                'CWE-295',['Pool reuse, TLS context caching and call sequences require runtime verification.',
                    'Passing policy into selection suppresses this narrow check; correct pool-key construction is not proved.'],state.uncertain,
                [dict(role='pool-selection',file_path=self.context.path,line_number=connection.line)])

    def condition(self,node,truth,state):pass
    def returned(self,node,state):pass

    @classmethod
    def analyze(cls,context):
        if not context.imports_api(cls.MANAGERS):return
        for owner in context.tree.body:
            if not isinstance(owner,ast.ClassDef):continue
            methods={n.name:n for n in owner.body if isinstance(n,ast.FunctionDef) and n.args.args}
            fields=set();lookups=set();mutators={}
            for method in methods.values():
                receiver=method.args.args[0].arg
                for n in HTMLCanonicalization.scoped(method.body):
                    if isinstance(n,ast.Assign) and isinstance(n.value,ast.Call) and context.resolve(n.value.func) in cls.MANAGERS:
                        fields.update(t.attr for t in n.targets if isinstance(t,ast.Attribute) and isinstance(t.value,ast.Name) and t.value.id==receiver)
            for name,method in methods.items():
                params=[a.arg for a in method.args.args[1:]];receiver=method.args.args[0].arg
                for n in HTMLCanonicalization.scoped(method.body):
                    if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr in {'connection_from_url','connection_from_host'}:
                        base=n.func.value
                        if isinstance(base,ast.Attribute) and base.attr in fields and isinstance(base.value,ast.Name) and base.value.id==receiver:
                            lookups.add(name)
                    if not isinstance(n,ast.If) or not n.orelse:continue
                    leaves=n.test.values if isinstance(n.test,ast.BoolOp) and isinstance(n.test.op,ast.And) else [n.test]
                    policy=next((v.id for v in leaves if isinstance(v,ast.Name) and v.id in params),None)
                    if not policy:continue
                    def flags(block):
                        return {(t.value.id,item.value.value) for item in HTMLCanonicalization.scoped(block)
                            if isinstance(item,ast.Assign) and isinstance(item.value,ast.Constant)
                            for t in item.targets if isinstance(t,ast.Attribute) and t.attr=='cert_reqs'
                            and isinstance(t.value,ast.Name) and t.value.id in params}
                    yes,no=flags(n.body),flags(n.orelse)
                    for parameter,flag in yes:
                        if flag=='CERT_REQUIRED' and (parameter,'CERT_NONE') in no:
                            mutators[name]=(params,params.index(parameter),params.index(policy))
            if not lookups or not mutators:continue
            for method in methods.values():
                domain=cls(context,method,lookups,mutators)
                try:BoundedPaths(domain).walk(method.body,[State()])
                except OverflowError:context.emit(method,'PY-OBL-TLS-POOL-001','TLS pool-policy path budget reached',
                    'tls','Review pool policy outside the bounded analysis.','TLS pool-policy analysis is incomplete.',None,uncertain=True)


class MCPMessageValidation:
    """Per-message validation must not silently terminate an MCP receive loop."""
    STREAM='anyio.streams.memory.MemoryObjectReceiveStream'
    MESSAGE='mcp.shared.message.SessionMessage'

    @classmethod
    def analyze(cls,context):
        if not context.imports_api({cls.STREAM}) or not context.imports_api({cls.MESSAGE}):return
        for owner in context.tree.body:
            if not isinstance(owner,ast.ClassDef):continue
            init=next((n for n in owner.body if isinstance(n,ast.FunctionDef) and n.name=='__init__'),None)
            if init is None or not init.args.args:continue
            receiver=init.args.args[0].arg
            streams={a.arg for a in init.args.args if isinstance(a.annotation,ast.Subscript)
                and context.resolve(a.annotation.value)==cls.STREAM
                and any(context.resolve(n)==cls.MESSAGE for n in ast.walk(a.annotation.slice))}
            model_vars=set()
            for n in context.tree.body:
                if isinstance(n,ast.Assign) and isinstance(n.value,ast.Call) and context.resolve(n.value.func)=='typing.TypeVar':
                    constraints=n.value.args[1:]+[k.value for k in n.value.keywords if k.arg=='bound']
                    if constraints and all(context.resolve(v)=='pydantic.BaseModel' or context.resolve(v).startswith('mcp.types.') for v in constraints):
                        model_vars.update(t.id for t in n.targets if isinstance(t,ast.Name))
            models={a.arg for a in init.args.args if isinstance(a.annotation,ast.Subscript)
                and isinstance(a.annotation.value,ast.Name) and a.annotation.value.id=='type'
                and (context.resolve(a.annotation.slice)=='pydantic.BaseModel'
                    or isinstance(a.annotation.slice,ast.Name) and a.annotation.slice.id in model_vars)}
            fields={t.attr for n in HTMLCanonicalization.scoped(init.body) if isinstance(n,ast.Assign)
                and isinstance(n.value,ast.Name) and n.value.id in streams for t in n.targets
                if isinstance(t,ast.Attribute) and isinstance(t.value,ast.Name) and t.value.id==receiver}
            validators={t.attr for n in HTMLCanonicalization.scoped(init.body) if isinstance(n,ast.Assign)
                and isinstance(n.value,ast.Name) and n.value.id in models for t in n.targets
                if isinstance(t,ast.Attribute) and isinstance(t.value,ast.Name) and t.value.id==receiver}
            for method in owner.body:
                if not isinstance(method,ast.AsyncFunctionDef) or not method.args.args:continue
                receiver=method.args.args[0].arg
                parents={child:parent for parent in ast.walk(method) for child in ast.iter_child_nodes(parent)}
                for loop in ast.walk(method):
                    if not (isinstance(loop,ast.AsyncFor) and isinstance(loop.target,ast.Name) and isinstance(loop.iter,ast.Attribute)
                        and loop.iter.attr in fields and isinstance(loop.iter.value,ast.Name) and loop.iter.value.id==receiver):continue
                    for call in HTMLCanonicalization.scoped(loop.body):
                        if not (isinstance(call,ast.Call) and isinstance(call.func,ast.Attribute) and call.func.attr=='model_validate'
                            and isinstance(call.func.value,ast.Attribute) and isinstance(call.func.value.value,ast.Name)
                            and call.func.value.value.id==receiver and call.func.value.attr in validators and call.args
                            and any(isinstance(n,ast.Name) and n.id==loop.target.id for n in ast.walk(call.args[0]))):continue
                        child=call;cursor=parents.get(child);handled=False
                        while cursor is not None and cursor is not loop:
                            if isinstance(cursor,ast.Try) and child in cursor.body:
                                for handler in cursor.handlers:
                                    kinds=handler.type.elts if isinstance(handler.type,ast.Tuple) else [handler.type]
                                    catches=any(k is None or context.resolve(k) in {'pydantic.ValidationError','pydantic_core.ValidationError','builtins.Exception','builtins.BaseException','builtins.ValueError'}
                                        or isinstance(k,ast.Name) and k.id in {'Exception','BaseException','ValueError'} and k.id not in context.bindings for k in kinds)
                                    if catches and not any(isinstance(n,(ast.Raise,ast.Return)) for n in HTMLCanonicalization.scoped(handler.body)):handled=True
                            child=cursor;cursor=parents.get(cursor)
                        if handled:continue
                        context.emit(call,'PY-OBL-MCP-VALIDATION-001','MCP message validation can terminate its receive loop',
                            'availability','Handle malformed-message validation failures inside the receive loop and return a protocol error without terminating unrelated processing.',
                            'A message from a resolved MCP SessionMessage receive stream reaches model_validate without a visible continuing per-message exception boundary.',
                            'CWE-248',['The session model/transport contracts and exception behavior require upstream/runtime verification.',
                                'Caller restart policies and the impact on other sessions are not inferred.'],
                            related_locations=[dict(role='message-loop',file_path=context.path,line_number=loop.lineno)])


class ASTCallableBoundary:
    """Raw callable lookup can bypass a name-only accessor's capability boundary."""
    @classmethod
    def analyze(cls,context):
        if not context.imports_api({'ast.parse'}):return
        nodes=list(ast.walk(context.tree))
        if not any(isinstance(n,ast.Call) and context.resolve(n.func)=='ast.parse' for n in nodes):return
        functions={n.name:n for n in context.tree.body if isinstance(n,ast.FunctionDef)}
        accessors=set()
        for name,fn in functions.items():
            if any(a.arg=='getattr' for a in fn.args.args) or 'getattr' in context.bindings:continue
            returns=[n for n in HTMLCanonicalization.scoped(fn.body) if isinstance(n,ast.Return)]
            if not any(isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Name) and n.value.func.id=='getattr' for n in returns):continue
            if not any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr in {'startswith','endswith'}
                and n.args and isinstance(n.args[0],ast.Constant) and n.args[0].value=='__' for n in HTMLCanonicalization.scoped(fn.body)):continue
            accessors.add(name)
        registries=set()
        for assignment in context.tree.body:
            if not isinstance(assignment,ast.Assign) or not isinstance(assignment.value,ast.Dict):continue
            entries={k.value:v for k,v in zip(assignment.value.keys,assignment.value.values) if isinstance(k,ast.Constant)}
            accessor=entries.get('getattr')
            if not isinstance(accessor,ast.Name) or accessor.id not in accessors:continue
            if not all(isinstance(entries.get(k),ast.Name) and entries[k].id==k and k not in context.bindings for k in ['map','filter']):continue
            registries.update(t.id for t in assignment.targets if isinstance(t,ast.Name))
        if not registries:return
        fields=set()
        for node in nodes:
            if not isinstance(node,ast.Assign) or not isinstance(node.value,ast.Dict):continue
            inherited=any(k is None and isinstance(v,ast.Call) and isinstance(v.func,ast.Attribute) and v.func.attr=='copy'
                and isinstance(v.func.value,ast.Name) and v.func.value.id in registries for k,v in zip(node.value.keys,node.value.values))
            if inherited:fields.update(t.attr for t in node.targets if isinstance(t,ast.Attribute))
        injected={k.arg for node in nodes if isinstance(node,ast.Call) for k in node.keywords
                  if k.arg and isinstance(k.value,ast.Attribute) and k.value.attr in fields}
        for method in functions.values():
            params={a.arg:a.annotation for a in method.args.args}
            expressions={name for name,annotation in params.items() if context.resolve(annotation)=='ast.Name'}
            tables={name for name,annotation in params.items() if name in injected and annotation is not None
                and any(context.resolve(n) in {'typing.Callable','collections.abc.Callable'} for n in ast.walk(annotation))}
            if not expressions or not tables:continue
            for returned in HTMLCanonicalization.scoped(method.body):
                value=returned.value if isinstance(returned,ast.Return) else None
                if not (isinstance(value,ast.Subscript) and isinstance(value.value,ast.Name) and value.value.id in tables
                    and isinstance(value.slice,ast.Attribute) and value.slice.attr=='id'
                    and isinstance(value.slice.value,ast.Name) and value.slice.value.id in expressions):continue
                context.emit(returned,'PY-OBL-AI-CAPABILITY-001','AST tool lookup returns an unwrapped capability',
                    'sandbox','Apply result-capability policy when exposing interpreter callables, including indirect calls through map/filter.',
                    'An AST-name resolver returns a raw callable from an injected tool table containing higher-order builtins and a name-filtered getattr accessor.',
                    'CWE-863',['Tool-table injection is a structural cross-function inference, not verified runtime dispatch.',
                        'The check does not prove all sandbox escapes or certify a wrapper merely because it is present.'],
                    related_locations=[dict(role='tool-registry',file_path=context.path,line_number=n.lineno)
                        for n in context.tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id in registries for t in n.targets)])
