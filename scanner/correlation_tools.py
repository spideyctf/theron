"""Supported tool declarations, local call paths and distribution claims; AST/data only."""
import ast
import builtins
import csv
from collections import Counter,defaultdict,deque
from email.parser import Parser
import hashlib
import io
import json
from pathlib import PurePosixPath
import re
import sys

from scanner.finding_utils import finding_scope
from scanner.python_project import PythonProject

FACTORIES={'mcp.server.fastmcp.FastMCP','fastmcp.FastMCP'}
LIMITS=[
    'Tool registration and call paths are statically inferred under supported FastMCP contracts; startup, dispatch and path conditions are not verified.',
    'An imported API call and OSV version match do not prove that the called function is affected by the advisory.',
    'Distribution metadata is a collected artifact claim, not authenticated ownership, an installed environment or effective import-path proof.',
    'Existing findings retain their severity and count; no additional vulnerability is inferred from a joined group.',
]


def canonical(name):return re.sub(r'[-_.]+','-',name).lower()


def resolve(node,bindings):
    if isinstance(node,ast.Name):return bindings.get(node.id,'')
    if isinstance(node,ast.Attribute):
        base=resolve(node.value,bindings)
        return base+'.'+node.attr if base else ''
    return ''


def scoped(node):
    if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef,ast.Lambda)):return
    yield node
    for child in ast.iter_child_nodes(node):yield from scoped(child)


def calls(statements):
    for node in statements:
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):continue
        if isinstance(node,ast.If):
            yield from (n for n in scoped(node.test) if isinstance(n,ast.Call))
            if isinstance(node.test,ast.Constant):yield from calls(node.body if node.test.value else node.orelse)
            else:
                yield from calls(node.body);yield from calls(node.orelse)
        else:
            yield from (n for n in scoped(node) if isinstance(n,ast.Call))
        if isinstance(node,(ast.Return,ast.Raise)):break


def distribution_claims(files):
    claims=defaultdict(list)
    for path,text in sorted(files.items()):
        parent=PurePosixPath(path).parent
        if PurePosixPath(path).name!='METADATA' or not parent.name.endswith('.dist-info'):continue
        record=str(parent/'RECORD')
        if record not in files:continue
        message=Parser().parsestr(text,headersonly=True)
        names=message.get_all('Name',[]);versions=message.get_all('Version',[])
        if len(names)!=1 or len(versions)!=1:continue
        name,version=str(names[0]).strip(),str(versions[0]).strip()
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',name) or not version or any(c.isspace() for c in version):continue
        roots=set();valid=True
        try:
            for index,row in enumerate(csv.reader(io.StringIO(files[record]),strict=True)):
                if index>=5000 or len(row)!=3:valid=False;break
                item=row[0];parts=item.split('/')
                if not item.endswith('.py'):continue
                if any(p in {'','..','.'} for p in parts) or any(c in item for c in '\\:\x00'):valid=False;break
                root=parts[0][:-3] if len(parts)==1 else parts[0]
                if root.isidentifier() and not root.startswith('_'):roots.add(root)
        except (csv.Error,ValueError):valid=False
        if valid:
            for root in sorted(roots):claims[root].append(dict(package=name,version=version,metadata=path,record=record))
    return claims


def nearest_manifest(path,files):
    parents=PurePosixPath(path).parent.parts;found=[]
    for candidate in files:
        p=PurePosixPath(candidate)
        if p.name in {'pyproject.toml','Pipfile','Pipfile.lock'} or p.name.startswith('requirements') and p.suffix=='.txt':
            if parents[:len(p.parent.parts)]==p.parent.parts:found.append(p.parent.parts)
    return max(found,key=len) if found else None


class ToolEvidence:
    def __init__(self,files,result):
        self.files,self.result=files,result
        self.project=PythonProject(files)
        self.claims=distribution_claims(files)
        self.hashes={}

    def location(self,path,node,role):return dict(file_path=path,line_number=node.lineno,role=role)

    def local_module(self,root):
        return any(p.endswith('.py') and (PurePosixPath(p).stem.casefold()==root.casefold() or root.casefold() in [part.casefold() for part in PurePosixPath(p).parts[:-1]]) for p in self.files)

    def call_evidence(self,path,call):
        root=call.func
        while isinstance(root,ast.Attribute):root=root.value
        declarations=[]
        if isinstance(root,ast.Name):
            for node in self.project.trees[path].body:
                if isinstance(node,(ast.Import,ast.ImportFrom)) and any((a.asname or a.name.split('.')[0])==root.id for a in node.names):declarations=[node]
        return [self.location(path,call,'call-site')]+[self.location(path,n,'import-declaration') for n in declarations]

    def edge(self,kind,source,target,evidence,basis,dependency=None):
        hashes={}
        for item in evidence:
            path=item['file_path']
            if path in self.files:
                if path not in self.hashes:self.hashes[path]=hashlib.sha256(self.files[path].encode()).hexdigest()
                hashes[path]=self.hashes[path]
        provenance=dict(commit_sha=self.result.commit_sha,source_text_sha256=hashes)
        if dependency:
            provenance.update(osv_queried_at=dependency.get('queried_at'),advisory_ids=dependency.get('advisory_ids',[]),
                              advisory_record_sha256=dependency.get('advisory_record_sha256'))
        return dict(kind=kind,source=source,target=target,classification='inferred',basis=basis,evidence=evidence,provenance=provenance)

    def registrations(self,target):
        tree=self.project.trees.get(target)
        if tree is None:return [],[dict(reason='entrypoint_python_unresolved',file_path=target)]
        bindings=self.project.bindings[target]
        module=self.project.module_name(target)
        attribute_writes=[n for item in tree.body for n in scoped(item) if isinstance(n,ast.Attribute) and isinstance(n.ctx,(ast.Store,ast.Del))]
        replaced_factories={resolve(n,bindings) for n in attribute_writes if resolve(n,bindings)}
        counts=Counter()
        for node in tree.body:
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):counts[node.name]+=1
            else:
                for n in scoped(node):
                    if isinstance(n,ast.Name) and isinstance(n.ctx,(ast.Store,ast.Del)):counts[n.id]+=1
        managers={};blocked=set();registered=[];notes=[];available=set()
        def note(node,reason):notes.append(dict(reason=reason,file_path=target,line_number=node.lineno))
        def handler(node,function,manager,public_name=None):
            fn=self.project.functions.get(function)
            if fn is None or not isinstance(fn,(ast.FunctionDef,ast.AsyncFunctionDef)):
                note(node,'handler_symbol_unresolved');return
            if len(registered)>=32:note(node,'tool_registration_budget_reached');return
            registered.append((node,function,fn,manager,public_name or fn.name))
        for node in tree.body:
            if isinstance(node,(ast.Import,ast.ImportFrom)):
                available.update(a.asname or a.name.split('.')[0] for a in node.names)
            if isinstance(node,(ast.Assign,ast.AnnAssign)):
                value=node.value;targets=node.targets if isinstance(node,ast.Assign) else [node.target]
                for name in targets:
                    if isinstance(name,ast.Attribute) and isinstance(name.value,ast.Name) and name.value.id in managers:
                        blocked.add((managers[name.value.id],name.attr))
                    if not isinstance(name,ast.Name) or counts[name.id]!=1:continue
                    if isinstance(value,ast.Call) and resolve(value.func,bindings) in FACTORIES:
                        factory=resolve(value.func,bindings)
                        if any(factory==name or factory.startswith(name+'.') or name.startswith(factory+'.') for name in replaced_factories):
                            note(node,'factory_contract_reassigned');continue
                        root_node=value.func
                        while isinstance(root_node,ast.Attribute):root_node=root_node.value
                        if not isinstance(root_node,ast.Name) or root_node.id not in available:
                            note(node,'factory_not_bound_at_construction');continue
                        root=resolve(value.func,bindings).split('.')[0]
                        if self.local_module(root):
                            note(node,'local_module_shadows_fastmcp');continue
                        managers[name.id]=(node.lineno,node.col_offset)
                    elif isinstance(value,ast.Name) and value.id in managers:managers[name.id]=managers[value.id]
                    available.add(name.id)
            elif isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                for decorator in node.decorator_list:
                    call=decorator if isinstance(decorator,ast.Call) else None
                    attr=call.func if call else decorator
                    if not (isinstance(attr,ast.Attribute) and isinstance(attr.value,ast.Name) and attr.value.id in managers and attr.attr=='tool'):continue
                    if (managers[attr.value.id],'tool') in blocked or counts[node.name]!=1:
                        note(decorator,'registration_binding_reassigned');continue
                    if any(isinstance(n.value,ast.Name) and managers.get(n.value.id)==managers[attr.value.id] and n.attr=='tool' for n in attribute_writes):
                        note(decorator,'registration_binding_reassigned');continue
                    if call is None or call.args or len(node.decorator_list)!=1 or any(k.arg not in {'name','description'} for k in call.keywords):
                        note(decorator,'unsupported_tool_decorator');continue
                    public=next((k.value for k in call.keywords if k.arg=='name'),None)
                    if public is not None and not (isinstance(public,ast.Constant) and isinstance(public.value,str)):
                        note(decorator,'dynamic_tool_name');continue
                    handler(decorator,module+'.'+node.name,managers[attr.value.id],public.value if public else None)
                available.add(node.name)
            elif isinstance(node,ast.Expr) and isinstance(node.value,ast.Call):
                call=node.value;attr=call.func
                if isinstance(attr,ast.Attribute) and isinstance(attr.value,ast.Name) and attr.value.id in managers and attr.attr=='add_tool':
                    if (managers[attr.value.id],'add_tool') in blocked:note(call,'registration_binding_reassigned');continue
                    if any(isinstance(n.value,ast.Name) and managers.get(n.value.id)==managers[attr.value.id] and n.attr=='add_tool' for n in attribute_writes):
                        note(call,'registration_binding_reassigned');continue
                    argument=call.args[0] if len(call.args)==1 and not call.keywords else None
                    symbol=resolve(argument,bindings);fn=self.project.functions.get(symbol)
                    argument_root=argument
                    while isinstance(argument_root,ast.Attribute):argument_root=argument_root.value
                    if not isinstance(argument_root,ast.Name) or argument_root.id not in available:
                        note(call,'handler_not_bound_at_registration');continue
                    if fn and fn.decorator_list:note(call,'unsupported_handler_decorator');continue
                    handler(call,symbol,managers[attr.value.id])
            elif isinstance(node,(ast.If,ast.Try,ast.For,ast.While,ast.With)):
                if any(isinstance(n,ast.Attribute) and n.attr in {'tool','add_tool'} for n in ast.walk(node)):
                    note(node,'conditional_registration_not_resolved')
        return registered,notes

    def dependency(self,path,symbol):
        root=symbol.split('.')[0];nearest=nearest_manifest(path,self.files)
        standard=getattr(sys,'stdlib_module_names',None)
        if standard is None:return [],'stdlib_identity_unavailable'
        if root.casefold() in {n.casefold() for n in standard}:return [],None
        candidates=[]
        for f in self.result.findings+self.result.context_findings:
            d=f.dependency
            if not (f.fingerprint and f.evidence_kind=='dependency-version-match' and d and d.get('provider')=='OSV'
                    and d.get('ecosystem')=='PyPI' and d.get('manifest')==f.file_path and f.file_path in self.files
                    and isinstance(d.get('package'),str) and isinstance(d.get('version'),str)
                    and nearest is not None and PurePosixPath(f.file_path).parent.parts==nearest):continue
            claims=self.claims.get(root,[])
            if claims:
                if len(claims)!=1:return [],'ambiguous_distribution_metadata'
                claim=claims[0]
                if canonical(claim['package'])!=canonical(d.get('package','')):continue
                if claim['version']!=d.get('version'):return [],'distribution_version_mismatch'
                evidence=[dict(role='distribution-metadata',file_path=claim['metadata']),dict(role='distribution-file-record',file_path=claim['record'])]
                candidates.append((f,'distribution-record-claim',evidence))
            elif root==d.get('package') and root.isidentifier():
                candidates.append((f,'same-name-declaration-only',[]))
        return candidates,None

    def groups(self,target,config,pointer,flows):
        registrations,notes=self.registrations(target);groups=[]
        for registration,symbol,handler,manager,public_name in registrations:
            path=self.project.locations[symbol][0]
            entry=dict(kind='file',file_path=target)
            endpoint=dict(kind='function',file_path=path,line_number=handler.lineno,symbol=symbol)
            edges=[self.edge('declares_entrypoint',dict(kind='configuration',file_path=config,pointer=pointer),entry,
                [dict(file_path=config,pointer=pointer+'/args')],'supported_python_declaration'),
                self.edge('declares_tool_handler',entry,endpoint,[self.location(target,registration,'tool-registration'),self.location(path,handler,'handler-definition')],
                          'supported_fastmcp_registration')]
            edges[-1]['evidence'].append(dict(file_path=target,line_number=manager[0],role='server-instance-construction'))
            refs=set();unresolved=[];queue=deque([(symbol,handler,0)]);seen=set();steps=0
            while queue:
                current,fn,depth=queue.popleft()
                if current in seen:continue
                seen.add(current);current_path,_,base=self.project.locations[current]
                bindings=base.copy()
                for arg in fn.args.posonlyargs+fn.args.args+fn.args.kwonlyargs+[a for a in [fn.args.vararg,fn.args.kwarg] if a]:bindings[arg.arg]=''
                for node in fn.body:
                    for n in scoped(node):
                        if isinstance(n,ast.Name) and isinstance(n.ctx,(ast.Store,ast.Del)):bindings[n.id]=''
                        elif isinstance(n,(ast.Import,ast.ImportFrom)):
                            for alias in n.names:bindings[alias.asname or alias.name.split('.')[0]]=''
                    if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):bindings[node.name]=''
                replaced=set()
                for node in list(self.project.trees[current_path].body)+list(fn.body):
                    for n in scoped(node):
                        if isinstance(n,ast.Attribute) and isinstance(n.ctx,(ast.Store,ast.Del)):
                            name=resolve(n,bindings)
                            if name:replaced.add(name)
                origin=dict(kind='function',file_path=current_path,line_number=fn.lineno,symbol=current)
                for call in calls(fn.body):
                    steps+=1
                    if steps>256:unresolved.append(dict(reason='handler_call_budget_reached',file_path=current_path));queue.clear();break
                    for f in flows.get(current_path,[]):
                        if f.line_number==call.lineno and f.fingerprint not in refs:
                            refs.add(f.fingerprint)
                            edges.append(self.edge('reachable_function_contains_existing_flow',origin,dict(kind='finding',fingerprint=f.fingerprint),
                                [dict(t) for t in f.trace],'supported_static_call_path_contains_original_finding'))
                    name=resolve(call.func,bindings)
                    if name and any(name==blocked or name.startswith(blocked+'.') for blocked in replaced):
                        unresolved.append(dict(reason='call_target_reassigned',file_path=current_path,line_number=call.lineno));continue
                    if name in self.project.functions:
                        next_fn=self.project.functions[name];next_path=self.project.locations[name][0]
                        if next_fn.decorator_list:
                            unresolved.append(dict(reason='local_callee_decorator_unresolved',file_path=current_path,line_number=call.lineno));continue
                        if depth>=5:unresolved.append(dict(reason='handler_call_depth_reached',file_path=current_path,line_number=call.lineno));continue
                        edges.append(self.edge('calls_local_function',origin,dict(kind='function',file_path=next_path,line_number=next_fn.lineno,symbol=name),
                            self.call_evidence(current_path,call)+[self.location(next_path,next_fn,'function-definition')],'resolved_local_symbol'))
                        queue.append((name,next_fn,depth+1));continue
                    root=name.split('.')[0] if name else ''
                    local_shadow=self.local_module(root)
                    if not name or local_shadow or any(m==root or m.startswith(root+'.') for m in self.project.modules):
                        if not (isinstance(call.func,ast.Name) and call.func.id in vars(builtins) and call.func.id not in bindings):
                            unresolved.append(dict(reason='call_target_unresolved',file_path=current_path,line_number=call.lineno))
                        continue
                    matches,reason=self.dependency(current_path,name)
                    if reason:unresolved.append(dict(reason=reason,file_path=current_path,line_number=call.lineno))
                    standard=getattr(sys,'stdlib_module_names',set())
                    if root.casefold() in {n.casefold() for n in standard}:continue
                    api=dict(kind='imported_api',symbol=name)
                    edges.append(self.edge('calls_imported_api',origin,api,self.call_evidence(current_path,call),'resolved_import_symbol'))
                    if not matches and not reason:unresolved.append(dict(reason='no_dependency_advisory_context',file_path=current_path,line_number=call.lineno))
                    for f,basis,evidence in matches:
                        d=f.dependency;refs.add(f.fingerprint)
                        dep=dict(kind='dependency',package=d['package'],version=d['version'],file_path=f.file_path)
                        edges.append(self.edge('import_has_dependency_context',api,dep,evidence+[dict(role='dependency-declaration',file_path=f.file_path)],basis))
                        edges.append(self.edge('declared_version_matches_osv_advisory',dep,dict(kind='finding',fingerprint=f.fingerprint),
                            [dict(role='dependency-declaration',file_path=f.file_path)],'existing_exact_version_osv_match',d))
            if len(unresolved)>32:unresolved=unresolved[:31]+[dict(reason='resolution_note_limit_reached',file_path=path)]
            identity=[self.result.repo_full_name,self.result.commit_sha,config,pointer,target,symbol,registration.lineno,registration.col_offset,sorted(refs)]
            scopes=[finding_scope(config),finding_scope(target),finding_scope(path)]+[finding_scope(e['file_path']) for edge in edges for e in edge['evidence']]
            groups.append(dict(id='mcp-tool-'+hashlib.sha256(json.dumps(identity,sort_keys=True).encode()).hexdigest()[:24],
                title='Declared MCP tool: '+public_name,scope=next((s for s in scopes if s!='application'),'application'),
                classification='inferred',maturity='experimental',finding_fingerprints=sorted(refs),relationships=edges,
                limitations=list(LIMITS),resolution_notes=unresolved))
        return groups,notes
