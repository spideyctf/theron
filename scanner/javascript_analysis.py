"""Bounded JS/TS syntax-based source/sink observations. Never execute repository code."""
from dataclasses import dataclass
from pathlib import PurePosixPath
import re
from html.parser import HTMLParser
from tree_sitter import Language, Parser
import tree_sitter_javascript
import tree_sitter_typescript
from scanner.models import Finding, Severity, Category
from scanner.utils.helpers import redact_secrets


@dataclass(frozen=True)
class Value:
    symbol: str = ''
    source: tuple = ()  # kind, source line, HTML text encoding proven
    literal: object = None
    parts: tuple = ()


def combine(values):
    sources=[v.source for v in values if v.source]
    if not sources:return Value()
    selected=sources[0]
    parts=[]
    for value in values:
        parts.extend(value.parts if value.parts else (value.source[2],) if value.source else (value.literal,) if isinstance(value.literal,str) else (None,))
    return Value(source=(selected[0],selected[1],all(s[2] for s in sources)),parts=tuple(parts) if len(parts)<=256 else (None,))


class TextContext(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.raw_text=False
    def handle_starttag(self,tag,attrs):
        if tag in {'script','style'}:self.raw_text=True
    def handle_endtag(self,tag):
        if tag in {'script','style'}:self.raw_text=False


def html_text_safe(value):
    if not value.source or not value.source[2]:return False
    parser=TextContext()
    for part in value.parts or (True,):
        if isinstance(part,str):parser.feed(part)
        elif part is True and not parser.rawdata and not parser.raw_text:parser.feed('encoded-text')
        else:return False
    return True


def analyze_javascript(path,content):
    suffix=PurePosixPath(path).suffix
    language=tree_sitter_typescript.language_tsx() if suffix=='.tsx' else tree_sitter_typescript.language_typescript() if suffix=='.ts' else tree_sitter_javascript.language()
    root=Parser(Language(language)).parse(content.encode()).root_node
    analyzer=Analyzer(path,content)
    if root.has_error:
        return [analyzer.notice('JS-PARSE-001','JavaScript/TypeScript syntax analysis incomplete',
            'The selected grammar could not parse this file completely. Source/sink checks were skipped; regex fallbacks do not establish semantic coverage.')]
    try:analyzer.block(root,{})
    except (RecursionError,AnalysisLimit):
        analyzer.findings.append(analyzer.notice('JS-BUDGET-001','JavaScript/TypeScript analysis budget reached',
            'The bounded syntax analysis stopped; remaining call paths are unknown.'))
    unique={ (f.rule_id,f.line_number):f for f in analyzer.findings }
    return list(unique.values())


class AnalysisLimit(Exception):pass


class Analyzer:
    def __init__(self,path,content):
        self.path,self.content=path,content
        self.findings=[]
        self.functions={}
        self.steps=0

    @staticmethod
    def text(node):return node.text.decode() if node else ''

    @staticmethod
    def field(node,key):return node.child_by_field_name(key) if node else None

    @staticmethod
    def children(node):return [n for n in node.named_children if n.type!='comment'] if node else []

    def notice(self,rule,title,description):
        return Finding(title=title,severity=Severity.INFO,category=Category.SAST,module='coverage',file_path=self.path,
            rule_id=rule,description=description,evidence_kind='coverage-notice',maturity='advisory')

    def add(self,node,source,rule,title,cwe):
        if not source or source[0] not in {'input','model'}:return
        line=node.start_point.row+1
        self.findings.append(Finding(title=title,severity=Severity.HIGH,category=Category.SAST,module='sast',
            file_path=self.path,line_number=line,rule_id=rule,cwe=cwe,confidence='medium',maturity='advisory',
            evidence_kind='static-flow',description='A supported syntax-level source reaches the statement/command/HTML argument. '
                'Callback arguments are not treated as model output. Startup, branch feasibility and exploitability are unverified.',
            recommendation='Use structured arguments, parameterized statements and context-appropriate encoding; review the source/sink evidence.',
            code_snippet=redact_secrets('\n'.join(self.content.splitlines()[node.start_point.row:node.end_point.row+1])),
            trace=[dict(role='source',file_path=self.path,line_number=source[1]),dict(role='sink',file_path=self.path,line_number=line)]))

    def tick(self):
        self.steps+=1
        if self.steps>20000:raise AnalysisLimit()

    def block(self,node,env):
        if node is None:return
        self.tick()
        nodes=self.children(node)
        for child in nodes:
            if child.type=='function_declaration':
                name=self.text(self.field(child,'name'))
                self.functions[name]=child if name not in self.functions else None
                env[name]=Value(symbol='local:'+name)
        for child in nodes:
            if child.type in {'lexical_declaration','variable_declaration'}:
                for item in self.children(child):
                    if item.type!='variable_declarator':continue
                    target=self.field(item,'name');value=self.eval(self.field(item,'value'),env)
                    if target.type=='identifier':env[self.text(target)]=value
                    elif target.type=='object_pattern':
                        for part in self.children(target):
                            key=self.field(part,'key') or part
                            alias=self.field(part,'value') or part
                            env[self.text(alias)]=Value(symbol=value.symbol+'.'+self.text(key)) if value.symbol else Value()
            elif child.type=='import_statement':
                source=self.field(child,'source');package=self.eval(source,env).literal
                if isinstance(package,str):package=package.removeprefix('node:')
                for clause in self.children(child):
                    if clause.type!='import_clause':continue
                    for item in self.children(clause):
                        if item.type=='identifier':env[self.text(item)]=Value(symbol=str(package))
                        elif item.type=='namespace_import':env[self.text(item.named_children[-1])]=Value(symbol=str(package))
                        elif item.type=='named_imports':
                            for spec in self.children(item):
                                name=self.field(spec,'name');alias=self.field(spec,'alias') or name
                                env[self.text(alias)]=Value(symbol=str(package)+'.'+self.text(name))
            elif child.type=='function_declaration':self.function(child,env,[])
            elif child.type in {'statement_block','program'}:self.block(child,env)
            elif child.type in {'if_statement','switch_statement','try_statement','for_statement','while_statement','do_statement'}:
                if child.type=='if_statement':
                    condition=self.eval(self.field(child,'condition'),env).literal
                    if type(condition) is bool:
                        selected=self.field(child,'consequence' if condition else 'alternative')
                        if selected:self.block(selected,env) if selected.type in {'statement_block','else_clause'} else self.eval(selected,env)
                        continue
                initial=dict(env)
                for part in self.children(child):
                    branch=dict(initial)
                    self.block(part,branch) if part.type in {'statement_block','else_clause'} else self.eval(part,branch)
                    for key in set(env)|set(branch):
                        old,new=env.get(key,Value()),branch.get(key,Value())
                        if old!=new:env[key]=combine([old,new])
            elif child.type=='return_statement':
                for part in self.children(child):self.eval(part,env)
                break
            else:self.eval(child,env)

    def function(self,node,env,arguments,this=Value()):
        local=dict(env)
        parameters=self.field(node,'parameters')
        params=self.children(parameters) if parameters else [self.field(node,'parameter')]
        for index,param in enumerate(params):
            if param is not None:
                name=self.field(param,'pattern') or param
                local[self.text(name)]=arguments[index] if index<len(arguments) else Value()
        local['this']=this
        body=self.field(node,'body')
        if body and body.type=='statement_block':self.block(body,local)
        elif body:self.eval(body,local)
        # Closures may update existing outer variables asynchronously; retain possible
        # sources without asserting callback order or runtime reachability.
        for key in env:
            old,new=env[key],local.get(key,Value())
            if old!=new:env[key]=combine([old,new])

    def encoder(self,name,env):
        node=self.functions.get(name)
        if not node or env.get(name,Value()).symbol!='local:'+name or 'document' in env or '@dom-replaced' in env:return False
        params=self.children(self.field(node,'parameters'));body=self.children(self.field(node,'body'))
        if len(params)!=1 or params[0].type!='identifier' or len(body)!=1 or body[0].type!='return_statement':return False
        expression=self.children(body[0])
        if len(expression)!=1:return False
        # Only the complete pure expression is recognized, never a helper's name.
        text=re.sub(r'\s+','',self.text(expression[0]))
        param=re.escape(self.text(params[0]))
        return bool(re.fullmatch(r'''document\.createElement\(['"](?:a|div|span)['"]\)\.appendChild\(document\.createTextNode\('''+param+r'''\)\)\.parentNode\.innerHTML''',text))

    def eval(self,node,env):
        if node is None:return Value()
        self.tick()
        kind=node.type
        if kind in {'identifier','this'}:return env.get(self.text(node),Value(symbol=self.text(node) if self.text(node) in {'document','window','process'} else ''))
        if kind in {'string','string_fragment'}:
            literal=self.text(node)[1:-1] if kind=='string' else self.text(node)
            # Escape decoding is not a proof of a safe HTML context. Unknown
            # literals must not hide script/attribute delimiters introduced at runtime.
            return Value(literal=literal) if '\\' not in literal else Value()
        if kind in {'true','false'}:return Value(literal=kind=='true')
        if kind in {'number','null','comment'}:return Value()
        if kind in {'arrow_function','function_expression'}:return Value()
        if kind in {'parenthesized_expression','await_expression','as_expression','non_null_expression'}:
            return self.eval(self.children(node)[0],env) if self.children(node) else Value()
        if kind in {'member_expression','subscript_expression'}:
            owner=self.eval(self.field(node,'object'),env)
            prop=self.text(self.field(node,'property')) if kind=='member_expression' else str(self.eval(self.field(node,'index'),env).literal or '')
            symbol=owner.symbol+'.'+prop if owner.symbol else ''
            if owner.symbol=='request' and prop in {'body','query','params','headers','cookies'}:return Value(symbol=symbol,source=('input',node.start_point.row+1,False))
            if owner.symbol in {'document','window.document'} and prop in {'body','documentElement'}:return Value(symbol='DOM.Element')
            if owner.symbol=='DOM.Element' and prop=='value':return Value(source=('input',node.start_point.row+1,False))
            if symbol in {'window.location','process.argv'}:return Value(symbol=symbol,source=('input',node.start_point.row+1,False))
            source=owner.source
            if source and source[0]=='model-response' and prop in {'content','text','output_text'}:source=('model',source[1],False)
            return Value(symbol=symbol,source=source)
        if kind in {'assignment_expression','augmented_assignment_expression'}:
            left=self.field(node,'left');right=self.eval(self.field(node,'right'),env)
            if kind=='augmented_assignment_expression':right=combine([self.eval(left,env),right])
            if left.type=='identifier':env[self.text(left)]=right
            elif left.type=='member_expression':
                owner=self.eval(self.field(left,'object'),env)
                property_name=self.text(self.field(left,'property'))
                if owner.symbol=='document':env['@dom-replaced']=Value(symbol='replaced')
                if owner.symbol:env['@replaced:'+owner.symbol+'.'+property_name]=Value(symbol='replaced')
                if property_name=='innerHTML' and owner.symbol=='DOM.Element' and right.source and not html_text_safe(right):
                    self.add(node,right.source,'JS-SAST-XSS-001','External input reaches an HTML parsing sink','CWE-79')
            return right
        if kind=='object':
            statement=None
            for part in self.children(node):
                if part.type=='pair':
                    key=self.text(self.field(part,'key')).strip('\"\x27')
                    value=self.eval(self.field(part,'value'),env)
                    if key=='sql':statement=value
                elif part.type=='spread_element':statement=self.eval(part,env)
            return Value(symbol='sql-options',source=statement.source) if statement else Value(symbol='object')
        if kind in {'call_expression','new_expression'}:
            fn=self.field(node,'function') or self.field(node,'constructor')
            callee=self.eval(fn,env);name=callee.symbol
            args=self.children(self.field(node,'arguments'))
            values=[self.eval(arg,env) for arg in args]
            first=values[0] if values else Value()
            contract_replaced='@replaced:'+name in env
            if self.text(fn)=='require' and 'require' not in env and isinstance(first.literal,str):return Value(symbol=first.literal.removeprefix('node:'))
            name=name.removeprefix('node:')
            if name in {'express','express.Router'}:result=Value(symbol='express.Router')
            elif name in {'mysql.createConnection','mysql2.createConnection','mysql.createPool','mysql2.createPool','mysql2/promise.createConnection','mysql2/promise.createPool','db-mysql.Database'}:result=Value(symbol='database')
            elif name in {'openai','openai.OpenAI','@anthropic-ai/sdk'}:result=Value(symbol='model-client')
            elif name in {'document.getElementById','document.querySelector'}:result=Value(symbol='DOM.Element')
            elif name in {'model-client.responses.create','model-client.chat.completions.create','model-client.messages.create'}:result=Value(source=('model-response',node.start_point.row+1,False))
            else:result=combine([callee]+values)
            if contract_replaced:
                result=combine([callee]+values)
                self.findings.append(self.notice('JS-CONTRACT-001','JavaScript API contract reassigned',
                    'A supported imported API was reassigned; its original call contract was not assumed. Review the modified binding.'))
            if not contract_replaced and name in {'child_process.exec','child_process.execSync','child_process.spawn','child_process.execFile'}:
                command_source=first.source
                if len(args)>1 and args[1].type=='array':
                    operands=self.children(args[1])
                    if isinstance(first.literal,str) and first.literal.replace('\\','/').split('/')[-1] in {'sh','bash','dash','zsh','cmd','cmd.exe','powershell','pwsh','node','python','python3'}:
                        for position,operand in enumerate(operands[:-1]):
                            if self.eval(operand,env).literal in {'-c','/c','-Command','-command','-e'}:
                                command_source=self.eval(operands[position+1],env).source or command_source
                    shell_enabled=any(self.text(self.field(p,'key'))=='shell' and self.text(self.field(p,'value'))=='true'
                        for option in args[2:] if option.type=='object' for p in self.children(option) if p.type=='pair')
                    if shell_enabled:command_source=values[1].source or command_source
                self.add(node,command_source,'JS-SAST-CMD-001','External input controls process execution','CWE-78')
            if not contract_replaced and name in {'database.query','database.execute'} and first.source:
                self.add(node,first.source,'JS-SAST-SQL-001','External input is interpolated into a SQL statement','CWE-89')
            if self.text(fn)=='eval' and 'eval' not in env:
                self.add(node,first.source,'JS-SAST-EXEC-001','Untrusted input reaches code execution','CWE-94')
            localname=self.text(fn)
            if self.encoder(localname,env) and first.source:
                result=Value(source=(first.source[0],first.source[1],True))
            receiver=self.eval(self.field(fn,'object'),env) if fn and fn.type=='member_expression' else Value()
            for index,arg in enumerate(args):
                if arg.type not in {'arrow_function','function_expression'}:continue
                callback=[];this=Value()
                if not contract_replaced and name.startswith('express.Router.') and name.rsplit('.',1)[-1] in {'get','post','put','patch','delete','use','all'}:
                    callback=[Value(symbol='request'),Value(symbol='response')]
                elif not contract_replaced and name in {'http.request','https.request','http.get','https.get'}:callback=[Value(symbol='HTTPResponse')]
                elif not contract_replaced and name=='HTTPResponse.on' and first.literal=='data':callback=[Value(source=('input',arg.start_point.row+1,False))]
                elif not contract_replaced and name=='database.connect':this=Value(symbol='database')
                self.function(arg,env,callback,this)
            return result
        if kind=='pair':return self.eval(self.field(node,'value'),env)
        if kind in {'expression_statement','return_statement'}:
            return combine([self.eval(c,env) for c in self.children(node)])
        return combine([self.eval(c,env) for c in self.children(node)])
