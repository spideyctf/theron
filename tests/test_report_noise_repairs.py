import pytest
from scanner.models import ScanContext,ProjectProfile,Severity
from scanner.plugins.sast import SASTScanner
from scanner.plugins.ai_security import AISecurityScanner
from scanner.plugins.agentic import AgenticScanner
from scanner.python_analysis import analyze_python
from scanner.finding_utils import normalize_findings
from scanner.rule_loader import RuleLoader
from scanner.javascript_analysis import analyze_javascript


def scan(files,scanner=SASTScanner):
    return normalize_findings(scanner().scan(ScanContext(files,{},ProjectProfile(),RuleLoader(),{'include_experimental':True})))


@pytest.mark.parametrize('code',['from flask import request','@app.before_request\ndef before(): pass',
    'if request.method == "POST":\n    x=request.form["name"]', 'value=input()'])
def test_sql_fallback_needs_a_sql_sink(code):
    assert not [f for f in scan({'app.py':code}) if f.rule_id=='PY-SAST-006']


def test_sql_fallback_keeps_actual_unsafe_statement_candidates():
    assert any(f.rule_id=='PY-SAST-006' for f in scan({'app.py':'cursor.execute("SELECT "+request.args["x"])'}))


PREFIX='from flask import Flask,request,render_template_string,session\nfrom jinja2 import Template\napp=Flask(__name__)\n@app.route("/")\ndef run():\n'
RAW='request.args["text"]'
CLEAN=RAW+'.replace("{", "").replace("}", "")'


@pytest.mark.parametrize('expression',[CLEAN, '"Hello %s" % ('+CLEAN+')', '"Hello: " + ('+CLEAN+')'])
def test_default_template_text_filter_respected(expression):
    findings=analyze_python('app.py',PREFIX+'    text='+expression+'\n    return render_template_string(text)')
    assert not [f for f in findings if f.rule_id=='PY-SAST-SSTI-001']


@pytest.mark.parametrize('expression',[RAW, RAW+'.replace("{", "", 1)',
    CLEAN+'.replace("x", "{{")', CLEAN+'.encode().decode("unicode_escape")',
    '"{{" + ('+CLEAN+') + "}}"', '"{" + ('+CLEAN+') + "}"'])
def test_unsafe_or_reintroduced_template_syntax_still_reported(expression):
    assert any(f.rule_id=='PY-SAST-SSTI-001' for f in analyze_python('app.py',PREFIX+'    return render_template_string('+expression+')'))


def test_untrusted_format_string_does_not_crash_or_become_sanitized():
    assert any(f.rule_id=='PY-SAST-SSTI-001' for f in analyze_python('app.py',PREFIX+'    return render_template_string('+RAW+'.format("text"))'))


def test_jinja_constructor_and_custom_delimiters_are_not_missed():
    assert any(f.rule_id=='PY-SAST-SSTI-001' for f in analyze_python('app.py',PREFIX+'    return Template('+RAW+').render()'))
    assert any(f.rule_id=='PY-SAST-SSTI-001' for f in analyze_python('app.py',PREFIX+'    return Template('+CLEAN+', variable_start_string="[[",variable_end_string="]]").render()'))


def test_session_peer_address_and_listener_facts_do_not_inflate_vulnerability_totals():
    code=PREFIX+'    session["remembered"]='+RAW+'\n    import os\n    os.system(request.remote_addr)\napp.run(host="0.0.0.0",debug=True)'
    findings=scan({'app.py':code},AISecurityScanner)+scan({'app.py':code})
    facts=[f for f in findings if f.rule_id in {'PY-SAST-SESSION-001','PY-SHELL-PEER-001','AI-ID-001','AI-ID-003'}]
    assert len(facts)>=4 and all(f.severity==Severity.INFO for f in facts)
    assert all(f.evidence_kind in {'review-context','configuration-observation'} for f in facts)


def test_arbitrary_session_key_selection_is_still_a_trust_boundary_finding():
    findings=analyze_python('app.py',PREFIX+'    session[request.args["key"]]="selected value"')
    assert any(f.rule_id=='PY-SAST-SESSION-001' and f.severity==Severity.MEDIUM for f in findings)


@pytest.mark.parametrize('key',['role','user_id','authenticated'])
def test_security_state_key_contracts_remain_explicit_review_candidates(key):
    code=PREFIX+'    session['+repr(key)+']='+RAW
    findings=analyze_python('app.py',code)
    finding=next(f for f in findings if f.rule_id=='PY-SAST-SESSION-001')
    assert finding.severity==Severity.MEDIUM and finding.evidence_kind=='advisory-flow'
    assert 'not proof' in finding.description


def test_html_encoding_survives_ordinary_formatting():
    code=PREFIX+'    import html\n    return "Welcome {}".format(html.escape(request.args["name"]))'
    assert not [f for f in analyze_python('app.py',code) if f.rule_id=='PY-SAST-XSS-001']


def test_none_guard_and_conditional_template_snapshot_keep_only_valid_text_proofs():
    code=PREFIX+'    text=request.args.get("text")\n    if text is not None:\n        text=text.replace("{", "").replace("}", "")\n    template=None\n    if text is not None:\n        template="Welcome %s" % text\n    return render_template_string(template)'
    assert not [f for f in analyze_python('app.py',code) if f.rule_id=='PY-SAST-SSTI-001']
    unsafe=code.replace('"Welcome %s"','"{{%s}}"')
    assert any(f.rule_id=='PY-SAST-SSTI-001' for f in analyze_python('app.py',unsafe))
    other_input=code.replace('    template=None','    else:\n        text=request.args["other"]\n    template=None')
    assert any(f.rule_id=='PY-SAST-SSTI-001' for f in analyze_python('app.py',other_input))


def test_node_builtin_imports_and_destructured_aliases_keep_execution_flows():
    code=JS+"const {exec:run}=require('node:child_process');router.post('/',(req,res)=>{run(req.body.command);});"
    assert any(f.rule_id=='JS-SAST-CMD-001' for f in analyze_javascript('app.js',code))


def test_prose_does_not_establish_agent_permissions_but_instruction_files_remain_checked():
    prose='We allow shell commands and allow filesystem writes. Execute arbitrary code.'
    for scanner in (AgenticScanner,AISecurityScanner):
        assert not [f for f in scan({'README.md':prose},scanner) if f.rule_id.startswith(('AG-AP-','AI-PI-'))]
    assert any(f.rule_id=='AG-AP-001' for f in scan({'AGENTS.md':prose},AgenticScanner))


JS="const express=require('express');const router=express.Router();"
DB="const mysql=require('mysql');const db=mysql.createConnection({});"
SHELL="const {exec}=require('child_process');"


@pytest.mark.parametrize('statement',[
    'db.query("SELECT "+req.params.id,(err,result)=>{});',
    'const q={sql:"SELECT "+req.params.id};db.query(q,(err,result)=>{});',
    'db.query({\n sql:"SELECT "+req.params.id\n},(err,result)=>{});',
])
def test_multiline_and_aliased_sql_has_correct_source_not_callback_model_claim(statement):
    fs=analyze_javascript('app.js',JS+DB+"router.get('/',(req,res)=>{"+statement+'});')
    assert len([f for f in fs if f.rule_id=='JS-SAST-SQL-001'])==1
    assert not any('LLM' in f.title for f in fs)


@pytest.mark.parametrize('statement',[
    'db.query("SELECT ?",[req.params.id],(err,result)=>{});',
    'db.query("SELECT 1",(err,result)=>{});',
    'const result="SELECT 1";db.query(result);',
    'db.query=custom;db.query(req.params.id);',
    'db.query({sql:"SELECT ?",values:[req.params.id]});',
])
def test_parameterized_fixed_and_reassigned_calls_are_not_sql_injection(statement):
    assert not [f for f in analyze_javascript('app.ts',JS+DB+"router.get('/',(req,res)=>{"+statement+'});') if f.rule_id=='JS-SAST-SQL-001']


def test_multiline_shell_sources_and_fixed_executable_arguments():
    fs=analyze_javascript('app.js',JS+SHELL+"router.post('/',(req,res)=>{exec(\n 'gzip '+req.query.path,\n()=>{});});")
    assert any(f.rule_id=='JS-SAST-CMD-001' for f in fs)
    safe=JS+"const {spawn}=require('child_process');router.post('/',(req,res)=>{spawn('gzip',[req.query.path]);});"
    assert not [f for f in analyze_javascript('app.js',safe) if f.rule_id=='JS-SAST-CMD-001']


@pytest.mark.parametrize('call',["spawn('sh',['-c',req.body.command])", "spawn('echo',[req.body.command],{shell:true})"])
def test_interpreter_flags_and_shell_options_are_not_mistaken_for_safe_arrays(call):
    code=JS+"const {spawn}=require('child_process');router.post('/',(req,res)=>{"+call+';});'
    assert any(f.rule_id=='JS-SAST-CMD-001' for f in analyze_javascript('app.js',code))


ENCODER="function encodeText(s){return document.createElement('a').appendChild(document.createTextNode(s)).parentNode.innerHTML;}"
DOM="const input=document.getElementById('name').value;const target=document.getElementById('welcome');"


@pytest.mark.parametrize('prefix,sink,unsafe',[
    (ENCODER,'target.innerHTML="Welcome "+encodeText(input);',False),
    ('function encodeText(s){return s;}','target.innerHTML=encodeText(input);',True),
    (ENCODER+'encodeText=custom;','target.innerHTML=encodeText(input);',True),
    (ENCODER+'if(flag){encodeText=custom;}','target.innerHTML=encodeText(input);',True),
    (ENCODER+'document.createTextNode=custom;','target.innerHTML=encodeText(input);',True),
    (ENCODER,'target.innerHTML=input;',True),
    (ENCODER,'target.innerHTML=encodeText(input)+input;',True),
    (ENCODER,'target.innerHTML=\'<a title="\'+encodeText(input)+\'">link</a>\';',True),
    (ENCODER,'target.innerHTML="<script>"+encodeText(input)+"</script>";',True),
    (ENCODER,'target.innerHTML="<b>"+encodeText(input)+"</b>";',False),
    (ENCODER,'target.innerHTML="\\x3cscript>"+encodeText(input)+"</script>";',True),
    (ENCODER,'target.innerHTML+=input;',True),
])
def test_dom_sanitizer_needs_the_complete_supported_contract(prefix,sink,unsafe):
    fs=analyze_javascript('app.js',prefix+DOM+sink)
    assert bool([f for f in fs if f.rule_id=='JS-SAST-XSS-001'])==unsafe


def test_names_and_comments_do_not_invent_sources_and_parse_failures_remain_visible():
    assert not analyze_javascript('app.js','eval(userInput); // exec(req.body.x)\nconst note="query(modelResult)";')
    assert any(f.rule_id=='JS-PARSE-001' for f in analyze_javascript('app.js','const broken = ('))
    assert not [f for f in analyze_javascript('app.js',JS+SHELL+"router.get('/',(req,res)=>{if(false){exec(req.body.x);}});") if f.severity!=Severity.INFO]


def test_model_output_requires_actual_sdk_binding_and_produces_a_source_trace():
    code="import OpenAI from 'openai'; const client=new OpenAI();const answer=await client.responses.create({});eval(answer.output_text);"
    assert any(f.rule_id=='JS-SAST-EXEC-001' and f.trace for f in analyze_javascript('app.ts',code))


def test_reassigned_framework_contract_does_not_invent_request_sources():
    code=JS+SHELL+"router.post=custom;router.post('/',(req,res)=>{exec(req.body.command);});"
    assert not [f for f in analyze_javascript('app.js',code) if f.rule_id=='JS-SAST-CMD-001']
