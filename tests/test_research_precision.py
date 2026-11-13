"""Original controls: static analysis and parsing only; no eval/exec calls run."""
import ast
import hashlib
import io
import sys
from itertools import product

import pytest

from scanner.python_analysis import analyze_python
from scripts.evaluate_real_validation import reference_matches
from scripts import evaluate_real_validation as real_validation


GUARD = '''if not value.startswith("'") or not value.endswith("'") or "'" in value[1:-1]:
 raise ValueError()
'''


def findings(tail, guard=GUARD):
    code = 'from flask import request\nimport os\nvalue=request.args["text"]\n' + guard + tail
    return analyze_python('service.py',code)


@pytest.mark.parametrize('sink', ['eval(value)', 'exec(value)'])
def test_complete_literal_guard_prevents_code_injection(sink):
    assert not findings(sink)


@pytest.mark.parametrize('tail', [
    'value += "; dangerous()"\nexec(value)',
    'value = value + "; dangerous()"\nexec(value)',
    'value = request.args["other"]\nexec(value)',
    'exec(value+"; dangerous()")',
    'exec(value.strip("\'"))',
    'os.system(value)',
])
def test_literal_proof_does_not_cross_mutation_or_grammars(tail):
    assert findings(tail)


@pytest.mark.parametrize('guard', [
    GUARD.replace('or "\'" in value[1:-1]', ''),
    GUARD.replace('value.endswith', 'other.endswith'),
    GUARD.replace('value[1:-1]', 'value[2:-1]'),
    GUARD.replace('or', 'and'),
    GUARD.replace('raise ValueError()', 'pass'),
])
def test_incomplete_guards_remain_unsafe(guard):
    assert findings('exec(value)',guard)


def test_literal_guard_ablation():
    code='from flask import request\nvalue=request.args["x"]\n'+GUARD+'exec(value)'
    assert analyze_python('service.py',code,disabled_features=['sanitizers'])


@pytest.mark.filterwarnings('ignore:invalid escape sequence:SyntaxWarning')
def test_accepted_original_strings_parse_as_literals_or_fail():
    # Check lexical counterexamples without executing an expression.
    for size in range(5):
        for chars in product("'\\\n;x()0",repeat=size):
            value="'"+''.join(chars)+"'"
            if "'" in value[1:-1]:
                continue
            try:
                tree=ast.parse(value,mode='eval')
            except (SyntaxError,ValueError):
                continue
            assert isinstance(tree.body,ast.Constant) and isinstance(tree.body.value,str)


def test_hash_selection_is_explicitly_advisory():
    result=analyze_python('service.py',"import hashlib\ncache_key=hashlib.md5(b'data').hexdigest()")
    assert len(result)==1
    assert result[0].maturity=='advisory'
    assert result[0].evidence_kind=='static-configuration'
    assert 'security use unverified' in result[0].title


def test_reference_matching_requires_cwe_span_and_non_notice():
    f=dict(cwe='CWE-22',line_number=12,evidence_kind='static-flow')
    assert reference_matches([f],['CWE-22'],10,15)==[f]
    assert not reference_matches([f],['CWE-94'],10,15)
    assert not reference_matches([f],['CWE-22'],13,15)
    assert not reference_matches([dict(f,evidence_kind='coverage-notice')],['CWE-22'],10,15)


@pytest.mark.parametrize('mode', ['valid','bad_bytes','final_test','outside_path'])
def test_validation_fetch_checks_partition_paths_and_bytes(tmp_path,monkeypatch,mode):
    raw=b'# Original inert source fixture\n'
    row=dict(cve_id='original',repository='example/original',role='vul_func',revision='a'*40,
             path='app.py',source_sha256=hashlib.sha256(raw).hexdigest())
    cases={'original':dict(repository=row['repository'],locations=[dict(path='app.py',role='vul_func',resolution=dict(sha='a'*40))])}
    if mode=='final_test':
        row['cve_id']='closed-test'
    if mode=='outside_path':
        row['path']='../../outside.py'
    monkeypatch.setattr(real_validation,'validation_cases',lambda:cases)
    monkeypatch.setattr(real_validation,'read',lambda path:dict(records=[row]))
    monkeypatch.setattr(real_validation,'evaluate',lambda cache,exposure:dict(records=[]))
    requests=[]
    def download(url,timeout):
        requests.append(url)
        return io.BytesIO(b'changed' if mode=='bad_bytes' else raw)
    monkeypatch.setattr(real_validation.urllib.request,'urlopen',download)
    monkeypatch.setattr(sys,'argv',['probe','--fetch','--cache',str(tmp_path/'cache'),'--output',str(tmp_path/'result.json')])
    if mode=='valid':
        real_validation.main()
        assert (tmp_path/'cache/original/vul_func'/('a'*40)/'app.py').read_bytes()==raw
    else:
        with pytest.raises(ValueError):
            real_validation.main()
        if mode in {'final_test','outside_path'}:
            assert requests==[]
