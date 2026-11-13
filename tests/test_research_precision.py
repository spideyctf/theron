"""Original controls: static analysis and parsing only; no eval/exec calls run."""
import ast
from itertools import product

import pytest

from scanner.python_analysis import analyze_python


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
