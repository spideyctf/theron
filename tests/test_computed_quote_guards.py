"""An unsupported comparison operand must not become an analysis-state key."""
import pytest

from scanner.python_analysis import analyze_python


@pytest.mark.parametrize('operator',['in','not in'])
def test_computed_quote_guard_does_not_crash_or_hide_unrelated_sink(operator):
    code=f'''from flask import request
import os
def handle():
    value=request.args["value"]
    if "'" {operator} str(value):
        os.system(value)
'''
    findings=analyze_python('handler.py',code)
    assert any(f.cwe=='CWE-78' and f.line_number==6 for f in findings)
