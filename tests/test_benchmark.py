"""Benchmark adapter tests use original miniature fixtures, not third-party code."""

import csv
import pytest

from scanner.benchmark import evaluate, target_span
from scanner.python_analysis import analyze_python


def test_qualified_target_span():
    assert target_span("class Service:\n def run(self):\n  def nested():\n   return 1\n", "Service.run.nested") == (3, 4)
    assert target_span("def run():\n pass", "missing") is None


def test_benchmark_scores_locations_types_and_missing_labels(tmp_path):
    root = tmp_path / "SyntheticDataset" / "94"
    root.mkdir(parents=True)
    with (tmp_path / "SyntheticDataset.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["TestCase", "CWE Type", "Vul Position"])
        writer.writerows([["94_A", "94", "danger"], ["94_B", "94", "danger"], ["94_C", "94", "typo"]])
    (root / "94_A_vul.py").write_text("def danger():\n exec(input())", encoding="utf-8")
    (root / "94_A_fix.py").write_text("def safe():\n return input()", encoding="utf-8")
    (root / "94_B_vul.py").write_text("def unrelated():\n exec(input())\ndef danger():\n return 1", encoding="utf-8")
    (root / "94_B_fix.py").write_text("def danger():\n exec(input())\ndef other():\n exec(input())", encoding="utf-8")
    (root / "94_C_vul.py").write_text("def danger():\n exec(input())", encoding="utf-8")
    (root / "94_C_fix.py").write_text("def safe():\n return 1", encoding="utf-8")
    result = evaluate(tmp_path)
    assert result["summary"] == {"tp": 1, "fn": 1, "fp": 1, "tn": 2, "errors": 1,
                                 "precision": .5, "recall": .5, "false_positive_rate": 1/3}
    assert result["cases"][1]["fixed_target_scope"].startswith("whole file")
    assert result["cases"][2]["unrelated_alerts"] == 1
    assert result["cases"][4]["outcome"] == "error"
    assert result["fixed_file_alerts"] == {"files_with_any_alert": 1, "total_alerts": 2, "outside_label_match": 1}


@pytest.mark.parametrize("code,rule", [
    ('from flask import request\nimport sqlite3\nconn = sqlite3.connect(":memory:")\ncursor = conn.cursor()\nq = "SELECT * FROM records WHERE name = \'{}\'".format(request.args.get("name"))\ncursor.execute(q)', "PY-SAST-SQL-001"),
    ('from sqlite3 import connect as db\nfrom bottle import request\nconn = db(":memory:")\nconn.execute(f"SELECT {request.query.get(\"field\")}")', "PY-SAST-SQL-001"),
    ('from quart import request\nimport sqlite3\nasync def search():\n data = await request.get_json()\n conn = sqlite3.connect(":memory:")\n conn.execute(f"SELECT {data.get(\"field\")}")', "PY-SAST-SQL-001"),
    ('from fastapi import FastAPI, Query\nimport sqlite3\napp = FastAPI()\n@app.get("/search")\ndef search(q: str = Query(...)):\n conn = sqlite3.connect(":memory:")\n conn.execute(f"SELECT {q}")', "PY-SAST-SQL-001"),
    ('import os\ndef run(command):\n os.system(command)\nrun(input().strip())', "PY-SAST-EXEC-001"),
    ('import pickle\nfrom flask import request\nclass Loader:\n def load(self, data):\n  pickle.loads(data)\nloader = Loader()\nloader.load(request.files["upload"].read())', "PY-AI-MODEL-001"),
    ('import os\ndef run(command, mode="shell"):\n os.system(command)\nrun(command=input())', "PY-SAST-EXEC-001"),
])
def test_benchmark_driven_positive_flows(code, rule):
    findings = analyze_python("app.py", code)
    assert any(finding.rule_id == rule for finding in findings)


@pytest.mark.parametrize("code", [
    'from flask import request\nimport sqlite3\nconn = sqlite3.connect(":memory:")\nconn.execute("SELECT * FROM records WHERE name = ?", (request.args.get("name"),))',
    'from flask import request\nclass Store:\n def execute(self, value):\n  return value\nstore = Store()\nstore.execute(request.args.get("q"))',
    'import sqlite3\nconn = sqlite3.connect(":memory:")\nx = input()\nif x not in {"name", "id"}:\n raise ValueError()\nconn.execute(f"SELECT {x}")',
    'from fastapi import FastAPI\nimport sqlite3\nALLOWED = {"id", "name"}\napp = FastAPI()\n@app.get("/search")\ndef search(column: str):\n if column not in ALLOWED:\n  return "invalid"\n conn = sqlite3.connect(":memory:")\n conn.execute(f"SELECT {column}")',
    'import sqlite3\nfrom flask import request\nconn = sqlite3.connect(":memory:")\nnumber = request.args.get("n", type=int)\nconn.execute(f"SELECT {number}")',
    'from fastapi import FastAPI\nimport sqlite3\napp = FastAPI()\n@app.get("/search")\ndef search(number: int):\n conn = sqlite3.connect(":memory:")\n conn.execute(f"SELECT {number}")',
    'import os\ndef run(command):\n os.system(command)\nrun("echo hello")',
    'import os\ndef run(command, required):\n os.system(command)\nrun(input())',
    'import os\ndef run(command):\n os.system(command)\nrun(input(), "extra")',
    'import os\ndef run(command):\n os.system(command)\nrun("safe", command=input())',
    'import os\ndef run(command, /):\n os.system(command)\nrun(command=input())',
    'import os\ndef run(command):\n command = "echo safe"\n os.system(command)\nrun(input())',
])
def test_benchmark_driven_near_misses(code):
    assert analyze_python("safe.py", code) == []


def test_allowlist_mutation_is_not_treated_as_validation():
    code = 'import sqlite3\ncolumns = ["id"]\nx = input()\ncolumns.append(x)\nif x in columns:\n conn = sqlite3.connect(":memory:")\n conn.execute(f"SELECT {x}")'
    assert any(f.cwe == "CWE-89" for f in analyze_python("app.py", code))


def test_recursion_is_bounded():
    code = 'def run(command):\n run(command)\nrun(input())'
    assert analyze_python("app.py", code) == []


def test_keyword_only_helper_flow():
    code = 'import os\ndef run(*, command):\n os.system(command)\nrun(command=input())'
    assert any(f.cwe == "CWE-78" for f in analyze_python("app.py", code))


def test_shadowed_global_allowlist_does_not_suppress():
    code = 'import sqlite3\nALLOWED = {"id"}\nx = input()\ndef query(ALLOWED, x):\n if x in ALLOWED:\n  conn = sqlite3.connect(":memory:")\n  conn.execute(f"SELECT {x}")\nquery([x], x)'
    assert any(f.cwe == "CWE-89" for f in analyze_python("app.py", code))
