"""Archive source/filter controls. No extraction or target imports are executed."""
import pytest

from scanner.python_analysis import analyze_python
from scanner.models import Severity


def archive_findings(code):
    return [f for f in analyze_python('app.py',code) if f.rule_id.startswith('PY-SAST-ARCHIVE')]


@pytest.mark.parametrize('policy',["'data'",'tarfile.data_filter'])
def test_explicit_data_filter_is_observed(policy):
    assert not archive_findings(f'import tarfile\nwith tarfile.open("bundle.tar") as t:\n t.extractall("/srv",filter={policy})')


def test_default_runtime_is_not_guessed_as_unsafe():
    fs=archive_findings('import tarfile\nwith tarfile.open("bundle.tar") as t:\n t.extractall("/srv")')
    assert len(fs)==1 and fs[0].severity==Severity.INFO and fs[0].cwe is None
    assert fs[0].maturity=='advisory'
    assert '3.14' in fs[0].description


def test_explicit_fully_trusted_filter_with_external_file_object_has_flow():
    code='from flask import request\nimport tarfile,io\nt=tarfile.open(fileobj=io.BytesIO(request.get_data()))\nt.extractall("/srv",filter="fully_trusted")'
    fs=archive_findings(code)
    assert len(fs)==1 and fs[0].severity==Severity.HIGH
    assert fs[0].cwe=='CWE-22' and fs[0].evidence_kind=='static-flow'
    assert fs[0].trace[0]['line_number']==3


def test_archive_filename_alone_does_not_establish_control_of_archive_bytes():
    fs=archive_findings('from flask import request\nimport tarfile\nt=tarfile.open(request.args["name"])\nt.extractall("/srv",filter="fully_trusted")')
    assert len(fs)==1 and fs[0].maturity=='advisory' and fs[0].evidence_kind=='static-configuration'


def test_instance_filter_does_not_leak_to_another_archive():
    fs=archive_findings('import tarfile\na=tarfile.open("a.tar")\nb=tarfile.open("b.tar")\na.extraction_filter=tarfile.data_filter\na.extractall("/srv/a")\nb.extractall("/srv/b")')
    assert len(fs)==1 and fs[0].line_number==6


def test_class_filter_staticmethod_is_recognized():
    assert not archive_findings('import tarfile\ntarfile.TarFile.extraction_filter=staticmethod(tarfile.data_filter)\na=tarfile.open("a.tar")\na.extractall("/srv")')


@pytest.mark.parametrize('code',[
 'from custom import tarfile\nt=tarfile.open("a.tar")\nt.extractall("/srv")',
 'import tarfile\ntarfile=object()\nt=tarfile.open("a.tar")\nt.extractall("/srv")',
])
def test_unrelated_extractors_are_not_guessed(code):
    assert not archive_findings(code)


def test_custom_filters_remain_review_items():
    fs=archive_findings('import tarfile\ndef validate(member,path):\n return member\nt=tarfile.open("a.tar")\nt.extractall("/srv",filter=validate)')
    assert len(fs)==1 and fs[0].severity==Severity.INFO


def test_import_alias_and_member_extract():
    fs=archive_findings('from tarfile import open as read_archive\nt=read_archive("a.tar")\nt.extract("member",filter="fully_trusted")')
    assert len(fs)==1 and fs[0].maturity=='advisory'
