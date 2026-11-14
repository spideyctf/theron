import pytest
from tests.test_security_obligations import findings

BASE='''import lxml.html,lxml.html.clean,unicodedata,re
def clean(raw):
 doc=lxml.html.fromstring(raw)
 lxml.html.clean.Cleaner()(doc)
 text=lxml.html.tostring(doc,encoding="unicode")
{body}
'''


def scan(body):
    return [f for f in findings(BASE.format(body='\n'.join(' '+line for line in body.splitlines()))) if f.rule_id.startswith('PY-OBL-HTML-ORDER')]


@pytest.mark.parametrize('form',['NFKC','NFKD'])
def test_returned_compatibility_normalization_follows_cleaning(form):
    fs=scan(f'text=unicodedata.normalize("{form}",text)\nreturn text')
    assert fs and fs[0].cwe=='CWE-79' and fs[0].severity.value=='MEDIUM'
    assert fs[0].obligation['related_locations'][0]['role']=='cleaning'


@pytest.mark.parametrize('body',[
 'return text',
 'return unicodedata.normalize("NFC",text)',
 'return unicodedata.normalize("NFKC",other)',
 'text="fixed"\nreturn unicodedata.normalize("NFKC",text)',
 'import html\nreturn html.escape(unicodedata.normalize("NFKC",text))',
 'text=unicodedata.normalize("NFKC",text)\nreturn "fixed"',
])
def test_noncompatibility_unrelated_replaced_or_unexposed_values_do_not_alert(body):
    assert not scan(body)


def test_normalize_before_cleaning_is_not_the_antipattern():
    code=BASE.format(body=' return text').replace(' doc=lxml.html.fromstring(raw)',' raw=unicodedata.normalize("NFKC",raw)\n doc=lxml.html.fromstring(raw)')
    assert not any(f.rule_id.startswith('PY-OBL-HTML-ORDER') for f in findings(code))


def test_local_cleaner_return_pipeline_and_aliases_are_tracked():
    code='from lxml_html_clean import Cleaner\nfrom unicodedata import normalize\ndef clean(raw):\n cleaner=Cleaner()\n text=cleaner.clean_html(raw)\n alias=text\n return normalize("NFKC",alias)'
    assert any(f.rule_id=='PY-OBL-HTML-ORDER-001' for f in findings(code))


def test_local_parser_import_in_fallback_does_not_hide_ordering():
    code=BASE.format(body=' return unicodedata.normalize("NFKC",text)').replace(' doc=lxml.html.fromstring(raw)',
        ' try:\n  doc=lxml.html.fromstring(raw)\n except ValueError:\n  from lxml.html import soupparser\n  doc=soupparser.fromstring(raw)')
    assert any(f.rule_id=='PY-OBL-HTML-ORDER-001' for f in findings(code))


def test_shadowed_normalizer_is_not_resolved_to_the_library():
    code=BASE.format(body=' unicodedata=custom\n return unicodedata.normalize("NFKC",text)')
    assert not any(f.rule_id=='PY-OBL-HTML-ORDER-001' for f in findings(code))
