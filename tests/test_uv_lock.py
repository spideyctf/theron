import json
import pytest
from scanner.models import ScanContext, ProjectProfile
from scanner.plugins.sca import SCAScanner
from scanner.python_lock import uv_inventory
from scanner.rule_loader import RuleLoader
from scanner.utils.helpers import should_scan_file
from tests.osv_delivery_fixture import RECORD

LOCK = '''version = 1
revision = 3
[[package]]
name = "demo"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
'''


def scan(files, monkeypatch):
    calls = []
    def query(self, name, version, ecosystem):
        calls.append((name, version, ecosystem))
        return [RECORD]
    monkeypatch.setattr(SCAScanner, '_query_osv', query)
    scanner = SCAScanner()
    findings = scanner.scan(ScanContext(files, {}, ProjectProfile(), RuleLoader(), {}))
    return scanner, findings, calls


def test_lock_queries_exact_version_and_carries_source_provenance(monkeypatch):
    scanner, findings, calls = scan({'uv.lock': LOCK, 'requirements.txt': 'Demo>=0.5'}, monkeypatch)
    assert calls == [('demo', '1.0', 'PyPI')]
    finding = next(f for f in findings if f.dependency)
    assert finding.file_path == 'uv.lock'
    assert finding.dependency['lock_provenance']['installation_verified'] is False
    assert len(finding.dependency['lock_provenance']['source_text_sha256']) == 64
    assert 'target environment' in finding.dependency['matching']
    bom = scanner.generate_sbom({'uv.lock': LOCK})
    assert bom['components'][0]['version'] == '1.0'
    assert 'locked inventory' in json.dumps(bom)
    assert should_scan_file('nested/uv.lock') and not should_scan_file('.venv/uv.lock')


@pytest.mark.parametrize('lock', [
    LOCK.replace('https://pypi.org/simple', 'https://private.example/simple'),
    LOCK.replace('registry = "https://pypi.org/simple"', 'git = "https://example.invalid/repo"'),
    LOCK.replace('source =', 'resolution-markers = ["sys_platform == \'win32\'"]\nsource ='),
    LOCK + LOCK[LOCK.index('[[package]]'):].replace('"1.0"', '"2.0"'),
    LOCK.replace('"1.0"', '"main"'),
])
def test_ambiguous_conditional_and_non_pypi_inventory_never_queries(lock, monkeypatch):
    scanner, findings, calls = scan({'uv.lock': lock}, monkeypatch)
    assert not calls and any(f.rule_id == 'SCA-UV-UNRESOLVED-001' for f in findings)
    assert all('version' not in c for c in scanner.generate_sbom({'uv.lock': lock})['components'])


@pytest.mark.parametrize('lock', ['not toml', 'version=2\npackage=[]', 'version=1\nrevision=99\npackage=[]',
                                  'version=1\npackage="bad"', 'version=1\n[[package]]\nname=3'])
def test_malformed_or_future_schema_remains_a_coverage_notice(lock, monkeypatch):
    _, findings, calls = scan({'uv.lock': lock}, monkeypatch)
    assert not calls and any(f.rule_id == 'SCA-UV-PARSE-001' for f in findings)


def test_nearest_lock_does_not_replace_another_project_manifest(monkeypatch):
    _, findings, calls = scan({'sub/uv.lock': LOCK, 'requirements.txt': 'demo==2.0'}, monkeypatch)
    assert set(calls) == {('demo', '1.0', 'PyPI'), ('demo', '2.0', 'PyPI')}


def test_stale_lock_conflicting_with_exact_manifest_is_not_used_as_resolution(monkeypatch):
    _, findings, calls = scan({'uv.lock': LOCK, 'requirements.txt': 'demo==2.0'}, monkeypatch)
    assert calls == [('demo', '2.0', 'PyPI')]
    assert any(f.rule_id == 'SCA-UV-CONFLICT-001' for f in findings)


def test_local_cli_collects_lock_and_delivers_advisory(tmp_path, monkeypatch):
    from scanner.cli import main
    (tmp_path/'uv.lock').write_text(LOCK)
    monkeypatch.setattr(SCAScanner, '_query_osv', lambda *a: [RECORD])
    output = tmp_path.parent/'lock-report.json'
    monkeypatch.setattr('sys.argv', ['ai-sec-scan', '--local', str(tmp_path), '--modules', 'sca', '--format', 'json', '--output', str(output)])
    main()
    result = json.loads(output.read_text())
    assert result['findings'][0]['dependency']['manifest'] == 'uv.lock'
    assert result['sbom']['components'][0]['version'] == '1.0'
