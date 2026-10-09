"""API tests use a controlled scanner; no network calls or real credentials."""
import time
from threading import Event

import pytest
import requests

pytest.importorskip("fastapi", reason="Install the web extra to run API tests.")
from fastapi.testclient import TestClient

from scanner.models import Category, Finding, ScanResult, Severity
from scanner.finding_utils import normalize_findings
from scanner.web import create_app, failure_message, repository_name


def result():
    findings = normalize_findings([Finding(
        title="Unsafe model load", severity=Severity.HIGH,
        category=Category.INSECURE_MODEL_DEPLOYMENT, module="ai",
        description="Evidence", file_path="models.py", line_number=3,
        recommendation="Use a safe format.", rule_id="TEST-001",
    )])
    return ScanResult(repo_full_name="owner/repo", branch="main", findings=findings, files_scanned=1, modules_run=["ai"])


def wait_for(client, scan_id, status):
    for _ in range(100):
        job = client.get("/api/scans/" + scan_id).json()
        if job["status"] == status:
            return job
        time.sleep(0.01)
    raise AssertionError("Scan never reached " + status)


def test_scan_lifecycle_queue_and_reports(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token-never-returned")
    started, release = Event(), Event()
    calls = []
    class ControlledScanner:
        def __init__(self, token, config):
            assert token == "test-token-never-returned"
            self.config = config
        def scan_repo(self, owner, repo, branch, modules):
            calls.append((owner, repo, branch, modules, self.config))
            started.set()
            assert release.wait(5)
            return result()
    with TestClient(create_app(ControlledScanner)) as client:
        first = client.post("/api/scans", json={"repository": "https://github.com/owner/repo", "modules": ["ai"]})
        assert first.status_code == 202
        scan_id = first.json()["id"]
        assert started.wait(2)
        assert client.get("/api/scans/" + scan_id).json()["status"] == "running"
        second_id = client.post("/api/scans", json={"repository": "owner/repo"}).json()["id"]
        assert client.get("/api/scans/" + second_id).json()["status"] == "queued"
        assert client.get("/api/scans/" + scan_id + "/report").status_code == 409
        release.set()
        job = wait_for(client, scan_id, "completed")
        assert job["result"]["findings"][0]["fingerprint"]
        assert job["finished_at"]
        assert calls[0][:4] == ("owner", "repo", None, ["ai"])
        report = client.get("/api/scans/" + scan_id + "/report?format=json")
        assert report.json()["repo_full_name"] == "owner/repo"
        assert "attachment" in report.headers["content-disposition"]
        sarif = client.get("/api/scans/" + scan_id + "/report?format=sarif").json()
        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["results"][0]["partialFingerprints"]
        assert client.get("/api/scans/" + scan_id + "/report?format=html").status_code == 422
        assert "test-token-never-returned" not in str(client.get("/api/scans").json())
        assert client.get("/api/health").json() == {"status": "ok", "github_token_configured": True}


@pytest.mark.parametrize("body", [
    {"repository": "https://evil.example/owner/repo"},
    {"repository": "owner/repo/tree/main"},
    {"repository": "owner/.."},
    {"repository": "owner/repo", "modules": []},
    {"repository": "owner/repo", "modules": ["bogus"]},
    {"repository": "owner/repo", "modules": ["ai", "ai"]},
    {"repository": "owner/repo", "branch": "../main"},
])
def test_invalid_inputs(monkeypatch, body):
    monkeypatch.setenv("GITHUB_TOKEN", "fake")
    with TestClient(create_app()) as client:
        assert client.post("/api/scans", json=body).status_code == 422
        assert client.get("/api/scans").json() == []


def test_missing_token_and_external_origin(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    with TestClient(create_app()) as client:
        assert client.get("/api/health").json()["github_token_configured"] is False
        assert client.post("/api/scans", json={"repository": "owner/repo"}).status_code == 503
        assert client.post("/api/scans", json={"repository": "owner/repo"}, headers={"origin": "https://external.test"}).status_code == 403
        assert client.get("/api/scans/missing").status_code == 404


def test_failed_scan_does_not_expose_exception_or_token(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "sensitive-token")
    class FailingScanner:
        def __init__(self, *args, **kwargs):
            raise ValueError("sensitive-token in a header")
    with TestClient(create_app(FailingScanner)) as client:
        scan_id = client.post("/api/scans", json={"repository": "owner/repo"}).json()["id"]
        job = wait_for(client, scan_id, "failed")
        assert "sensitive-token" not in str(job)
        assert "failed" in job["error"].lower()


@pytest.mark.parametrize("code, expected", [(401, "authentication"), (403, "rate limit"), (404, "not found")])
def test_http_error_messages(code, expected):
    response = requests.Response()
    response.status_code = code
    assert expected in failure_message(requests.HTTPError(response=response)).lower()


def test_timeout_and_repository_normalization():
    assert "in time" in failure_message(requests.Timeout("secret"))
    assert repository_name(" https://github.com/owner/repo.git/ ") == "owner/repo"


def test_built_frontend_static_files():
    from pathlib import Path
    dist = Path(__file__).resolve().parents[1] / "frontend" / "dist"
    if not dist.is_dir():
        pytest.skip("Build the frontend to verify production serving.")
    with TestClient(create_app(static_dir=dist)) as client:
        response = client.get("/")
        assert response.status_code == 200
        assert "Security workspace" in response.text
        assert client.get("/api/health").status_code == 200
