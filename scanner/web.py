"""Local, single-user web API. Start with `theron-web` (web extra required)."""

import argparse
import os
import re
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import List, Optional
from urllib.parse import urlparse
from uuid import uuid4

import requests
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from scanner.engine import ScanEngine
from scanner.reporters.json_reporter import generate_json_report
from scanner.reporters.sarif import generate_sarif_report


MODULES = {"ai", "sast", "sca", "agentic"}


class ScanRequest(BaseModel):
    repository: str = Field(min_length=3, max_length=250)
    branch: Optional[str] = Field(default=None, max_length=250)
    modules: List[str] = Field(default_factory=lambda: ["ai", "sast", "sca", "agentic"])
    include_experimental: bool = False


def repository_name(value: str) -> str:
    value = value.strip()
    if value.startswith("https://"):
        url = urlparse(value)
        if url.netloc != "github.com" or url.query or url.fragment:
            raise ValueError("Use a github.com repository URL or owner/repo.")
        value = url.path.strip("/")
    value = value.removesuffix(".git") if hasattr(value, "removesuffix") else re.sub(r"\.git$", "", value)
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_.-]{1,100}", value):
        raise ValueError("Use a GitHub repository URL or owner/repo, without extra paths.")
    if value.split("/")[1] in {".", ".."}:
        raise ValueError("Invalid repository name.")
    return value


def failure_message(exc: Exception) -> str:
    """Do not return exception strings: URLs, headers or secrets may be embedded."""
    if isinstance(exc, requests.Timeout):
        return "GitHub did not respond in time. Try again in a moment."
    if isinstance(exc, requests.HTTPError) and exc.response is not None:
        code = exc.response.status_code
        if code == 401:
            return "GitHub authentication failed. Check the backend GITHUB_TOKEN."
        if code == 403:
            return "GitHub denied access or its rate limit was reached. Check token permissions and retry later."
        if code == 404:
            return "Repository or branch not found, or your token cannot access it."
    if isinstance(exc, requests.RequestException):
        return "Cannot connect to GitHub. Check your connection and retry."
    if isinstance(exc, RuntimeError) and "rate limit" in str(exc).lower():
        return "GitHub rate limit reached. Retry after the rate limit resets."
    if isinstance(exc, RuntimeError) and "tree is too large" in str(exc).lower():
        return "This repository is too large for a complete GitHub tree scan. Use the CLI on a local checkout."
    return "The scan failed. Check the backend and retry."


def create_app(scanner_factory=ScanEngine, static_dir=None):
    jobs = {}
    results = {}
    lock = Lock()
    worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix="theron-scan")

    @asynccontextmanager
    async def lifespan(app):
        yield
        worker.shutdown(wait=True, cancel_futures=True)

    app = FastAPI(title="Theron local API", lifespan=lifespan)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "[::1]", "testserver"])

    @app.middleware("http")
    async def local_requests(request: Request, call_next):
        origin = request.headers.get("origin")
        if origin and urlparse(origin).hostname not in {"localhost", "127.0.0.1", "::1"}:
            return JSONResponse({"detail": "Only local browser origins are allowed."}, status_code=403)
        return await call_next(request)

    def public(job):
        return dict(job)

    def run_scan(scan_id, body, token):
        with lock:
            jobs[scan_id]["status"] = "running"
        engine = None
        try:
            engine = scanner_factory(token, config={"include_experimental": body.include_experimental})
            owner, repo = body.repository.split("/")
            result = engine.scan_repo(owner, repo, branch=body.branch, modules=body.modules)
            with lock:
                results[scan_id] = result
                jobs[scan_id]["status"] = "completed"
                jobs[scan_id]["result"] = result.to_dict()
        except Exception as exc:
            with lock:
                jobs[scan_id]["status"] = "failed"
                jobs[scan_id]["error"] = failure_message(exc)
        finally:
            with lock:
                jobs[scan_id]["finished_at"] = datetime.now(timezone.utc).isoformat()
            if engine and hasattr(engine, "github"):
                engine.github.session.close()

    @app.get("/api/health")
    def health():
        return {"status": "ok", "github_token_configured": bool(os.environ.get("GITHUB_TOKEN"))}

    @app.post("/api/scans", status_code=202)
    def submit(body: ScanRequest):
        try:
            body.repository = repository_name(body.repository)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        if not body.modules or len(set(body.modules)) != len(body.modules) or not set(body.modules) <= MODULES:
            raise HTTPException(422, "Select one or more unique modules: ai, sast, sca, agentic.")
        if body.branch is not None:
            body.branch = body.branch.strip() or None
            if body.branch and (any(ord(c) < 32 for c in body.branch) or ".." in body.branch or body.branch.startswith("-")):
                raise HTTPException(422, "Invalid branch name.")
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            raise HTTPException(503, "Set GITHUB_TOKEN in the backend environment to enable live scans.")
        scan_id = uuid4().hex
        with lock:
            if sum(job["status"] in {"queued", "running"} for job in jobs.values()) >= 10:
                raise HTTPException(429, "Scan queue is full. Wait for a scan to finish.")
            jobs[scan_id] = {
                "id": scan_id, "repository": body.repository, "branch": body.branch,
                "modules": body.modules, "include_experimental": body.include_experimental,
                "status": "queued", "created_at": datetime.now(timezone.utc).isoformat(),
                "finished_at": None, "error": None, "result": None,
            }
        worker.submit(run_scan, scan_id, body, token)
        return {"id": scan_id}

    @app.get("/api/scans")
    def list_scans():
        with lock:
            return [{key: value for key, value in job.items() if key != "result"}
                    for job in reversed(list(jobs.values()))]

    @app.get("/api/scans/{scan_id}")
    def get_scan(scan_id: str):
        with lock:
            if scan_id not in jobs:
                raise HTTPException(404, "Scan not found. Session history resets when the backend restarts.")
            return public(jobs[scan_id])

    @app.get("/api/scans/{scan_id}/report")
    def report(scan_id: str, format: str = "json"):
        if format not in {"json", "sarif"}:
            raise HTTPException(422, "Report format must be json or sarif.")
        with lock:
            if scan_id not in jobs:
                raise HTTPException(404, "Scan not found.")
            result = results.get(scan_id)
        if result is None:
            raise HTTPException(409, "Reports are available after a scan completes.")
        content = generate_json_report(result) if format == "json" else generate_sarif_report(result)
        name = result.repo_full_name.replace("/", "_")
        return Response(content, media_type="application/json", headers={
            "Content-Disposition": f'attachment; filename="theron_{name}.{format}"',
        })

    # API routes must precede the static mount. Vite proxies /api in development.
    dist = Path(static_dir) if static_dir else Path(__file__).resolve().parents[1] / "frontend" / "dist"
    if dist.is_dir():
        app.mount("/", StaticFiles(directory=dist, html=True), name="frontend")
    return app


def main():
    import uvicorn
    parser = argparse.ArgumentParser(description="Run the Theron local scanner workspace")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--frontend-dir", help="Path to a built frontend/dist directory")
    args = parser.parse_args()
    uvicorn.run(create_app(static_dir=args.frontend_dir), host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
