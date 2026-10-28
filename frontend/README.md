# Theron workspace

A local, single-user React + TypeScript workspace for the Python scanner. The UI uses plain CSS and Lucide icons. Sample findings are explicitly labeled and never presented as live scans.

Requires Node.js 22.12 or newer (Node 24 recommended). Typography uses system fallbacks, so no fonts or other runtime assets are fetched from external services.

## Development

From the project root:

```powershell
python -m pip install -e ".[web,dev]"
$env:GITHUB_TOKEN = "your-github-token"
python -m scanner.web
```

In a second terminal:

```powershell
cd frontend
npm ci
npm run dev
```

Open http://127.0.0.1:5173. Vite proxies `/api` to http://127.0.0.1:8000.

On macOS/Linux, use `export GITHUB_TOKEN=your-github-token`. The token stays in the backend process; never put it in a `VITE_*` environment variable. Without a token you can explore the sample report, but live scan submission is disabled.

## Production, served locally

```powershell
cd frontend
npm run build
cd ..
python -m scanner.web
```

Open http://127.0.0.1:8000. The API serves `frontend/dist` if built before startup. The equivalent installed entry point is `theron-web`; `--port 8000` and `--frontend-dir PATH` are available. Both servers bind to loopback. This is a local tool, not a hosted multi-user service.

## Workflow

1. Select **New scan** and enter a GitHub repository URL or `owner/repo`.
2. Choose an optional branch and scan modules. All modules start selected; experimental rules start disabled.
3. The engine queues one scan at a time. The UI displays actual queued/running/completed/failed states.
4. Combine search, severity, module, and status filters. Click a finding for source evidence and remediation.
5. Download JSON or SARIF from completed live scans; copy remediation or open source on GitHub.

The report tabs expose **Findings**, **Dependencies / SBOM**, **Project profile**, and **Scan details**. Findings show maturity beside the rule, with informational coverage/advisory notices called out separately. Dependency search covers package names, versions, source paths and package URLs; unresolved versions remain explicit. Download the standalone SBOM or expand its complete metadata/properties. The project tab exposes all exported profiler fields, including framework evidence and configuration paths; these are static detections, not proof of deployment. Scan details include requested/completed modules, experimental-rule settings, timestamps, job metadata and the complete report JSON. Older reports without a profile show an explicit unavailable state.

Use `/` to focus search and Escape to close dialogs. On mobile, the current-scan selector provides access to session history. A sample JSON export is available; sample SARIF export is disabled.

History and results are held in backend memory and reset on restart. Closing a browser tab does not stop a scan. Repository code is inspected as text, not executed. Each GitHub request has a bounded timeout. Large repositories can take longer because files are fetched serially; there is no invented percentage or ETA.

The UI preserves the scanner's `new`/`existing` fields; it does not write baselines or create issues. GitHub API authentication, permissions, missing repositories/branches, timeouts, and rate limits appear as actionable errors. Evidence can include sensitive source text, so reports stay on the local machine.

## API

- `GET /api/health` — health and token-configured boolean.
- `POST /api/scans` — JSON body: `repository`, optional `branch`, `modules`, `include_experimental`; returns a scan ID with HTTP 202.
- `GET /api/scans` — session scan metadata, most recent first.
- `GET /api/scans/{id}` — job status and completed `ScanResult`.
- `GET /api/scans/{id}/report?format=json|sarif` — completed report download.

## Checks

```powershell
npm test
npm run build
cd ..
python -m pytest tests -q -p no:cacheprovider
```

Web tests use a mocked scanner and fake credentials. They never require a GitHub account.

## Detection expectations

Default scans now favour precision: Python input/model-text flows into dangerous sinks,
provider-shaped credential evidence, and exact-version dependency advisory matches.
Ordinary prompt input, AI package presence, and broad code/config patterns are not default bugs.
Experimental rules remain available but are review candidates. Credential-shaped evidence is
redacted; reports can still contain sensitive source code and should stay private.
Informational findings identify incomplete analysis, unresolved versions, and unavailable lookups.
An empty report does not mean the application is secure. See the root README for supported flows and limits.
