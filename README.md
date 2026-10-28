# Theron — Open Source AI Infrastructure Security Scanner

A local, read-only SAST/SCA scanner with CycloneDX SBOM output and AI-aware Python analysis. Findings are evidence for review, not a guarantee of exploitability or complete coverage.

## v1 workflow

Theron is report-only by default: it produces terminal, JSON, HTML, or SARIF evidence for a human to validate and turn into an issue or pull request. Python receives syntax-aware checks for AI data flows and unsafe model loading; JavaScript/TypeScript remain advisory, pattern-based coverage.

Use `theron.yml` to exclude paths or accept finding fingerprints as an existing baseline. Add `--fail-on high` only when you want CI to block on new findings at that severity. Broad legacy regex and agent/config review checks now require `--include-experimental`; they are not confirmed bugs.

### Detection quality and limits

- Default Python checks require an observed external-input-to-execution/deserialization/SQLite-statement flow or model-text-to-execution flow. They resolve imports and OpenAI/Anthropic clients, track simple assignments and response-content extraction, clear reassigned values, and isolate function scopes. Passing user input to an LLM alone does **not** alert.
- Safe subprocess argument lists, safe YAML loaders, ordinary `.generate()` methods, arbitrary credential-like variable names, and AI package presence do not produce default vulnerability alerts.
- Analysis is conservative, with direct same-file helper/method calls bounded to three levels. Flask/Bottle/Quart request sources and typed FastAPI request/string-route inputs are recognised, along with selected string transformations. It does not prove runtime reachability, follow cross-file calls/dynamic dispatch/tainted helper returns, model every framework, or recognise every sanitizer. Unsupported and ambiguous flows can be missed. JavaScript/TypeScript remain opt-in advisory regex checks.
- Provider-shaped credentials are redacted in evidence. A pattern match does not prove a credential is valid; the scanner never attempts authentication with discovered credentials.
- SCA queries OSV using the manifest's ecosystem and an exact declared or locked version. Ranges and unpinned dependencies stay unresolved in the SBOM and produce informational coverage notices, not invented installed versions. An advisory match does not prove deployment or exploitability.
- npm lockfiles (v1/v2/v3), npm shrinkwrap, and Pipfile.lock add locked transitive versions. Matching lock entries take precedence over declarations in the same directory. Unsupported lock formats are not analysed. Malformed supported manifests, failed advisory requests, unparseable Python, oversized files, and download/read failures produce informational notices. Advisory severity uses supplied metadata; unknown severity is provisionally medium (CVSS vectors are not scored).
- Files over 500 KB and configured/generated directories are not analysed. An empty report is not a security certification. Default filtering favours precision over recall.

Local and GitHub collection share file selection, including `.env` and `.env.*`. Configured path exclusions apply before reading/downloading files or querying their dependencies. CLI module selections and configuration list types are validated; invalid module names fail instead of returning an empty success. Possible Python taint is retained across selected branch/exception/loop paths; loop analysis remains bounded and cross-file flows remain unsupported.

## Local web workspace

The React workspace in `frontend/` connects to a local Python API. Scan GitHub repositories, combine finding filters, inspect source evidence, and download JSON or SARIF. Tokens stay in the backend environment; session history resets when the backend restarts.

```powershell
python -m pip install -e ".[web]"
python -m scanner.web
```

In a second terminal, run `npm ci` and `npm run dev` from `frontend/`, then open http://127.0.0.1:5173. Set `GITHUB_TOKEN` in the backend environment to enable live scans. See [frontend/README.md](frontend/README.md) for setup, production serving, and verification commands.

## Features

### AI-Specific Security Analysis
- Default: known provider-shaped credentials and observed Python model-text-to-execution flows.
- Experimental: prompt/instruction patterns, deployment settings, generic credentials, and exfiltration review candidates.

### SAST (Static Application Security Testing)
- Default: Python syntax-aware input-to-command/code execution, unsafe deserialization, resolved SQLite statement-injection checks, and reflected input in explicit Django/FastAPI/Starlette HTML responses. Selected Django, standard-library HTTP, Tornado, and resolved socket inputs are recognised. Parameterized SQL values and literal identifier allowlists are handled separately from unsafe interpolation.
- Experimental: broader Python and advisory JS/TS patterns for SQLi, SSRF, traversal, and other security review candidates.

### SCA (Software Composition Analysis)
- Auto-generates SBOM (CycloneDX format) from dependency manifests
- **Checks dependencies against OSV.dev vulnerability database (live API — no hardcoded CVEs)**
- AI/ML package review hints are experimental; using a package is not a bug.
- Supported declarations: requirements.txt, package.json, pyproject.toml, go.mod, Pipfile. Supported locks: package-lock.json, npm-shrinkwrap.json, Pipfile.lock.

### Agentic AI Security
- Experimental MCP/config, SKILL/instruction, permission, and tool-description review checks.
- Missing authentication fields alone do not prove a public endpoint lacks authentication. Malformed MCP files produce an informational parsing notice.

### GitHub Integration
- Connects directly to your GitHub account via Personal Access Token
- Scan single repos, all user repos, or entire organizations
- No automatic issues, PRs, bounty submissions, or production-site probing.
- SARIF output for GitHub Code Scanning integration

### Local Scanning
- Scan any local directory without GitHub connectivity
- Same scanner plugins, same rules, same output formats

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    CLI / Web UI                       │
├──────────────────────────────────────────────────────┤
│                    Scan Engine                        │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────┐  │
│  │  GitHub      │  │   Project    │  │  Rule Loader│  │
│  │  Client      │  │   Profiler   │  │  (versioned │  │
│  │  (fetch files)│ │   (detect    │  │   YAML rules)│ │
│  └──────┬───────┘  └──────┬───────┘  └─────┬──────┘  │
│         └────────┬────────┘                │          │
│                  ▼                         │          │
│         ┌──────────────────┐               │          │
│         │   ScanContext     │───────────────┘          │
│         └────────┬──────────┘                          │
│     ┌────────────┼────────────┐                       │
│     ▼            ▼            ▼                        │
│  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────────┐          │
│  │  AI  │  │ SAST │  │ SCA  │  │ Agentic  │          │
│  │Scanner│ │Scanner│ │Scanner│ │ Scanner  │          │
│  └──┬───┘  └──┬───┘  └──┬───┘  └────┬─────┘          │
│     └─────────┴─────────┴───────────┘                 │
│                     │                                 │
│                     ▼                                 │
│              ┌──────────────┐                         │
│              │  Aggregate    │                         │
│              │  & Report     │                         │
│              └──────┬───────┘                         │
│     ┌───────────────┼───────────────┐                │
│     ▼               ▼               ▼                 │
│ ┌──────┐     ┌──────────┐     ┌──────────┐           │
│ │Terminal│    │JSON/SARIF│    │   HTML   │           │
│ └──────┘     └──────────┘     └──────────┘           │
└──────────────────────────────────────────────────────┘

rules/  (versioned YAML, community-contributed)
├── ai/v1/
│   ├── prompt_injection.yaml
│   ├── secret_exposure.yaml
│   ├── insecure_deployment.yaml
│   └── data_exfiltration.yaml
├── sast/v1/
│   ├── python.yaml
│   ├── javascript.yaml
│   └── ai_taint.yaml
├── sca/v1/
│   └── risky_packages.yaml
└── agentic/v1/
    ├── mcp_config.yaml
    ├── skill_injection.yaml
    ├── tool_poisoning.yaml
    ├── hidden_injections.yaml
    └── agent_permissions.yaml
```

### Plugin System
Each scanner (ai, sast, sca, agentic) is a plugin implementing a common `Scanner` interface. New scanners can be added by dropping a file in `scanner/plugins/` — the engine auto-discovers them.

### Versioned Rules
Regex patterns are in versioned YAML files under `rules/`. Default Python source, sink and flow analysis lives in `scanner/python_analysis.py`; SCA and structured configuration checks also use Python code. Community members can add rules via PR without touching Python code. Rules support severity overrides, context-aware skipping, and structural (JSON-path) analysis.

### Project Profiler
Before scanning, the profiler detects languages, AI frameworks (LangChain, CrewAI, AutoGen, LlamaIndex, etc.), MCP configs, skill files, tool definitions, and infrastructure. This metadata is shared with all scanners for targeted scanning.

## Quick Start

See [INSTALL.md](INSTALL.md) for detailed installation instructions.

```bash
# Install
pip install -e .

# Scan a GitHub repository
export GITHUB_TOKEN=ghp_your_token_here
ai-sec-scan --repo owner/repo-name

# Scan a local directory
ai-sec-scan --local /path/to/project

# Generate HTML report
ai-sec-scan --repo owner/repo-name --format html --output report.html

# Run only specific modules
ai-sec-scan --repo owner/repo-name --modules ai,agentic

# Scan all your repos
ai-sec-scan --mine

# Opt into broader review candidates (not confirmed vulnerabilities)
ai-sec-scan --repo owner/repo-name --include-experimental
```

## Modules

| Module | Flag | Description |
|--------|------|-------------|
| AI Security | `ai` | Prompt injection, secret exposure, insecure model deployment, data exfiltration |
| SAST | `sast` | Static analysis for code vulnerabilities (Python, JS/TS) |
| SCA | `sca` | SBOM generation + live OSV.dev vulnerability checking |
| Agentic | `agentic` | MCP config analysis, SKILL.md scanning, tool poisoning, agent permissions |

## Output Formats

- **Terminal** — Color-coded console output (requires `rich`)
- **JSON** — Machine-readable JSON report
- **HTML** — Interactive HTML report with severity filtering and SBOM viewer
- **SARIF** — Industry-standard SARIF 2.1.0 format for GitHub code scanning

## Adding Custom Rules

Create a YAML file in the appropriate `rules/<module>/<version>/` directory:

```yaml
rule_set:
  name: my_custom_rules
  version: "1.0.0"
  category: misconfiguration
  module: ai
  description: "Custom security rules for my organization"

rules:
  - id: CUSTOM-001
    title: "My Custom Check"
    severity: HIGH
    pattern: 'my_dangerous_pattern'
    cwe: CWE-798
    confidence: high
    maturity: experimental
    description: "Detected a dangerous pattern."
    recommendation: "Fix this by doing X."
    references:
      - "https://example.com/docs"
```

## Running Tests

For the pinned external synthetic evaluation, results, scoring rules, and limits, see [PySASTBench evaluation](docs/PYSASTBENCH.md). This benchmark evaluates Python SAST only, not AI, SCA, or SBOM quality.

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## Try It on the Example

```bash
# Scan the bundled vulnerable example repo
ai-sec-scan --local examples/vulnerable_repo --format terminal

# Generate an HTML report for the example
ai-sec-scan --local examples/vulnerable_repo --format html --output example_report.html
```

## License

MIT — Completely free and open source.
