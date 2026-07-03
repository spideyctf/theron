# AISecScanner — Open Source AI Infrastructure Security Scanner

A free, open-source security scanner that integrates directly with your GitHub repositories to detect AI-specific vulnerabilities, misconfigurations, insecure model deployments, prompt injection risks, secret exposure, and agentic AI threats.

## Features

### 🔍 AI-Specific Security Analysis
- **Prompt Injection Detection** — Detects prompt injection patterns in system prompts, instructions, SKILL.md files, and agent configurations
- **Secret Exposure Scanning** — Finds hardcoded API keys, tokens, credentials in code and config files (OpenAI, Anthropic, GitHub, AWS, HuggingFace, Slack, Google, and more)
- **Insecure Model Deployment** — Checks for exposed model endpoints, missing auth, insecure serialization (pickle/joblib/torch.load)
- **Model Poisoning Indicators** — Detects untrusted model loading, unsigned model files, suspicious weights
- **Data Exfiltration Risks** — Identifies outbound data flows to untrusted endpoints from AI pipelines

### 📦 SAST (Static Application Security Testing)
- Taint analysis for Python, JavaScript/TypeScript
- Detects command injection, path traversal, SSRF, SQL injection, deserialization flaws, XXE
- **AI-specific taint tracking**: user input → LLM prompt (prompt injection risk), LLM output → code execution (code injection via manipulated model)

### 📋 SCA (Software Composition Analysis)
- Auto-generates SBOM (CycloneDX format) from dependency manifests
- **Checks dependencies against OSV.dev vulnerability database (live API — no hardcoded CVEs)**
- Flags AI/ML packages with known security risks (langchain, torch, transformers, crewai, autogen, etc.)
- Supports: requirements.txt, package.json, pyproject.toml, go.mod, Pipfile

### 🤖 Agentic AI Security
- **MCP (Model Context Protocol) Analysis** — Scans MCP server configs for malicious tools, overly permissive scopes, insecure transports, hardcoded secrets, auto-approve, wildcard permissions
- **SKILL.md / Instructions Scanning** — Detects prompt injection, hidden instructions, privilege escalation in agent skill definitions
- **Agent Connector Auditing** — Analyzes agentic AI connectors (LangChain tools, CrewAI tools, custom MCP tools) for injection vectors and unsafe operations
- **Tool Poisoning Detection** — Identifies malicious tool descriptions that could manipulate agent behavior
- **Hidden Injection Detection** — Finds hidden instructions in HTML comments, zero-width characters, escaped newlines, fake system tags

### 🔗 GitHub Integration
- Connects directly to your GitHub account via Personal Access Token
- Scan single repos, all user repos, or entire organizations
- Optional auto-issue creation for CRITICAL/HIGH findings
- SARIF output for GitHub Code Scanning integration

### 🖥️ Local Scanning
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
All detection patterns are in versioned YAML files under `rules/`. Community members can add rules via PR without touching Python code. Rules support severity overrides, context-aware skipping, and structural (JSON-path) analysis.

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

# Create GitHub issues for findings
ai-sec-scan --repo owner/repo-name --create-issues
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
    description: "Detected a dangerous pattern."
    recommendation: "Fix this by doing X."
    references:
      - "https://example.com/docs"
```

## Running Tests

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
