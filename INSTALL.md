# Installation Guide

## Prerequisites

- **Python 3.9 or higher**
- **pip** (comes with Python)
- **A GitHub Personal Access Token** (only needed for GitHub scanning, not for local scans)

## Installation

### Option 1: Install from source (recommended)

```bash
# Clone the repository
git clone https://github.com/aryaman-futane/ai-sec-scanner.git
cd ai-sec-scanner

# Install in development mode
pip install -e .

# Verify installation
ai-sec-scan --help
```

### Option 2: Install without cloning (from a zip)

```bash
# Unzip the project
unzip ai-sec-scanner.zip
cd ai-sec-scanner

# Install
pip install -e .

# Verify
ai-sec-scan --help
```

### Option 3: Use without installing

You can run the scanner directly without installing it as a package:

```bash
cd ai-sec-scanner

# Run via Python module
python -m scanner.cli --local examples/vulnerable_repo

# Or set up PYTHONPATH and use the entry point
export PYTHONPATH=$(pwd)
python -c "from scanner.cli import main; main()" --local examples/vulnerable_repo
```

## Dependencies

The scanner has minimal dependencies:

| Package | Purpose | Required |
|---------|---------|----------|
| `requests` | GitHub API + OSV.dev API calls | Yes |
| `PyYAML` | Parse YAML rule files | Yes |
| `rich` | Color-coded terminal output | Optional (falls back to plain text) |

All dependencies are installed automatically by `pip install -e .`.

## GitHub Token Setup

To scan GitHub repositories, you need a Personal Access Token:

1. Go to https://github.com/settings/tokens
2. Click "Generate new token (classic)"
3. Select scopes:
   - `repo` — to scan private repos and create issues
   - `read:org` — if scanning organization repos
4. Generate the token and copy it
5. Set it as an environment variable:

```bash
# Linux/macOS
export GITHUB_TOKEN=ghp_your_token_here

# Windows (PowerShell)
$env:GITHUB_TOKEN="ghp_your_token_here"

# Windows (CMD)
set GITHUB_TOKEN=ghp_your_token_here
```

**Note:** You don't need a GitHub token for local scans (`--local` mode).

## Usage

### Scan a single GitHub repository

```bash
ai-sec-scan --repo owner/repo-name
```

### Scan all your repositories

```bash
ai-sec-scan --mine
```

### Scan a GitHub organization

```bash
ai-sec-scan --org my-org
```

### Scan a specific GitHub user's repos

```bash
ai-sec-scan --user username
```

### Scan a local directory

```bash
ai-sec-scan --local /path/to/project
```

### Run specific modules only

```bash
# Only AI security + agentic scanning
ai-sec-scan --repo owner/repo --modules ai,agentic

# Only SAST
ai-sec-scan --repo owner/repo --modules sast

# Only SCA (dependency checking + SBOM)
ai-sec-scan --repo owner/repo --modules sca
```

### Output formats

```bash
# Terminal (default)
ai-sec-scan --repo owner/repo --format terminal

# JSON report
ai-sec-scan --repo owner/repo --format json --output report.json

# HTML report (interactive, with SBOM viewer)
ai-sec-scan --repo owner/repo --format html --output report.html

# SARIF (for GitHub code scanning)
ai-sec-scan --repo owner/repo --format sarif --output report.sarif
```

### Create GitHub issues for findings

```bash
ai-sec-scan --repo owner/repo --create-issues
```

This creates GitHub issues for CRITICAL and HIGH findings (max 20 issues per scan).

### Use custom rules directory

```bash
ai-sec-scan --repo owner/repo --rules-dir /path/to/custom/rules
```

## CI/CD Integration

### GitHub Actions

Add this to your workflow (`.github/workflows/security-scan.yml`):

```yaml
name: AI Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -e .
      - run: ai-sec-scan --local . --format sarif --output scan.sarif
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: scan.sarif
```

### GitLab CI

```yaml
security-scan:
  image: python:3.11
  script:
    - pip install -e .
    - ai-sec-scan --local . --format json --output scan.json
  artifacts:
    paths:
      - scan.json
```

### Pre-commit hook

```bash
# .git/hooks/pre-commit
#!/bin/bash
ai-sec-scan --local . --modules ai,sast --format terminal
```

## Testing the Installation

### Run the test suite

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

### Scan the example vulnerable repo

```bash
# Terminal output
ai-sec-scan --local examples/vulnerable_repo

# HTML report
ai-sec-scan --local examples/vulnerable_repo --format html --output example_report.html
```

The example repo in `examples/vulnerable_repo/` contains intentional vulnerabilities that trigger all scanner modules.

## Troubleshooting

### "GITHUB_TOKEN environment variable not set"

You need to set your GitHub token. See [GitHub Token Setup](#github-token-setup) above.
Alternatively, use `--local` to scan a local directory without a token.

### "No rules found for module"

The rules directory is missing or the path is wrong. By default, the scanner looks for `rules/` in the project root. If you installed from a different location, use `--rules-dir` to specify the correct path.

### "GitHub API rate limit exceeded"

Authenticated requests have a limit of 5,000/hour. For large org scans, consider:
- Scanning fewer repos with `--max-repos`
- Spacing out scans
- Using a token with higher rate limits

### Rich not installed (plain text output)

If `rich` is not installed, the scanner falls back to plain text output. To get color-coded output:

```bash
pip install rich
```

## Uninstall

```bash
pip uninstall ai-sec-scanner
```
