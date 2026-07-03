"""
CLI entry point for ai-sec-scan.
"""

import argparse
import sys
import os


def main():
    parser = argparse.ArgumentParser(
        prog="ai-sec-scan",
        description="Open-source AI infrastructure security scanner with GitHub integration.",
        epilog=(
            "Examples:\n"
            "  ai-sec-scan --repo owner/repo-name\n"
            "  ai-sec-scan --user my-username\n"
            "  ai-sec-scan --org my-org --modules ai,agentic\n"
            "  ai-sec-scan --repo owner/repo --format html --output report.html\n"
            "  ai-sec-scan --local /path/to/project --format terminal\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--repo", help="Repository to scan (format: owner/repo)")
    target.add_argument("--user", help="GitHub username to scan all their repos")
    target.add_argument("--org", help="GitHub organization to scan all repos")
    target.add_argument("--mine", action="store_true", help="Scan all repos owned by you")
    target.add_argument("--local", help="Scan a local directory instead of GitHub")

    parser.add_argument("--branch", help="Branch to scan (default: repo's default branch)")
    parser.add_argument("--modules", default="ai,sast,sca,agentic",
                        help="Comma-separated modules: ai,sast,sca,agentic (default: all)")
    parser.add_argument("--format", default="terminal", choices=["terminal", "json", "html", "sarif"],
                        help="Output format (default: terminal)")
    parser.add_argument("--output", "-o", help="Output file path (for json/html/sarif)")
    parser.add_argument("--create-issues", action="store_true",
                        help="Create GitHub issues for critical/high findings")
    parser.add_argument("--max-repos", type=int, default=50,
                        help="Max repos to scan for --user/--org/--mine (default: 50)")
    parser.add_argument("--rules-dir", help="Custom rules directory (default: bundled rules/)")

    args = parser.parse_args()

    # Parse modules
    module_names = [m.strip().lower() for m in args.modules.split(",")]

    # ── Local scan mode ──────────────────────────────────────────────────
    if args.local:
        _run_local_scan(args, module_names)
        return

    # ── GitHub scan mode ─────────────────────────────────────────────────
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("Error: GITHUB_TOKEN environment variable not set.")
        print("Create a token at https://github.com/settings/tokens with 'repo' scope.")
        print("Then run: export GITHUB_TOKEN=ghp_your_token_here")
        sys.exit(1)

    from scanner.engine import ScanEngine
    from scanner.models import Severity

    try:
        engine = ScanEngine(token, rules_dir=args.rules_dir)
    except Exception as e:
        print(f"Error initializing scanner: {e}")
        sys.exit(1)

    if args.repo:
        if "/" not in args.repo:
            print("Error: --repo must be in format 'owner/repo'")
            sys.exit(1)
        owner, repo = args.repo.split("/", 1)
        results = [engine.scan_repo(owner, repo, branch=args.branch, modules=module_names)]
    elif args.user:
        results = engine.scan_user_repos(args.user, modules=module_names, max_repos=args.max_repos)
    elif args.org:
        results = engine.scan_org_repos(args.org, modules=module_names, max_repos=args.max_repos)
    elif args.mine:
        results = engine.scan_my_repos(modules=module_names, max_repos=args.max_repos)
    else:
        print("Error: No scan target specified.")
        sys.exit(1)

    _output_results(results, args, engine)

    # Optionally create GitHub issues
    if args.create_issues:
        for result in results:
            owner, repo = result.repo_full_name.split("/", 1)
            critical_high = [f for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
            if critical_high:
                print(f"\n  Creating GitHub issues for {result.repo_full_name} ({len(critical_high)} critical/high)...")
                for finding in critical_high[:20]:
                    try:
                        body = _format_issue_body(finding)
                        engine.github.create_issue(
                            owner, repo,
                            title=f"[SECURITY] {finding.severity.value}: {finding.title}",
                            body=body,
                            labels=["security", "ai-sec-scanner", f"severity:{finding.severity.value.lower()}"],
                        )
                        print(f"    ✅ Created issue: {finding.title[:60]}")
                    except Exception as e:
                        print(f"    ❌ Failed to create issue: {e}")

    # Exit non-zero if critical findings
    has_critical = any(
        f.severity == Severity.CRITICAL
        for result in results
        for f in result.findings
    )
    if has_critical:
        sys.exit(2)


def _run_local_scan(args, module_names):
    """Scan a local directory without GitHub."""
    import os
    from scanner.models import ScanResult, Severity, ScanContext
    from scanner.profiler import ProjectProfiler
    from scanner.rule_loader import RuleLoader
    from scanner.plugins import discover_plugins, clear_registry

    scan_dir = args.local
    if not os.path.isdir(scan_dir):
        print(f"Error: Directory '{scan_dir}' does not exist.")
        sys.exit(1)

    clear_registry()
    scanners = discover_plugins()
    rule_loader = RuleLoader(args.rules_dir)
    profiler = ProjectProfiler()

    # Collect files
    SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist",
                 "build", ".next", "vendor", ".idea", ".vscode", "target",
                 "coverage", ".cache", ".pytest_cache", ".mypy_cache"}
    SCANABLE_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".yaml", ".yml", ".json",
                    ".toml", ".env", ".cfg", ".ini", ".txt", ".md", ".xml"}
    SCANABLE_BASE = {"Dockerfile", "docker-compose.yml", "docker-compose.yaml",
                     "requirements.txt", "package.json", "pyproject.toml", "go.mod",
                     "Pipfile", "SKILL.md", "AGENTS.md", "AGENT.md", "CLAUDE.md",
                     "GUMMIE.md", "INSTRUCTIONS.md", "README.md"}

    files = {}
    for root, dirs, filenames in os.walk(scan_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in filenames:
            if os.path.getsize(os.path.join(root, filename)) > 500_000:
                continue
            ext = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""
            if ext in SCANABLE_EXT or filename in SCANABLE_BASE or filename.startswith("Dockerfile"):
                full_path = os.path.join(root, filename)
                rel_path = os.path.relpath(full_path, scan_dir)
                try:
                    with open(full_path, "r", errors="replace") as f:
                        files[rel_path] = f.read()
                except Exception:
                    continue

    print(f"  Local scan: {scan_dir}")
    print(f"  Found {len(files)} files to scan")

    import time
    start = time.time()
    profile = profiler.analyze(files)
    print(f"  Project: {profile.primary_language}, AI frameworks: {len(profile.ai_frameworks)}")

    context = ScanContext(files=files, repo_info={}, project_profile=profile, rule_loader=rule_loader)
    result = ScanResult(repo_full_name=scan_dir, branch="local", files_scanned=len(files))

    for scanner in scanners.values():
        if module_names and scanner.name not in module_names:
            continue
        print(f"  Running {scanner.name} scanner...")
        result.findings.extend(scanner.scan(context))
        result.modules_run.append(scanner.name)

    if "sca" in result.modules_run:
        sca = scanners.get("sca")
        if sca:
            result.sbom = sca.generate_sbom(files, scan_dir)

    result.scan_duration_seconds = round(time.time() - start, 2)

    sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    result.findings.sort(key=lambda f: sev_order.get(f.severity, 99))

    _output_results([result], args, None)


def _output_results(results, args, engine):
    from scanner.reporters.terminal import print_terminal_report
    from scanner.reporters.json_reporter import save_json_report
    from scanner.reporters.sarif import save_sarif_report
    from scanner.reporters.html import save_html_report

    for result in results:
        if args.format == "terminal":
            print_terminal_report(result)
        elif args.format == "json":
            path = args.output or f"scan_{result.repo_full_name.replace('/', '_')}.json"
            save_json_report(result, path)
            print(f"JSON report saved to {path}")
        elif args.format == "html":
            path = args.output or f"scan_{result.repo_full_name.replace('/', '_')}.html"
            save_html_report(result, path)
            print(f"HTML report saved to {path}")
        elif args.format == "sarif":
            path = args.output or f"scan_{result.repo_full_name.replace('/', '_')}.sarif"
            save_sarif_report(result, path)
            print(f"SARIF report saved to {path}")


def _format_issue_body(finding):
    return f"""## 🔍 Security Finding: {finding.title}

**Severity:** {finding.severity.value}
**Category:** {finding.category.value}
**Module:** {finding.module}
**CWE:** {finding.cwe or 'N/A'}
**Confidence:** {finding.confidence}
**Rule ID:** {finding.rule_id or 'N/A'}

**File:** `{finding.file_path}:{finding.line_number or 'N/A'}`

### Description
{finding.description}

### Code
```
{finding.code_snippet or 'N/A'}
```

### Recommendation
{finding.recommendation or 'N/A'}

---
*Generated by [ai-sec-scanner](https://github.com/aryaman-futane/ai-sec-scanner)*"""


if __name__ == "__main__":
    main()
