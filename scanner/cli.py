"""
CLI entry point for ai-sec-scan.
"""

import argparse
import sys
import os
from pathlib import Path


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
    parser.add_argument("--modules", help="Comma-separated modules: ai,sast,sca,agentic (default: config or all)")
    parser.add_argument("--format", default="terminal", choices=["terminal", "json", "html", "sarif"],
                        help="Output format (default: terminal)")
    parser.add_argument("--output", "-o", help="Output file path (for json/html/sarif)")
    parser.add_argument("--max-repos", type=int, default=50,
                        help="Max repos to scan for --user/--org/--mine (default: 50)")
    parser.add_argument("--rules-dir", help="Custom rules directory (default: bundled rules/)")
    parser.add_argument("--config", help="Path to theron.yml (default: target's theron.yml)")
    parser.add_argument("--include-experimental", action="store_true", help="Enable experimental rules")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low"],
                        help="Exit 2 when a new finding reaches this severity; default reports only")

    args = parser.parse_args()

    # Parse modules
    module_names = [m.strip().lower() for m in args.modules.split(",")] if args.modules else None
    if args.modules is not None:
        from scanner.config import validate_modules
        try:
            validate_modules(module_names)
        except ValueError as exc:
            parser.error(str(exc))

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
    from scanner.config import load_config

    try:
        config = load_config(os.getcwd(), args.config)
        config["include_experimental"] = args.include_experimental
        engine = ScanEngine(token, rules_dir=args.rules_dir, config=config)
    except Exception as e:
        print(f"Error initializing scanner: {e}")
        sys.exit(1)

    if args.repo:
        if "/" not in args.repo:
            print("Error: --repo must be in format 'owner/repo'")
            sys.exit(1)
        owner, repo = args.repo.split("/", 1)
        results = [engine.scan_repo(owner, repo, branch=args.branch, modules=module_names or config["modules"])]
    elif args.user:
        results = engine.scan_user_repos(args.user, modules=module_names or config["modules"], max_repos=args.max_repos)
    elif args.org:
        results = engine.scan_org_repos(args.org, modules=module_names or config["modules"], max_repos=args.max_repos)
    elif args.mine:
        results = engine.scan_my_repos(modules=module_names or config["modules"], max_repos=args.max_repos)
    else:
        print("Error: No scan target specified.")
        sys.exit(1)

    _output_results(results, args, engine)

    if _should_fail(results, args.fail_on):
        sys.exit(2)


def _run_local_scan(args, module_names):
    """Scan a local directory without GitHub."""
    import os
    from scanner.models import ScanResult, Severity, ScanContext
    from scanner.config import load_config
    from scanner.finding_utils import normalize_findings, coverage_finding, partition_findings
    from scanner.profiler import ProjectProfiler
    from scanner.rule_loader import RuleLoader
    from scanner.plugins import discover_plugins, clear_registry
    from scanner.utils.helpers import should_scan_file, is_excluded, DEFAULT_SKIP_DIRS

    scan_dir = args.local
    if not os.path.isdir(scan_dir):
        print(f"Error: Directory '{scan_dir}' does not exist.")
        sys.exit(1)

    try:
        config = load_config(scan_dir, args.config)
    except ValueError as exc:
        print(f"Error loading config: {exc}")
        sys.exit(1)
    config["include_experimental"] = args.include_experimental
    if module_names is None:
        module_names = config["modules"]

    clear_registry()
    scanners = discover_plugins()
    rule_loader = RuleLoader(args.rules_dir)
    profiler = ProjectProfiler()

    # Collect files
    files = {}
    coverage = []
    for root, dirs, filenames in os.walk(scan_dir):
        dirs[:] = [d for d in dirs if d not in DEFAULT_SKIP_DIRS]
        for filename in filenames:
            if should_scan_file(filename):
                full_path = os.path.join(root, filename)
                rel_path = os.path.relpath(full_path, scan_dir).replace("\\", "/")
                if is_excluded(rel_path, config.get("exclude")):
                    continue
                try:
                    if os.path.getsize(full_path) > 500_000:
                        coverage.append(coverage_finding(rel_path, "The file exceeds the 500 KB analysis limit."))
                        continue
                    with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                        files[rel_path] = f.read()
                except Exception:
                    coverage.append(coverage_finding(rel_path, "The local file could not be read."))
                    continue

    print(f"  Local scan: {scan_dir}")
    print(f"  Found {len(files)} files to scan")

    import time
    start = time.time()
    profile = profiler.analyze(files)
    print(f"  Project: {profile.primary_language}, AI frameworks: {len(profile.ai_frameworks)}")

    context = ScanContext(files=files, repo_info={}, project_profile=profile, rule_loader=rule_loader, config=config)
    result = ScanResult(repo_full_name=scan_dir, branch="local", files_scanned=len(files), findings=coverage)
    result.project_profile = profile.to_dict()

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

    result.findings = normalize_findings(result.findings, config)
    partition_findings(result)
    result.scan_duration_seconds = round(time.time() - start, 2)

    sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    result.findings.sort(key=lambda f: sev_order.get(f.severity, 99))

    _output_results([result], args, None)
    if _should_fail([result], args.fail_on):
        sys.exit(2)


def _output_results(results, args, engine):
    from scanner.reporters.terminal import print_terminal_report
    from scanner.reporters.json_reporter import save_json_report
    from scanner.reporters.sarif import save_sarif_report
    from scanner.reporters.html import save_html_report

    for result in results:
        if args.format == "terminal":
            print_terminal_report(result)
        elif args.format == "json":
            path = args.output or _default_output_path(result, "json")
            save_json_report(result, path)
            print(f"JSON report saved to {path}")
        elif args.format == "html":
            path = args.output or _default_output_path(result, "html")
            save_html_report(result, path)
            print(f"HTML report saved to {path}")
        elif args.format == "sarif":
            path = args.output or _default_output_path(result, "sarif")
            save_sarif_report(result, path)
            print(f"SARIF report saved to {path}")


def _default_output_path(result, extension):
    """Use a portable name even when the scan target is a nested directory."""
    name = Path(str(result.repo_full_name).replace("\\", "/")).name or "scan"
    safe_name = "".join(char if char.isalnum() or char in "._-" else "_" for char in name)
    return f"scan_{safe_name}.{extension}"


def _should_fail(results, threshold):
    if not threshold:
        return False
    from scanner.models import Severity
    levels = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    cutoff = levels.index(Severity(threshold.upper()))
    return any(
        finding.status == "new" and levels.index(finding.severity) <= cutoff
        for result in results for finding in result.findings
        if finding.severity in levels
    )


if __name__ == "__main__":
    main()
