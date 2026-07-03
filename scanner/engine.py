"""
Scan engine — orchestrates all scanner plugins against a repository.

Uses the plugin system for auto-discovery, the profiler for framework
detection, and the rule loader for versioned YAML rules.
"""

import time
from typing import List, Optional
from scanner.models import Finding, ScanResult, Severity, ScanContext
from scanner.github_client import GitHubClient
from scanner.profiler import ProjectProfiler
from scanner.rule_loader import RuleLoader
from scanner.plugins import discover_plugins


SCANABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".yaml", ".yml", ".json",
    ".toml", ".env", ".cfg", ".ini", ".txt", ".md", ".xml",
}

SCANABLE_BASENAMES = {
    "Dockerfile", "Dockerfile.dev", "Dockerfile.prod", "Dockerfile.base",
    "docker-compose.yml", "docker-compose.yaml", "docker-compose.dev.yml",
    "requirements.txt", "package.json", "pyproject.toml", "go.mod",
    "Pipfile", "SKILL.md", "AGENTS.md", "AGENT.md", "CLAUDE.md",
    "GUMMIE.md", "INSTRUCTIONS.md", "README.md",
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "dist",
    "build", ".next", "vendor", ".idea", ".vscode", "target",
    "coverage", ".cache", ".pytest_cache", ".mypy_cache",
}

MAX_FILE_SIZE = 500_000


class ScanEngine:
    """Orchestrates security scanning across all discovered plugins."""

    def __init__(self, github_token: Optional[str] = None, rules_dir: Optional[str] = None):
        self.github = GitHubClient(github_token)
        self.rule_loader = RuleLoader(rules_dir)
        self.profiler = ProjectProfiler()
        self.scanners = discover_plugins()

    def scan_repo(
        self,
        owner: str,
        repo: str,
        branch: Optional[str] = None,
        modules: Optional[List[str]] = None,
    ) -> ScanResult:
        start_time = time.time()

        # Get repo info
        repo_info = self.github.get_repo_info(owner, repo)
        if branch is None:
            branch = repo_info.get("default_branch", "main")

        print(f"  Scanning {owner}/{repo} (branch: {branch})...")

        # Get file tree
        tree = self.github.get_tree(owner, repo, branch)

        # Filter files
        scanable_paths = []
        for item in tree:
            if item.get("type") != "blob":
                continue
            path = item.get("path", "")
            size = item.get("size", 0)
            if size > MAX_FILE_SIZE:
                continue
            if any(skip_dir in path for skip_dir in SKIP_DIRS):
                continue
            basename = path.rsplit("/", 1)[-1]
            ext = "." + basename.rsplit(".", 1)[-1] if "." in basename else ""
            if ext in SCANABLE_EXTENSIONS or basename in SCANABLE_BASENAMES or basename.startswith("Dockerfile"):
                scanable_paths.append(path)

        print(f"  Found {len(scanable_paths)} files to scan")

        # Fetch file contents
        files = {}
        for path in scanable_paths:
            try:
                content = self.github.get_file_content(owner, repo, path, branch)
                files[path] = content
            except Exception as e:
                print(f"  Warning: Could not fetch {path}: {e}")
                continue

        print(f"  Fetched {len(files)} files")

        # Profile the project
        profile = self.profiler.analyze(files, repo_info)
        print(f"  Project profile: {profile.primary_language}, "
              f"{len(profile.ai_frameworks)} AI frameworks, "
              f"MCP={profile.has_mcp_servers}, skills={profile.has_skill_files}")

        # Build shared context
        context = ScanContext(
            files=files,
            repo_info=repo_info,
            project_profile=profile,
            rule_loader=self.rule_loader,
        )

        # Run scanners
        result = ScanResult(
            repo_full_name=f"{owner}/{repo}",
            branch=branch,
            files_scanned=len(files),
        )

        for scanner in self.scanners.values():
            if modules and scanner.name not in modules:
                continue
            if not scanner.supports_project(profile):
                continue
            print(f"  Running {scanner.name} scanner...")
            findings = scanner.scan(context)
            result.findings.extend(findings)
            result.modules_run.append(scanner.name)

        # Generate SBOM
        if "sca" in result.modules_run:
            print("  Generating SBOM...")
            sca_scanner = self.scanners.get("sca")
            if sca_scanner:
                result.sbom = sca_scanner.generate_sbom(files, f"{owner}/{repo}")

        result.scan_duration_seconds = round(time.time() - start_time, 2)

        # Sort findings by severity
        severity_order = {
            Severity.CRITICAL: 0, Severity.HIGH: 1,
            Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4,
        }
        result.findings.sort(key=lambda f: severity_order.get(f.severity, 99))

        return result

    def scan_user_repos(self, username: str, modules=None, max_repos=50):
        repos = self.github.list_user_repos(username)
        return self._scan_multiple(repos, modules, max_repos)

    def scan_org_repos(self, org: str, modules=None, max_repos=50):
        repos = self.github.list_org_repos(org)
        return self._scan_multiple(repos, modules, max_repos)

    def scan_my_repos(self, modules=None, max_repos=50):
        repos = self.github.list_my_repos()
        return self._scan_multiple(repos, modules, max_repos)

    def _scan_multiple(self, repos, modules, max_repos):
        results = []
        for repo_data in repos[:max_repos]:
            full_name = repo_data.get("full_name", "")
            if not full_name:
                continue
            owner, repo = full_name.split("/", 1)
            try:
                result = self.scan_repo(owner, repo, modules=modules)
                results.append(result)
            except Exception as e:
                print(f"  Error scanning {full_name}: {e}")
        return results
