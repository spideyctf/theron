"""
Agentic AI security scanner plugin.

Scans for vulnerabilities in:
- MCP (Model Context Protocol) server configurations
- SKILL.md / instructions files for prompt injection and hidden instructions
- Agent connector definitions (LangChain tools, CrewAI tools, custom MCP tools)
- Tool poisoning — malicious tool descriptions that manipulate agent behavior
- Agent permission/scope issues — overly permissive agent capabilities
"""

import re
import json
import os
from typing import List
from scanner.models import Finding, ScanContext, Severity, Category
from scanner.plugins.base import Scanner
from scanner.plugins import register


@register
class AgenticScanner(Scanner):
    """Scanner for agentic AI security issues."""

    @property
    def name(self) -> str:
        return "agentic"

    @property
    def description(self) -> str:
        return "Agentic AI security: MCP misconfig, skill/instruction injection, tool poisoning, agent permissions"

    SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"}

    MCP_CONFIG_FILES = {
        "mcp.json", "mcp_config.json", "claude_desktop_config.json",
        "claude_code_config.json", ".mcp.json", "mcp_servers.json",
    }

    SKILL_FILE_PATTERNS = [
        r".*SKILL\.md$", r".*skill.*\.md$", r".*INSTRUCTIONS?\.md$",
        r".*INSTRUCTIONS?\.txt$", r".*system_prompt.*", r".*agent.*\.md$",
        r".*AGENTS?\.md$", r".*CLAUDE\.md$", r".*GUMMIE\.md$",
        r".*AGENT\.md$",
    ]

    CONNECTOR_PATTERNS = [
        r".*tools?\.py$", r".*tools?\.js$", r".*tools?\.ts$",
        r".*connectors?\.py$", r".*connectors?\.js$", r".*connectors?\.ts$",
        r".*mcp.*\.py$", r".*mcp.*\.js$", r".*mcp.*\.ts$",
    ]

    def scan(self, context: ScanContext) -> List[Finding]:
        findings = []
        rule_sets = context.rule_loader.load("agentic")
        profile = context.project_profile
        files = context.files

        for rule_set in rule_sets:
            for file_path, content in files.items():
                if any(skip in file_path for skip in self.SKIP_DIRS):
                    continue

                basename = os.path.basename(file_path)

                # Determine if this file is relevant for this rule set
                should_scan = False

                if rule_set.target_files_exact or rule_set.target_files_pattern:
                    matched = basename in rule_set.target_files_exact
                    if not matched:
                        for p in rule_set.target_files_pattern:
                            # Convert glob to regex
                            regex_p = p.replace("*", ".*").replace("?", ".")
                            if re.match(regex_p, basename, re.IGNORECASE):
                                matched = True
                                break
                    if matched:
                        should_scan = True
                elif "mcp" in rule_set.name.lower():
                    if basename in self.MCP_CONFIG_FILES or ("mcp" in basename.lower() and basename.endswith(".json")):
                        should_scan = True
                elif "skill" in rule_set.name.lower() or "hidden" in rule_set.name.lower():
                    if any(re.match(p, file_path, re.IGNORECASE) for p in self.SKILL_FILE_PATTERNS):
                        should_scan = True
                    elif file_path.endswith((".md", ".yaml", ".yml", ".json", ".py", ".js", ".ts")):
                        should_scan = True  # Hidden injection checks run on all text files
                elif "tool" in rule_set.name.lower():
                    if self._has_tool_definitions(content):
                        should_scan = True
                elif "permission" in rule_set.name.lower() or "agent" in rule_set.name.lower():
                    if self._is_agent_config(file_path, content):
                        should_scan = True
                else:
                    # Default: scan code + config + md files
                    if file_path.endswith((".py", ".js", ".ts", ".yaml", ".yml", ".json", ".md", ".txt")):
                        should_scan = True

                if not should_scan:
                    continue

                # Apply regex rules
                for rule in rule_set.rules:
                    findings.extend(self._apply_rule(rule, file_path, content, self.name))

                # Apply structural (JSON) rules for MCP configs
                if rule_set.structural_rules and basename.endswith(".json"):
                    try:
                        data = json.loads(content)
                        for struct_rule in rule_set.structural_rules:
                            findings.extend(
                                self._apply_structural_rule(struct_rule, file_path, data, rule_set.module)
                            )
                    except (json.JSONDecodeError, TypeError):
                        pass

        return findings

    def _has_tool_definitions(self, content: str) -> bool:
        indicators = [
            r"@tool\b", r"Tool\s*\(", r"BaseTool", r"StructuredTool",
            r"tool_name\s*=", r"def\s+\w+_tool\b", r"register_tool",
            r"mcp\.tool", r"@mcp\.tool", r"FastMCP", r"Server\(",
            r"tools?\s*[:=]\s*\[", r"tool_registry", r"define_tool",
            r"function_tool", r"@function_tool",
        ]
        return any(re.search(p, content, re.IGNORECASE) for p in indicators)

    def _is_agent_config(self, file_path: str, content: str) -> bool:
        config_indicators = [
            "agent_config", "agent_type", "max_iterations", "max_tokens",
            "allowed_tools", "permissions", "capabilities", "agent_role",
            "Agent(", "CrewAI", "AutoGen", "create_agent", "AgentConfig",
        ]
        return any(ind in content for ind in config_indicators)

    def _apply_structural_rule(self, struct_rule: dict, file_path: str, data: dict, module: str) -> List[Finding]:
        """Apply a JSON-path-based structural rule to parsed JSON data."""
        findings = []
        json_path = struct_rule.get("json_path", "")
        condition = struct_rule.get("condition", "")

        # Navigate to mcpServers or similar top-level keys
        servers = data.get("mcpServers", data.get("mcp_servers", data.get("servers", {})))
        if not isinstance(servers, dict):
            return findings

        for server_name, config in servers.items():
            if not isinstance(config, dict):
                continue

            # Check: URL exists but no auth
            if condition == "exists" and "url" in config:
                has_auth = "auth" in config or "headers" in config
                if not has_auth:
                    findings.append(self._make_structural_finding(
                        struct_rule, file_path, module,
                        f"MCP Server '{server_name}' — No Authentication",
                        f"MCP server '{server_name}' in {file_path} connects to a URL without authentication headers or auth configuration.",
                        "Add authentication (API key, bearer token, or OAuth) to the MCP server configuration.",
                        "CWE-306", Severity.HIGH,
                    ))

            # Check: HTTP (not HTTPS)
            url = config.get("url", "")
            if url.startswith("http://"):
                findings.append(self._make_structural_finding(
                    struct_rule, file_path, module,
                    f"MCP Server '{server_name}' — Insecure HTTP Transport",
                    f"MCP server '{server_name}' in {file_path} uses insecure HTTP transport (no TLS).",
                    "Use HTTPS for all MCP server connections. HTTP traffic is unencrypted and vulnerable to interception.",
                    "CWE-319", Severity.HIGH,
                ))

            # Check: hardcoded secrets in env
            env = config.get("env", {})
            if isinstance(env, dict):
                for key, value in env.items():
                    if any(s in key.upper() for s in ["KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"]):
                        if isinstance(value, str) and len(value) > 5 and not value.startswith("${") and not value.startswith("$("):
                            findings.append(self._make_structural_finding(
                                struct_rule, file_path, module,
                                f"MCP Server '{server_name}' — Hardcoded Secret in Environment",
                                f"MCP server '{server_name}' in {file_path} has hardcoded secret in env variable '{key}'.",
                                f"Remove the hardcoded value for '{key}'. Use environment variable references (e.g., ${{ENV_VAR}}) instead.",
                                "CWE-798", Severity.CRITICAL,
                            ))

        return findings

    @staticmethod
    def _make_structural_finding(rule, file_path, module, title, desc, rec, cwe, severity):
        return Finding(
            title=title,
            severity=severity,
            category=Category.MCP_MISCONFIG,
            module=module,
            description=desc,
            file_path=file_path,
            recommendation=rec,
            cwe=cwe,
            confidence="high",
            rule_id=rule.get("id", "STRUCT-UNKNOWN"),
            references=rule.get("references", []),
        )
