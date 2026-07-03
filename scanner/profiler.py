"""
Project profiler — detects project type, languages, AI frameworks, and
infrastructure before scanning. Runs once per repo, results shared with
all scanner plugins via ScanContext.
"""

import re
from typing import Dict, List, Optional
from scanner.models import ProjectProfile, FrameworkDetection


class ProjectProfiler:
    """Detects project characteristics before scanning."""

    FRAMEWORK_SIGNATURES = {
        "langchain": {
            "file_patterns": [r"langchain", r"langgraph", r"from langchain"],
            "package_names": ["langchain", "langchain-core", "langchain-community",
                              "langchain-openai", "langchain-anthropic", "langgraph"],
            "config_indicators": [r"ConversationChain", r"AgentExecutor", r"LLMChain",
                                  r"RetrievalQA", r"VectorStoreIndex"],
        },
        "crewai": {
            "file_patterns": [r"crewai", r"from crewai"],
            "package_names": ["crewai", "crewai-tools"],
            "config_indicators": [r"Agent\s*\(", r"Task\s*\(", r"Crew\s*\(", r"Process\.sequential"],
        },
        "autogen": {
            "file_patterns": [r"autogen", r"from autogen"],
            "package_names": ["pyautogen", "autogen"],
            "config_indicators": [r"AssistantAgent", r"UserProxyAgent", r"GroupChat",
                                  r"conversable_agent"],
        },
        "openai_agents_sdk": {
            "file_patterns": [r"from agents", r"openai\.agents", r"Agent\("],
            "package_names": ["openai-agents", "openai"],
            "config_indicators": [r"from agents import", r"Runner\.run", r"function_tool",
                                  r"handoff"],
        },
        "llama_index": {
            "file_patterns": [r"llama_index", r"llama-index", r"from llama_index"],
            "package_names": ["llama-index", "llama-index-core"],
            "config_indicators": [r"VectorStoreIndex", r"QueryEngine", r"ServiceContext"],
        },
        "haystack": {
            "file_patterns": [r"haystack", r"from haystack"],
            "package_names": ["farm-haystack", "haystack-ai"],
            "config_indicators": [r"Pipeline", r"DocumentStore"],
        },
        "dspy": {
            "file_patterns": [r"import dspy", r"from dspy"],
            "package_names": ["dspy-ai"],
            "config_indicators": [r"dspy\.Signature", r"dspy\.Module"],
        },
        "semantic_kernel": {
            "file_patterns": [r"semantic_kernel", r"from semantic_kernel"],
            "package_names": ["semantic-kernel"],
            "config_indicators": [r"Kernel", r"SemanticFunction"],
        },
    }

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

    TOOL_INDICATORS = [
        r"@tool\b", r"Tool\s*\(", r"BaseTool", r"StructuredTool",
        r"tool_name\s*=", r"def\s+\w+_tool\b", r"register_tool",
        r"mcp\.tool", r"@mcp\.tool", r"FastMCP", r"Server\(",
        r"tools?\s*[:=]\s*\[", r"tool_registry", r"define_tool",
        r"function_tool", r"@function_tool",
    ]

    EXT_TO_LANG = {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".jsx": "javascript", ".tsx": "typescript", ".go": "go",
        ".rs": "rust", ".java": "java", ".rb": "ruby", ".php": "php",
    }

    def analyze(self, files: Dict[str, str], repo_info: dict = None) -> ProjectProfile:
        profile = ProjectProfile(
            repo_info=repo_info or {},
            file_count=len(files),
        )

        all_content = "\n".join(files.values())

        # ── Languages ──────────────────────────────────────────────────
        ext_counts = {}
        for file_path in files:
            ext = "." + file_path.rsplit(".", 1)[-1] if "." in file_path else ""
            ext_counts[ext] = ext_counts.get(ext, 0) + 1
        for ext, count in ext_counts.items():
            lang = self.EXT_TO_LANG.get(ext)
            if lang:
                profile.languages.add(lang)
        if profile.languages:
            lang_to_ext = {v: k for k, v in self.EXT_TO_LANG.items()}
            profile.primary_language = max(
                profile.languages,
                key=lambda l: ext_counts.get(lang_to_ext.get(l, ""), 0),
            )

        # ── Dependency manifests ───────────────────────────────────────
        for file_path, content in files.items():
            basename = file_path.rsplit("/", 1)[-1]
            if basename in ("requirements.txt", "package.json", "pyproject.toml",
                            "go.mod", "Pipfile"):
                profile.dependency_manifests[basename] = content

        # ── AI frameworks ──────────────────────────────────────────────
        for fw_name, sigs in self.FRAMEWORK_SIGNATURES.items():
            detection = self._detect_framework(fw_name, sigs, files, all_content,
                                               profile.dependency_manifests)
            if detection:
                profile.ai_frameworks.append(detection)

        # ── Serving frameworks ─────────────────────────────────────────
        serving_indicators = {
            "fastapi": [r"from fastapi", r"FastAPI\("],
            "flask": [r"from flask", r"Flask\("],
            "uvicorn": [r"uvicorn", r"uvicorn\.run"],
            "gunicorn": [r"gunicorn"],
            "streamlit": [r"import streamlit", r"st\."],
            "gradio": [r"import gradio", r"gradio\.Interface"],
        }
        for fw_name, patterns in serving_indicators.items():
            if any(re.search(p, all_content, re.IGNORECASE) for p in patterns):
                profile.serving_frameworks.add(fw_name)

        # ── MCP configs ────────────────────────────────────────────────
        for file_path in files:
            basename = file_path.rsplit("/", 1)[-1]
            if basename in self.MCP_CONFIG_FILES or ("mcp" in basename.lower() and basename.endswith(".json")):
                profile.has_mcp_servers = True
                profile.mcp_config_files.append(file_path)

        # ── Skill/instruction files ────────────────────────────────────
        for file_path in files:
            if any(re.match(p, file_path, re.IGNORECASE) for p in self.SKILL_FILE_PATTERNS):
                profile.has_skill_files = True
                profile.skill_files.append(file_path)

        # ── Tool definitions ───────────────────────────────────────────
        for file_path, content in files.items():
            if any(re.search(p, content, re.IGNORECASE) for p in self.TOOL_INDICATORS):
                profile.has_tool_definitions = True
                profile.tool_definition_files.append(file_path)

        # ── Agent configs ──────────────────────────────────────────────
        agent_config_indicators = [
            "agent_config", "max_iterations", "allowed_tools", "permissions",
            "capabilities", "Agent(", "CrewAI", "AutoGen", "create_agent",
        ]
        for file_path, content in files.items():
            if any(ind in content for ind in agent_config_indicators):
                profile.has_agent_configs = True
                profile.agent_config_files.append(file_path)

        # ── Infrastructure ─────────────────────────────────────────────
        for file_path in files:
            basename = file_path.rsplit("/", 1)[-1]
            if basename.startswith("Dockerfile"):
                profile.has_dockerfile = True
            if basename.startswith("docker-compose"):
                profile.has_docker_compose = True
            if basename.endswith((".yaml", ".yml")) and any(
                k in file_path for k in ["k8s", "kubernetes", "deploy", "manifest"]
            ):
                profile.has_kubernetes_manifests = True
            if basename.endswith((".tf", ".tfvars")) or "terraform" in file_path.lower():
                profile.has_terraform = True
            if any(ci in file_path for ci in [".github/workflows", ".gitlab-ci",
                                               "Jenkinsfile", ".circleci"]):
                profile.has_ci_cd = True
                profile.ci_cd_files.append(file_path)

        # ── Risk indicators ────────────────────────────────────────────
        profile.uses_pickle = bool(re.search(r"\bpickle\.load|pickle\.loads\b", all_content))
        profile.uses_torch_load = bool(re.search(r"\btorch\.load\b", all_content))
        profile.uses_huggingface = bool(re.search(r"from_pretrained|huggingface_hub|hf_hub_download", all_content))
        profile.uses_openai = bool(re.search(r"openai|OpenAI|ChatCompletion", all_content))
        profile.uses_anthropic = bool(re.search(r"anthropic|Anthropic|claude", all_content))

        return profile

    def _detect_framework(self, name, sigs, files, all_content,
                          dependency_manifests) -> Optional[FrameworkDetection]:
        evidence = []
        config_files = []
        confidence = "low"
        version = None

        for pattern in sigs["file_patterns"]:
            if re.search(pattern, all_content, re.IGNORECASE):
                evidence.append(f"Import pattern: {pattern}")
                confidence = "medium"

        for manifest_name, manifest_content in dependency_manifests.items():
            for pkg in sigs["package_names"]:
                if pkg in manifest_content:
                    evidence.append(f"Dependency: {pkg} in {manifest_name}")
                    confidence = "high"
                    version_match = re.search(
                        rf"{re.escape(pkg)}[^a-zA-Z0-9]*([=<>!~]+)?\s*([\d.]+)",
                        manifest_content,
                    )
                    if version_match:
                        version = version_match.group(2)

        for indicator in sigs["config_indicators"]:
            if re.search(indicator, all_content):
                evidence.append(f"Config indicator: {indicator}")
                if confidence == "low":
                    confidence = "medium"

        for file_path, content in files.items():
            for pattern in sigs["file_patterns"]:
                if re.search(pattern, content, re.IGNORECASE):
                    if file_path not in config_files:
                        config_files.append(file_path)
                    break

        if evidence:
            return FrameworkDetection(
                name=name, version=version, confidence=confidence,
                evidence=evidence, config_files=config_files,
            )
        return None
