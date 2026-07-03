"""
Core data models for security findings and scan results.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Category(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    SECRET_EXPOSURE = "secret_exposure"
    INSECURE_MODEL_DEPLOYMENT = "insecure_model_deployment"
    MODEL_POISONING = "model_poisoning"
    DATA_EXFILTRATION = "data_exfiltration"
    SAST = "sast"
    SCA = "sca"
    MCP_MISCONFIG = "mcp_misconfig"
    SKILL_INJECTION = "skill_injection"
    AGENTIC_CONNECTOR = "agentic_connector"
    TOOL_POISONING = "tool_poisoning"
    MISCONFIGURATION = "misconfiguration"


@dataclass
class Finding:
    """A single security finding."""
    title: str
    severity: Severity
    category: Category
    module: str
    description: str
    file_path: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    recommendation: Optional[str] = None
    cwe: Optional[str] = None
    confidence: str = "high"
    rule_id: Optional[str] = None
    references: Optional[List[str]] = None

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            "category": self.category.value if isinstance(self.category, Category) else str(self.category),
            "module": self.module,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "recommendation": self.recommendation,
            "cwe": self.cwe,
            "confidence": self.confidence,
            "rule_id": self.rule_id,
            "references": self.references or [],
        }


@dataclass
class FrameworkDetection:
    """Detected AI framework in the project."""
    name: str
    version: Optional[str] = None
    confidence: str = "low"
    evidence: List[str] = field(default_factory=list)
    config_files: List[str] = field(default_factory=list)


@dataclass
class ProjectProfile:
    """Profile of the project being scanned — built once, shared with all scanners."""
    languages: set = field(default_factory=set)
    primary_language: str = "unknown"
    ai_frameworks: List[FrameworkDetection] = field(default_factory=list)
    serving_frameworks: set = field(default_factory=set)
    has_mcp_servers: bool = False
    mcp_config_files: List[str] = field(default_factory=list)
    has_skill_files: bool = False
    skill_files: List[str] = field(default_factory=list)
    has_agent_configs: bool = False
    agent_config_files: List[str] = field(default_factory=list)
    has_tool_definitions: bool = False
    tool_definition_files: List[str] = field(default_factory=list)
    has_dockerfile: bool = False
    has_docker_compose: bool = False
    has_kubernetes_manifests: bool = False
    has_terraform: bool = False
    has_ci_cd: bool = False
    ci_cd_files: List[str] = field(default_factory=list)
    dependency_manifests: Dict[str, str] = field(default_factory=dict)
    uses_pickle: bool = False
    uses_torch_load: bool = False
    uses_huggingface: bool = False
    uses_openai: bool = False
    uses_anthropic: bool = False
    repo_info: Dict = field(default_factory=dict)
    file_count: int = 0


@dataclass
class ScanContext:
    """Shared context passed to every scanner plugin."""
    files: Dict[str, str]
    repo_info: Dict
    project_profile: ProjectProfile
    rule_loader: object  # RuleLoader
    config: Dict = field(default_factory=dict)


@dataclass
class ScanResult:
    """Aggregated results of a full repository scan."""
    repo_full_name: str
    branch: str
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    modules_run: List[str] = field(default_factory=list)
    sbom: Optional[dict] = None
    scan_duration_seconds: float = 0.0
    project_profile: Optional[dict] = None

    @property
    def summary(self) -> dict:
        counts = {}
        for f in self.findings:
            sev = f.severity.value if isinstance(f.severity, Severity) else str(f.severity)
            counts[sev] = counts.get(sev, 0) + 1
        return {
            "repo": self.repo_full_name,
            "branch": self.branch,
            "files_scanned": self.files_scanned,
            "total_findings": len(self.findings),
            "by_severity": counts,
            "modules_run": self.modules_run,
            "scan_duration_seconds": self.scan_duration_seconds,
        }

    def to_dict(self) -> dict:
        return {
            "repo_full_name": self.repo_full_name,
            "branch": self.branch,
            "findings": [f.to_dict() for f in self.findings],
            "files_scanned": self.files_scanned,
            "modules_run": self.modules_run,
            "sbom": self.sbom,
            "scan_duration_seconds": self.scan_duration_seconds,
            "summary": self.summary,
            "project_profile": self.project_profile,
        }
