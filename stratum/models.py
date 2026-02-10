from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone
import uuid


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    HEURISTIC = "heuristic"


class RiskCategory(str, Enum):
    SECURITY = "security"
    OPERATIONAL = "operational"
    BUSINESS = "business"


class TrustLevel(str, Enum):
    PRIVILEGED = "privileged"
    RESTRICTED = "restricted"
    INTERNAL = "internal"
    EXTERNAL = "external"
    PUBLIC = "public"


@dataclass
class Capability:
    """A dangerous capability found in a Python function.

    confidence determines how this was detected:
    - CONFIRMED: import resolved to call site (e.g. `import requests` + `requests.post()`)
    - PROBABLE: strong inference (e.g. SQL DELETE keyword in function body that has a DB import)
    - HEURISTIC: unresolved method (e.g. `.send()` on unknown object) - max severity MEDIUM
    """
    kind: str
    confidence: Confidence
    function_name: str
    source_file: str
    line_number: int
    evidence: str
    library: str
    trust_level: TrustLevel
    has_error_handling: bool = False
    has_timeout: bool = False
    has_input_validation: bool = False
    call_text: str = ""  # Actual source line text for remediation diffs. NOT in telemetry.


@dataclass
class MCPServer:
    name: str
    source_file: str
    command: str = ""
    url: str = ""
    args: list[str] = field(default_factory=list)
    env_vars_passed: list[str] = field(default_factory=list)
    transport: str = "unknown"
    is_remote: bool = False
    has_auth: bool = False
    npm_package: str = ""
    package_version: str = ""
    is_known_safe: bool = False
    known_incidents: list = field(default_factory=list)  # list[MCPIncident] from research


@dataclass
class GuardrailSignal:
    """Evidence of guardrails/safety patterns found in the project."""
    kind: str
    source_file: str
    line_number: int
    detail: str
    covers_tools: list[str] = field(default_factory=list)
    has_usage: bool = True


@dataclass
class Finding:
    id: str
    severity: Severity
    confidence: Confidence
    category: RiskCategory
    title: str
    path: str
    description: str
    evidence: list[str] = field(default_factory=list)
    scenario: str = ""
    business_context: str = ""
    remediation: str = ""
    effort: str = "low"
    references: list[str] = field(default_factory=list)
    owasp_id: str = ""
    owasp_name: str = ""        # e.g. "Agent Goal Hijacking"
    finding_class: str = "security"  # "reliability" | "operational" | "security"
    citation: dict | None = None  # For JSON output: {stat, source, url}
    quick_fix_type: str = ""  # Key into remediation TEMPLATES dict


@dataclass
class ScanResult:
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    directory: str = ""
    capabilities: list[Capability] = field(default_factory=list)
    mcp_servers: list[MCPServer] = field(default_factory=list)
    guardrails: list[GuardrailSignal] = field(default_factory=list)
    env_vars: list[str] = field(default_factory=list)

    top_paths: list[Finding] = field(default_factory=list)
    signals: list[Finding] = field(default_factory=list)

    risk_score: int = 0
    total_capabilities: int = 0
    outbound_count: int = 0
    data_access_count: int = 0
    code_exec_count: int = 0
    destructive_count: int = 0
    financial_count: int = 0
    mcp_server_count: int = 0
    guardrail_count: int = 0
    has_any_guardrails: bool = False
    checkpoint_type: str = "none"

    diff: ScanDiff | None = None


@dataclass
class ScanDiff:
    previous_risk_score: int = 0
    risk_score_delta: int = 0
    new_finding_ids: list[str] = field(default_factory=list)
    resolved_finding_ids: list[str] = field(default_factory=list)


@dataclass
class TelemetryProfile:
    """Anonymized structural risk profile. No source code, secrets, paths, function names, env values.

    SCHEMA RULES (non-negotiable):
    Every field must pass the context-blindness test:
    "Does this field have the same meaning and comparable values whether the source
    is a 50-line hobby script or a 50,000-line enterprise platform?"

    Fields are annotated [structural] or [scale]:
    - [structural] fields transfer across contexts and are used for archetype
      grouping, benchmarking, and enterprise intelligence.
    - [scale] fields are useful for individual scan dashboards but must NOT be
      used as grouping keys in the intelligence layer.

    PROHIBITED FIELDS (must never be added):
    - framework_name, framework_version (creates framework-specific clusters)
    - language_distribution (Python-only for now; irrelevant to risk structure)
    - file_count, line_count, repo_size (scale signals that separate GitHub from enterprise)
    - project_age, commit_count, contributor_count (context signals)
    - star_count, fork_count, popularity metrics (GitHub-specific)
    - org_name, team_name, environment (enterprise context — belongs in EnterpriseContext overlay)
    - any field derived from README content, docstrings, or comments
    - any field that requires network access to compute
    """
    scan_id: str = ""                                    # [scale]
    timestamp: str = ""                                  # [scale]
    version: str = "0.1.0"                               # [scale]

    # === Capability structure ===
    total_capabilities: int = 0                          # [scale]
    capability_distribution: dict[str, int] = field(default_factory=dict)  # [scale]
    trust_level_distribution: dict[str, int] = field(default_factory=dict)  # [scale]

    # === Trust crossings ===
    trust_crossings: dict[str, int] = field(default_factory=dict)  # [scale]
    total_trust_crossings: int = 0                       # [scale]

    # === Topology (telemetry primitives) ===
    topology_signature_hash: str = ""                    # [structural]
    trust_crossing_adjacency: dict[str, int] = field(default_factory=dict)  # [structural]

    # === Archetype ===
    archetype_class: str = ""                            # [structural]

    # === MCP ===
    mcp_server_count: int = 0                            # [scale]
    mcp_remote_count: int = 0                            # [scale]
    mcp_auth_ratio: float = 0.0                          # [structural]
    mcp_pinned_ratio: float = 0.0                        # [structural]

    # === Guardrails ===
    guardrail_count: int = 0                             # [scale]
    has_any_guardrails: bool = False                     # [structural]
    guardrail_types: list[str] = field(default_factory=list)  # [structural]

    # === Risk ===
    risk_score: int = 0                                  # [scale]
    finding_severities: dict[str, int] = field(default_factory=dict)  # [scale]
    finding_confidences: dict[str, int] = field(default_factory=dict)  # [scale]
    finding_rules: list[str] = field(default_factory=list)  # [structural]

    # === Environment ===
    env_var_count: int = 0                               # [scale]
    has_env_in_gitignore: bool = False                   # [structural]

    # === Operational signals ===
    error_handling_rate: float = 0.0                     # [structural]
    timeout_rate: float = 0.0                            # [structural]
    checkpoint_type: str = "none"                        # [structural]
    has_financial_tools: bool = False                    # [structural]
    financial_validation_rate: float = 0.0               # [structural]

    # === Mitigation coverage (telemetry primitives) ===
    mitigation_coverage: dict[str, float] = field(default_factory=dict)  # [structural]
