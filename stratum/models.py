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
    COMPOUNDING = "compounding"
    COMPLIANCE = "compliance"


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

    # Learning-related (populated by learning_risk scanner)
    has_memory: bool = False
    memory_type: str | None = None      # "vector", "conversation", "file", "custom"
    memory_store: str = ""              # e.g. "chromadb", "pinecone"
    memory_is_shared: bool = False
    writes_to_memory: bool = False
    reads_from_memory: bool = False


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
    graph_paths: list = field(default_factory=list)  # list[RiskPath] from graph
    crew_id: str = ""  # Which crew this finding belongs to, or "" for project-level


# ── Agent Relationship Models ────────────────────────────────

@dataclass
class AgentRelationship:
    """A directed relationship between two agents."""
    source_agent: str
    target_agent: str
    relationship_type: str  # "delegates_to", "feeds_into", "shares_tool"
    shared_resource: str = ""
    source_file: str = ""


@dataclass
class CrewDefinition:
    """A crew/team/flow grouping agents together."""
    name: str
    framework: str  # "CrewAI", "LangGraph", "AutoGen"
    agent_names: list[str] = field(default_factory=list)
    process_type: str = ""  # "sequential", "hierarchical", "parallel"
    source_file: str = ""
    has_manager: bool = False
    delegation_enabled: bool = False


# ── Blast Radius ────────────────────────────────────────────────

@dataclass
class BlastRadius:
    """Quantifies the impact of a single shared tool being compromised."""
    source_node_id: str
    source_label: str
    affected_agent_ids: list[str] = field(default_factory=list)
    affected_agent_labels: list[str] = field(default_factory=list)
    downstream_external_ids: list[str] = field(default_factory=list)
    downstream_external_labels: list[str] = field(default_factory=list)
    agent_count: int = 0
    external_count: int = 0
    crew_name: str = ""


# ── Incident Match Enhancement ────────────────────────────────

@dataclass
class IncidentMatch:
    """Enhanced incident match with explanation."""
    incident_id: str
    name: str
    date: str
    impact: str
    confidence: float
    attack_summary: str
    source_url: str
    match_reason: str = ""
    matching_capabilities: list[str] = field(default_factory=list)
    matching_files: list[str] = field(default_factory=list)


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
    detected_frameworks: list[str] = field(default_factory=list)

    graph: object | None = None  # RiskGraph, typed as object to avoid circular import

    diff: ScanDiff | None = None

    # File counts (for audit summary display)
    files_scanned: int = 0
    mcp_configs_scanned: int = 0
    env_files_scanned: int = 0

    # Agent relationships
    crew_definitions: list[CrewDefinition] = field(default_factory=list)
    agent_relationships: list[AgentRelationship] = field(default_factory=list)

    # Blast radius (from graph analysis)
    blast_radii: list[BlastRadius] = field(default_factory=list)

    # Learning & Governance
    agent_definitions: list = field(default_factory=list)  # list[AgentDefinition] from graph.agents
    incident_matches: list[IncidentMatch] = field(default_factory=list)
    learning_type: str | None = None
    has_learning_loop: bool = False
    has_shared_context: bool = False
    telemetry_destinations: list[str] = field(default_factory=list)
    has_eval_conflict: bool = False

    # Connectable surfaces (Sprint 1: CHAIN-PATCH)
    llm_models: list = field(default_factory=list)
    env_var_names_detected: list = field(default_factory=list)
    vector_stores_detected: list[str] = field(default_factory=list)
    framework_parse_quality: str = "unknown"


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
    version: str = "0.2.0"                               # [scale]

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

    # === Learning & Governance signals ===
    has_memory_store: bool = False                                        # [structural]
    memory_store_types: list[str] = field(default_factory=list)          # [structural]
    has_learning_loop: bool = False                                       # [structural]
    learning_type: str | None = None                                     # [structural]
    has_context_provenance: bool = False                                  # [structural]
    has_context_rollback: bool = False                                    # [structural]
    has_shared_context: bool = False                                      # [structural]
    telemetry_destination_count: int = 0                                  # [scale]
    has_eval_framework: bool = False                                      # [structural]
    has_eval_conflict: bool = False                                       # [structural]
    agent_count: int = 0                                                  # [scale]
    has_shared_credentials: bool = False                                  # [structural]
    has_agent_identity: bool = False                                      # [structural]

    # === Graph telemetry ===
    graph_node_count: int = 0                                             # [scale]
    graph_edge_count: int = 0                                             # [scale]
    graph_node_type_distribution: dict[str, int] = field(default_factory=dict)  # [scale]
    graph_edge_type_distribution: dict[str, int] = field(default_factory=dict)  # [scale]
    uncontrolled_path_count: int = 0                                      # [scale]
    max_path_hops: int = 0                                                # [scale]
    data_sensitivity_types: list[str] = field(default_factory=list)       # [structural]
    control_coverage_pct: float = 0.0                                     # [structural]
    regulatory_framework_count: int = 0                                   # [scale]
    downward_trust_crossings: int = 0                                     # [scale]

    # === Enriched topology (from STRATUM-EVAL-AND-PATCH) ===
    crew_count: int = 0                                                    # [scale]
    max_blast_radius: int = 0                                              # [structural]
    control_bypass_count: int = 0                                          # [scale]
    has_hitl_anywhere: bool = False                                         # [structural]
    has_observability: bool = False                                         # [structural]
    incident_match_count: int = 0                                          # [scale]
    incident_ids: list[str] = field(default_factory=list)                  # [structural]
    has_pii: bool = False                                                   # [structural]
    has_financial_data: bool = False                                        # [structural]
    edge_density: float = 0.0                                               # [structural]
    shared_tool_max_agents: int = 0                                         # [structural]
    external_sink_count: int = 0                                            # [scale]

    # === Finding class distribution (v4) ===
    findings_by_class: dict[str, int] = field(default_factory=dict)          # [structural]

    # === v0.2 enrichment ===
    findings_by_category: dict[str, int] = field(default_factory=dict)       # [scale]
    blast_radius_distribution: list[int] = field(default_factory=list)       # [scale]
    guardrail_linked_count: int = 0                                          # [scale]
    regulatory_surface: list[str] = field(default_factory=list)              # [structural]
    schema_version: str = "0.2"                                              # [structural]


# ── ScanProfile (Enterprise Intelligence Schema) ──────────────────────

@dataclass
class ScanProfile:
    """Complete anonymized scan profile for the intelligence database.
    Every field exists because it powers a specific enterprise query.

    Privacy contract:
    - No file paths, function names, agent names, or code content
    - Tool names and library names are included (open-source identifiers)
    - External service names are included (Gmail, Slack — not secret)
    - Crew names are hashed
    - All counts, ratios, booleans, and categorical values
    """

    # ─── IDENTITY ───────────────────────────────────────────────
    scan_id: str = ""
    topology_signature: str = ""
    schema_version: str = "2.0"
    scan_timestamp: str = ""
    scanner_version: str = ""

    # ─── PROJECT IDENTITY (Sprint 1: CHAIN-PATCH) ────────────────
    project_name: str = ""
    repo_url: str = ""
    org_id: str = ""
    branch: str = ""
    commit_sha: str = ""
    scan_source: str = "cli"
    project_hash: str = ""

    # ─── PARSE QUALITY ───────────────────────────────────────────
    framework_parse_quality: str = "unknown"

    # ─── ARCHITECTURE ───────────────────────────────────────────
    archetype: str = ""
    archetype_confidence: float = 0.0

    frameworks: list[str] = field(default_factory=list)
    framework_versions: dict[str, str] = field(default_factory=dict)

    agent_count: int = 0
    crew_count: int = 0
    files_scanned: int = 0
    is_monorepo: bool = False

    crew_sizes: list[int] = field(default_factory=list)
    crew_process_types: dict[str, int] = field(default_factory=dict)
    max_chain_depth: int = 0
    avg_crew_size: float = 0.0
    has_hierarchical_crew: bool = False
    has_delegation: bool = False

    # ─── TOOL INVENTORY ─────────────────────────────────────────
    tool_names: list[str] = field(default_factory=list)
    tool_count: int = 0
    tool_categories: dict[str, int] = field(default_factory=dict)

    libraries: list[str] = field(default_factory=list)

    capability_counts: dict[str, int] = field(default_factory=dict)
    outbound_to_data_ratio: float = 0.0

    tool_reuse_ratio: float = 0.0
    max_tool_sharing: int = 0
    tools_shared_by_3_plus: int = 0

    # ─── EXTERNAL SERVICES ──────────────────────────────────────
    external_services: list[str] = field(default_factory=list)
    external_service_count: int = 0

    data_sources: list[str] = field(default_factory=list)
    data_source_count: int = 0

    has_email_integration: bool = False
    has_messaging_integration: bool = False
    has_web_scraping: bool = False
    has_database_integration: bool = False
    has_file_system_access: bool = False
    has_financial_tools: bool = False
    has_code_execution: bool = False

    # ─── RISK PROFILE ───────────────────────────────────────────
    risk_score: int = 0
    risk_score_breakdown: dict[str, int] = field(default_factory=dict)
    risk_scores_per_crew: list[int] = field(default_factory=list)

    finding_ids: list[str] = field(default_factory=list)
    finding_count: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    findings_by_category: dict[str, int] = field(default_factory=dict)
    findings_by_class: dict[str, int] = field(default_factory=dict)

    # Anti-pattern flags
    has_unguarded_data_external: bool = False
    has_destructive_no_gate: bool = False
    has_blast_radius_3_plus: bool = False
    has_control_bypass: bool = False
    has_unvalidated_chain: bool = False
    has_shared_tool_bridge: bool = False
    has_no_error_handling: bool = False
    has_no_timeout: bool = False
    has_no_checkpointing: bool = False
    has_no_audit_trail: bool = False
    has_unreviewed_external_comms: bool = False
    has_no_cost_controls: bool = False

    # Incident pattern matching
    incident_matches: list[dict] = field(default_factory=list)
    incident_match_count: int = 0
    matches_echoleak: bool = False
    matches_any_breach: bool = False

    # ─── BLAST RADIUS ───────────────────────────────────────────
    blast_radii: list[dict] = field(default_factory=list)
    blast_radius_count: int = 0
    max_blast_radius: int = 0
    total_blast_surface: int = 0
    blast_radius_distribution: dict[str, int] = field(default_factory=dict)

    # ─── CONTROL MATURITY ───────────────────────────────────────
    guardrail_count: int = 0
    guardrail_types: dict[str, int] = field(default_factory=dict)
    guardrail_linked_count: int = 0
    guardrail_coverage_ratio: float = 0.0

    control_coverage_pct: float = 0.0

    has_hitl: bool = False
    has_structured_output: bool = False
    has_checkpointing: bool = False
    checkpoint_type: str = "none"
    has_observability: bool = False
    has_rate_limiting: bool = False
    has_error_handling: bool = False
    error_handling_ratio: float = 0.0
    has_input_validation: bool = False
    has_output_filtering: bool = False

    maturity_score: int = 0
    maturity_level: str = ""

    # ─── DATA FLOW ──────────────────────────────────────────────
    sensitive_data_types: list[str] = field(default_factory=list)
    has_pii_flow: bool = False
    has_financial_flow: bool = False
    has_credential_flow: bool = False

    uncontrolled_path_count: int = 0
    max_path_hops: int = 0
    trust_boundary_crossings: int = 0
    downward_crossings: int = 0

    has_inbox_to_outbound: bool = False
    has_scrape_to_action: bool = False
    has_db_to_external: bool = False
    has_file_to_external: bool = False

    # ─── REGULATORY EXPOSURE ────────────────────────────────────
    applicable_regulations: list[str] = field(default_factory=list)

    eu_ai_act_risk_level: str = ""
    eu_ai_act_articles: list[str] = field(default_factory=list)
    eu_ai_act_gap_count: int = 0

    gdpr_relevant: bool = False
    gdpr_articles: list[str] = field(default_factory=list)

    nist_ai_rmf_functions: list[str] = field(default_factory=list)

    compliance_gap_count: int = 0

    # ─── CONNECTABLE SURFACES (Sprint 1: CHAIN-PATCH) ──────────
    llm_models: list = field(default_factory=list)
    llm_providers: list[str] = field(default_factory=list)
    llm_model_count: int = 0
    has_multiple_providers: bool = False

    env_var_names: list = field(default_factory=list)
    env_var_names_specific: list = field(default_factory=list)

    vector_stores: list[str] = field(default_factory=list)
    has_vector_store: bool = False

    # ─── GRAPH TOPOLOGY ─────────────────────────────────────────
    node_count: int = 0
    edge_count: int = 0
    edge_density: float = 0.0
    agent_to_agent_edges: int = 0
    guardrail_edges: int = 0

    avg_node_degree: float = 0.0
    max_node_degree: int = 0
    isolated_agent_count: int = 0

    # ─── DELTA ──────────────────────────────────────────────────
    has_previous_scan: bool = False
    previous_risk_score: int = 0
    risk_score_delta: int = 0
    new_finding_ids: list[str] = field(default_factory=list)
    resolved_finding_ids: list[str] = field(default_factory=list)
    new_finding_count: int = 0
    resolved_finding_count: int = 0
    maturity_score_delta: int = 0

    # ─── WHAT-IF SIGNALS ────────────────────────────────────────
    what_if_controls: list[dict] = field(default_factory=list)
    top_recommendation: str = ""
    top_recommendation_impact: int = 0


# ── RepoContext (GitHub batch pipeline) ───────────────────────────────

@dataclass
class RepoContext:
    """Repository metadata from GitHub. NOT captured by the scanner.
    Added by the batch scan pipeline for public repos.
    Enterprise customers provide equivalent context through their own metadata.
    """

    # ─── REPO IDENTITY ──────────────────────────────────────────
    repo_hash: str = ""
    platform: str = "github"

    # ─── POPULARITY ─────────────────────────────────────────────
    stars: int = 0
    forks: int = 0
    watchers: int = 0
    open_issues: int = 0

    # ─── ACTIVITY ───────────────────────────────────────────────
    created_at: str = ""
    last_commit_at: str = ""
    days_since_last_commit: int = 0
    commit_count_90d: int = 0
    contributor_count: int = 0
    is_archived: bool = False
    is_active: bool = False

    # ─── STRUCTURE ──────────────────────────────────────────────
    primary_language: str = ""
    total_files: int = 0
    total_lines: int = 0
    has_tests: bool = False
    has_ci: bool = False
    has_dockerfile: bool = False
    has_requirements_txt: bool = False
    has_pyproject_toml: bool = False

    # ─── DOMAIN INFERENCE ───────────────────────────────────────
    domain_hint: str = ""
    domain_confidence: float = 0.0
    domain_signals: list[str] = field(default_factory=list)

    # ─── DEPENDENCY VERSIONS ────────────────────────────────────
    dependency_versions: dict[str, str] = field(default_factory=dict)
    outdated_dependencies: int = 0

    # ─── README ANALYSIS ────────────────────────────────────────
    has_readme: bool = False
    readme_mentions_security: bool = False
    readme_mentions_production: bool = False
    readme_length: int = 0
