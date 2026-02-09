"""Risk map data structures."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AggregateStats:
    total_scans: int = 0
    scans_by_week: dict[str, int] = field(default_factory=dict)
    capability_prevalence: dict[str, float] = field(default_factory=dict)
    trust_crossing_prevalence: dict[str, float] = field(default_factory=dict)
    guardrail_adoption_rate: float = 0.0
    guardrail_type_rates: dict[str, float] = field(default_factory=dict)
    avg_risk_score: float = 0.0
    risk_score_distribution: dict[str, int] = field(default_factory=dict)
    finding_prevalence: dict[str, float] = field(default_factory=dict)
    avg_mcp_servers: float = 0.0
    mcp_auth_rate: float = 0.0
    mcp_pinned_rate: float = 0.0

    # Topology distribution (populated when risk_map engine runs)
    topology_distribution: dict[str, int] = field(default_factory=dict)
    # Key: topology_signature_hash -> value: count of scans with that hash

    # Aggregate crossing adjacency (sum across all scans)
    aggregate_crossing_adjacency: dict[str, int] = field(default_factory=dict)
    # Key: directed crossing -> value: total count across all scans

    # Aggregate mitigation coverage (averages across all scans)
    aggregate_mitigation_coverage: dict[str, float] = field(default_factory=dict)
    # Key: coverage type -> value: mean rate across all scans

    # Archetype-level aggregates
    archetype_distribution: dict[str, int] = field(default_factory=dict)
    # Key: archetype_class hash -> value: count of scans

    archetype_baselines: dict[str, dict[str, float]] = field(default_factory=dict)
    # Key: archetype_class hash -> value: dict of baseline metrics

    archetype_control_adoption: dict[str, dict[str, float]] = field(default_factory=dict)
    # Key: archetype_class hash -> value: dict of control adoption rates


@dataclass
class RiskIntelligence:
    """Derived risk intelligence from aggregated telemetry.

    GROUPING RULE: All intelligence computations must group by STRUCTURAL
    fields only (archetype_class, topology_signature_hash, checkpoint_type,
    has_any_guardrails, mitigation_coverage ratios). Never group by scale
    fields (total_capabilities, capability_distribution counts, mcp_server_count).

    This rule ensures that intelligence derived from GitHub/consumer scans
    transfers to enterprise contexts without normalization.

    EXCEPTION: risk_score is a scale-adjacent field but is used in baselines
    because users expect it. Always present risk_score baselines ALONGSIDE
    structural comparisons, never as the sole dimension.
    """
    capability_combo_risk: dict[str, float] = field(default_factory=dict)
    guardrail_benchmarks: dict[str, float] = field(default_factory=dict)
    crossing_risk_correlation: dict[str, dict] = field(default_factory=dict)
    ecosystem_risk_trend: list[dict] = field(default_factory=list)

    # Archetype-specific intelligence
    archetype_insights: dict[str, list[str]] = field(default_factory=dict)
    # Key: archetype_class hash -> value: list of insight strings


@dataclass
class EnterpriseContext:
    """Enterprise-specific metadata that overlays a TelemetryProfile.

    THIS IS NOT PART OF TelemetryProfile. It exists as a separate data model
    that joins to profiles via scan_id. Enterprise customers attach this
    context when they upload scans to the Stratum platform.

    The intelligence layer can use EnterpriseContext for:
    - Filtering ("show me only production scans")
    - Segmenting ("compare our team's agents to the ecosystem")
    - Enriching ("this scan is from a regulated industry")

    But it must NEVER use EnterpriseContext for:
    - Grouping in archetype analysis (use archetype_class)
    - Computing baselines (use structural TelemetryProfile fields)
    - Training any model (structural fields only)
    """
    scan_id: str = ""
    org_id: str = ""
    team: str = ""
    environment: str = ""
    compliance_frameworks: list[str] = field(default_factory=list)
    deployment_context: str = ""
    has_centralized_auth: bool = False
    has_infra_retry_layer: bool = False
    has_policy_enforcement: bool = False
    notes: str = ""
