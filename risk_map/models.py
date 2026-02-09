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


@dataclass
class RiskIntelligence:
    capability_combo_risk: dict[str, float] = field(default_factory=dict)
    guardrail_benchmarks: dict[str, float] = field(default_factory=dict)
    crossing_risk_correlation: dict[str, dict] = field(default_factory=dict)
    ecosystem_risk_trend: list[dict] = field(default_factory=list)
