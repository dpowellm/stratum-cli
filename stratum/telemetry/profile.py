"""Anonymized telemetry profile builder.

No source code, secrets, paths, function names, or env values.
Just counts and ratios.
"""
from __future__ import annotations

import hashlib
import logging
from collections import Counter

from stratum.models import (
    Capability, Confidence, GuardrailSignal, ScanResult, TelemetryProfile, TrustLevel,
)
from stratum.knowledge.db import HTTP_LIBRARIES
from stratum import __version__

logger = logging.getLogger(__name__)


def build_profile(result: ScanResult) -> TelemetryProfile:
    """Build an anonymized telemetry profile from a ScanResult."""
    # Capability distribution
    cap_dist: dict[str, int] = {}
    trust_dist: dict[str, int] = {}
    for cap in result.capabilities:
        cap_dist[cap.kind] = cap_dist.get(cap.kind, 0) + 1
        tl = cap.trust_level.value
        trust_dist[tl] = trust_dist.get(tl, 0) + 1

    # Trust crossings (undirected, existing)
    trust_crossings: dict[str, int] = {}
    caps = result.capabilities
    seen_pairs: set[tuple[str, str]] = set()
    for i, c1 in enumerate(caps):
        for c2 in caps[i + 1:]:
            if c1.trust_level != c2.trust_level:
                pair = tuple(sorted([c1.trust_level.value, c2.trust_level.value]))
                pair_key = (pair[0], pair[1])
                if pair_key not in seen_pairs:
                    seen_pairs.add(pair_key)
                key = f"{pair[0]}\u2192{pair[1]}"
                trust_crossings[key] = trust_crossings.get(key, 0) + 1

    # Trust crossing adjacency (directed, new)
    crossing_adjacency = _compute_trust_crossing_adjacency(caps)

    # Topology signature hash
    topology_hash = _compute_topology_hash(result)

    # Archetype class
    archetype = _compute_archetype_class(caps)

    # MCP stats
    mcp_remote = sum(1 for s in result.mcp_servers if s.is_remote)
    mcp_auth = (
        sum(1 for s in result.mcp_servers if s.has_auth) / len(result.mcp_servers)
        if result.mcp_servers else 0.0
    )
    mcp_pinned = (
        sum(1 for s in result.mcp_servers if s.package_version) / len(result.mcp_servers)
        if result.mcp_servers else 0.0
    )

    # Guardrail types
    guard_types = list({g.kind for g in result.guardrails})

    # Finding severities and confidences
    all_findings = result.top_paths + result.signals
    sev_dist: dict[str, int] = {}
    conf_dist: dict[str, int] = {}
    for f in all_findings:
        sev_dist[f.severity.value] = sev_dist.get(f.severity.value, 0) + 1
        conf_dist[f.confidence.value] = conf_dist.get(f.confidence.value, 0) + 1

    # Finding rules (sorted unique rule IDs)
    finding_rules = sorted({f.id for f in all_findings})

    # Error handling rate
    external_caps = [
        c for c in result.capabilities
        if c.kind in ("outbound", "data_access", "financial")
    ]
    error_rate = (
        sum(1 for c in external_caps if c.has_error_handling) / len(external_caps)
        if external_caps else 0.0
    )

    # Timeout rate
    http_caps = [
        c for c in result.capabilities
        if c.kind == "outbound" and c.library in HTTP_LIBRARIES
    ]
    timeout_rate = (
        sum(1 for c in http_caps if c.has_timeout) / len(http_caps)
        if http_caps else 0.0
    )

    # Financial validation rate
    fin_caps = [c for c in result.capabilities if c.kind == "financial"]
    fin_val_rate = (
        sum(1 for c in fin_caps if c.has_input_validation) / len(fin_caps)
        if fin_caps else 0.0
    )

    # Mitigation coverage
    coverage = _compute_mitigation_coverage(result.capabilities, result.guardrails)

    profile = TelemetryProfile(
        scan_id=result.scan_id,
        timestamp=result.timestamp,
        version=__version__,
        total_capabilities=result.total_capabilities,
        capability_distribution=cap_dist,
        trust_level_distribution=trust_dist,
        trust_crossings=trust_crossings,
        total_trust_crossings=sum(trust_crossings.values()),
        topology_signature_hash=topology_hash,
        trust_crossing_adjacency=crossing_adjacency,
        archetype_class=archetype,
        mcp_server_count=result.mcp_server_count,
        mcp_remote_count=mcp_remote,
        mcp_auth_ratio=round(mcp_auth, 2),
        mcp_pinned_ratio=round(mcp_pinned, 2),
        guardrail_count=result.guardrail_count,
        has_any_guardrails=result.has_any_guardrails,
        guardrail_types=guard_types,
        risk_score=result.risk_score,
        finding_severities=sev_dist,
        finding_confidences=conf_dist,
        finding_rules=finding_rules,
        env_var_count=len(result.env_vars),
        has_env_in_gitignore=False,
        error_handling_rate=round(error_rate, 2),
        timeout_rate=round(timeout_rate, 2),
        checkpoint_type=result.checkpoint_type,
        has_financial_tools=any(c.kind == "financial" for c in result.capabilities),
        financial_validation_rate=round(fin_val_rate, 2),
        mitigation_coverage=coverage,
    )

    return _validate_profile(profile)


def _compute_topology_hash(result: ScanResult) -> str:
    """Compute a stable hash of the project's capability topology.

    Encodes:
    1. Sorted set of capability kinds present (non-heuristic only)
    2. Sorted set of directed trust crossings that exist (presence, not count)
    3. Boolean: has_financial (any financial capability)
    4. checkpoint_type string

    Returns first 16 hex chars of SHA-256. Irreversible.
    """
    confirmed_caps = [
        c for c in result.capabilities if c.confidence != Confidence.HEURISTIC
    ]
    if not confirmed_caps:
        return ""

    sorted_kinds = sorted({c.kind for c in confirmed_caps})

    # Directed crossing keys present
    trust_levels = {c.trust_level for c in confirmed_caps}
    crossings: set[str] = set()
    for a in trust_levels:
        for b in trust_levels:
            if a != b:
                crossings.add(f"{a.value}\u2192{b.value}")
    sorted_crossings = sorted(crossings)

    structure: list[tuple[str, object]] = []
    for kind in sorted_kinds:
        structure.append(("kind", kind))
    for crossing in sorted_crossings:
        structure.append(("crossing", crossing))
    structure.append(("has_financial", any(c.kind == "financial" for c in confirmed_caps)))
    structure.append(("checkpoint_type", result.checkpoint_type))

    canonical = "|".join(f"{k}={v}" for k, v in structure)
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    return digest[:16]


def _compute_trust_crossing_adjacency(capabilities: list[Capability]) -> dict[str, int]:
    """Compute directed trust-crossing adjacency counts.

    Uses O(k^2) where k is the number of distinct trust levels (max 5).
    For each ordered pair of distinct levels (a, b), the count is
    level_counts[a] * level_counts[b].
    """
    non_heuristic = [c for c in capabilities if c.confidence != Confidence.HEURISTIC]
    level_counts: dict[TrustLevel, int] = Counter(c.trust_level for c in non_heuristic)

    adjacency: dict[str, int] = {}
    for a, count_a in level_counts.items():
        for b, count_b in level_counts.items():
            if a != b:
                key = f"{a.value}\u2192{b.value}"
                product = count_a * count_b
                if product > 0:
                    adjacency[key] = product

    return adjacency


def _compute_mitigation_coverage(
    capabilities: list[Capability],
    guardrails: list[GuardrailSignal],
) -> dict[str, float]:
    """Compute mitigation coverage ratios for three key capability-guardrail pairs."""
    # outbound_output_filter_rate
    outbound_caps = [
        c for c in capabilities
        if c.kind == "outbound" and c.confidence != Confidence.HEURISTIC
    ]
    has_active_output_filter = any(
        g.kind == "output_filter" and g.has_usage for g in guardrails
    )
    outbound_rate = 1.0 if (outbound_caps and has_active_output_filter) else 0.0
    if not outbound_caps:
        outbound_rate = 0.0

    # destructive_hitl_rate
    destructive_caps = [
        c for c in capabilities
        if c.kind == "destructive" and c.confidence != Confidence.HEURISTIC
    ]
    if destructive_caps:
        hitl_guards = [g for g in guardrails if g.kind == "hitl"]
        covered = 0
        for cap in destructive_caps:
            for g in hitl_guards:
                if not g.covers_tools or cap.function_name in g.covers_tools:
                    covered += 1
                    break
        destructive_rate = covered / len(destructive_caps)
    else:
        destructive_rate = 0.0

    # financial_validation_rate
    financial_caps = [
        c for c in capabilities
        if c.kind == "financial" and c.confidence != Confidence.HEURISTIC
    ]
    if financial_caps:
        financial_rate = sum(1 for c in financial_caps if c.has_input_validation) / len(financial_caps)
    else:
        financial_rate = 0.0

    return {
        "outbound_output_filter_rate": round(outbound_rate, 2),
        "destructive_hitl_rate": round(destructive_rate, 2),
        "financial_validation_rate": round(financial_rate, 2),
    }


def _compute_archetype_class(capabilities: list[Capability]) -> str:
    """Compute a coarse archetype hash from capability-kind presence.

    Encodes ONLY which capability kinds exist (non-heuristic).
    SHA-256, first 12 hex chars (shorter than topology hash to distinguish).
    Returns empty string if no confirmed capabilities.
    """
    kinds = sorted({c.kind for c in capabilities if c.confidence != Confidence.HEURISTIC})
    if not kinds:
        return ""
    canonical = "|".join(kinds)
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    return digest[:12]


def _validate_profile(profile: TelemetryProfile) -> TelemetryProfile:
    """Validate that a telemetry profile contains no prohibited fields.

    Defensive, not blocking — logs warnings but never crashes.
    """
    # Check hash lengths
    if profile.topology_signature_hash and len(profile.topology_signature_hash) != 16:
        logger.warning("topology_signature_hash is not 16 chars: %s", profile.topology_signature_hash)
    if profile.archetype_class and len(profile.archetype_class) != 12:
        logger.warning("archetype_class is not 12 chars: %s", profile.archetype_class)

    # Check ratio fields in [0.0, 1.0]
    ratio_fields = [
        ("mcp_auth_ratio", profile.mcp_auth_ratio),
        ("mcp_pinned_ratio", profile.mcp_pinned_ratio),
        ("error_handling_rate", profile.error_handling_rate),
        ("timeout_rate", profile.timeout_rate),
        ("financial_validation_rate", profile.financial_validation_rate),
    ]
    for name, value in ratio_fields:
        if not (0.0 <= value <= 1.0):
            logger.warning("Ratio field %s outside [0.0, 1.0]: %s", name, value)

    # Check mitigation_coverage values
    for key, value in profile.mitigation_coverage.items():
        if not (0.0 <= value <= 1.0):
            logger.warning("mitigation_coverage[%s] outside [0.0, 1.0]: %s", key, value)

    # Check checkpoint_type
    valid_checkpoints = {"durable", "memory_only", "none"}
    if profile.checkpoint_type not in valid_checkpoints:
        logger.warning("checkpoint_type not in %s: %s", valid_checkpoints, profile.checkpoint_type)

    # Check version
    if profile.version != __version__:
        logger.warning("Profile version %s != CLI version %s", profile.version, __version__)

    # Check for path fragments in string fields
    for field_name in ("scan_id", "timestamp", "version", "checkpoint_type",
                       "topology_signature_hash", "archetype_class"):
        value = getattr(profile, field_name)
        if isinstance(value, str) and ("\\" in value or "/" in value):
            logger.warning("String field %s contains path separator: %s", field_name, value)

    return profile
