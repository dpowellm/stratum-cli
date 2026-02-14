"""Anonymized telemetry profile builder.

No source code, secrets, paths, function names, or env values.
Just counts and ratios.
"""
from __future__ import annotations

import hashlib
import logging
import os
import subprocess
from collections import Counter

from stratum.models import (
    Capability, Confidence, GuardrailSignal, ScanProfile, ScanResult,
    TelemetryProfile, TrustLevel,
)
from stratum.knowledge.db import HTTP_LIBRARIES
from stratum.telemetry.tools import categorize_tools, categorize_single_tool
from stratum.telemetry.maturity import compute_maturity_score
from stratum.telemetry.regulatory import compute_regulatory_exposure
from stratum.telemetry.what_if import compute_what_if_controls
from stratum import __version__

logger = logging.getLogger(__name__)

ENV_TO_PROVIDER: dict[str, dict] = {
    "OPENAI_API_KEY":        {"provider": "openai",       "confidence": "high"},
    "ANTHROPIC_API_KEY":     {"provider": "anthropic",    "confidence": "high"},
    "GOOGLE_API_KEY":        {"provider": "google",       "confidence": "medium"},
    "GOOGLE_GENAI_API_KEY":  {"provider": "google",       "confidence": "high"},
    "AZURE_OPENAI_API_KEY":  {"provider": "azure_openai", "confidence": "high"},
    "AZURE_OPENAI_ENDPOINT": {"provider": "azure_openai", "confidence": "high"},
    "GROQ_API_KEY":          {"provider": "groq",         "confidence": "high"},
    "TOGETHER_API_KEY":      {"provider": "together",     "confidence": "high"},
    "MISTRAL_API_KEY":       {"provider": "mistral",      "confidence": "high"},
    "COHERE_API_KEY":        {"provider": "cohere",       "confidence": "high"},
    "FIREWORKS_API_KEY":     {"provider": "fireworks",    "confidence": "high"},
    "DEEPSEEK_API_KEY":      {"provider": "deepseek",     "confidence": "high"},
    "XAI_API_KEY":           {"provider": "xai",          "confidence": "high"},
}


def infer_providers_from_env(
    env_var_names: list[str], detected_models: list,
) -> list[dict]:
    """Infer LLM providers from API key env vars when no models detected."""
    if detected_models:
        return []
    inferred = []
    seen: set[str] = set()
    for var_name in env_var_names:
        match = ENV_TO_PROVIDER.get(var_name)
        if match and match["provider"] not in seen:
            seen.add(match["provider"])
            inferred.append({
                "provider": match["provider"],
                "model": None,
                "source": "env_inference",
                "env_var": var_name,
                "confidence": match["confidence"],
            })
    return inferred


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
    archetype = _compute_archetype_class(caps, result)

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

    # Learning & governance signals
    has_memory = any(c.has_memory for c in result.capabilities)
    memory_types = list({c.memory_type for c in result.capabilities if c.memory_type})
    has_context_provenance = not any(f.id == "CONTEXT-001" for f in all_findings)
    has_context_rollback = not any(f.id == "CONTEXT-002" for f in all_findings)
    has_shared_creds = any(f.id == "IDENTITY-001" for f in all_findings)
    has_agent_identity = not any(f.id == "IDENTITY-002" for f in all_findings)

    # Graph telemetry (anonymized shape only - no node labels, IDs, or library names)
    graph_node_count = 0
    graph_edge_count = 0
    graph_node_type_dist: dict[str, int] = {}
    graph_edge_type_dist: dict[str, int] = {}
    graph_uncontrolled_path_count = 0
    graph_max_path_hops = 0
    graph_data_sensitivity_types: list[str] = []
    graph_control_coverage_pct = 0.0
    graph_regulatory_framework_count = 0
    graph_downward_trust_crossings = 0

    if result.graph is not None:
        graph = result.graph
        surface = graph.risk_surface
        graph_node_count = surface.total_nodes
        graph_edge_count = surface.total_edges
        graph_uncontrolled_path_count = surface.uncontrolled_path_count
        graph_max_path_hops = surface.max_path_hops
        graph_data_sensitivity_types = surface.sensitive_data_types
        graph_control_coverage_pct = round(surface.control_coverage_pct, 1)
        graph_regulatory_framework_count = len(surface.regulatory_frameworks)
        graph_downward_trust_crossings = surface.downward_crossings

        # Node type distribution (counts only, no labels)
        for node in graph.nodes.values():
            nt = node.node_type.value
            graph_node_type_dist[nt] = graph_node_type_dist.get(nt, 0) + 1

        # Edge type distribution (counts only, no source/target)
        for edge in graph.edges:
            et = edge.edge_type.value
            graph_edge_type_dist[et] = graph_edge_type_dist.get(et, 0) + 1

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
        # Learning & Governance
        has_memory_store=has_memory or result.has_learning_loop,
        memory_store_types=memory_types,
        has_learning_loop=result.has_learning_loop,
        learning_type=result.learning_type,
        has_context_provenance=has_context_provenance,
        has_context_rollback=has_context_rollback,
        has_shared_context=result.has_shared_context,
        telemetry_destination_count=len(result.telemetry_destinations),
        has_eval_framework=any(f.id in ("EVAL-001",) for f in all_findings) or not any(f.id == "EVAL-002" for f in all_findings),
        has_eval_conflict=result.has_eval_conflict,
        agent_count=len(getattr(result, 'agent_definitions', [])),
        has_shared_credentials=has_shared_creds,
        has_agent_identity=has_agent_identity,
        # Graph telemetry
        graph_node_count=graph_node_count,
        graph_edge_count=graph_edge_count,
        graph_node_type_distribution=graph_node_type_dist,
        graph_edge_type_distribution=graph_edge_type_dist,
        uncontrolled_path_count=graph_uncontrolled_path_count,
        max_path_hops=graph_max_path_hops,
        data_sensitivity_types=graph_data_sensitivity_types,
        control_coverage_pct=graph_control_coverage_pct,
        regulatory_framework_count=graph_regulatory_framework_count,
        downward_trust_crossings=graph_downward_trust_crossings,
        # Enriched topology
        crew_count=len(getattr(result, 'crew_definitions', [])),
        max_blast_radius=max(
            (br.agent_count for br in getattr(result, 'blast_radii', [])),
            default=0,
        ),
        control_bypass_count=len(getattr(result, '_control_bypasses', [])),
        has_hitl_anywhere=any(g.kind == "hitl" for g in result.guardrails),
        has_observability=not any(f.id == "TELEMETRY-003" for f in all_findings),
        incident_match_count=len(getattr(result, 'incident_matches', [])),
        incident_ids=[m.incident_id for m in getattr(result, 'incident_matches', [])],
        has_pii="personal" in graph_data_sensitivity_types,
        has_financial_data="financial" in graph_data_sensitivity_types,
        edge_density=(
            graph_edge_count / (graph_node_count * (graph_node_count - 1))
            if graph_node_count > 1 else 0.0
        ),
        shared_tool_max_agents=max(
            (br.agent_count for br in getattr(result, 'blast_radii', [])),
            default=0,
        ),
        external_sink_count=graph_node_type_dist.get("external", 0),
        # v4: findings by class
        findings_by_class={
            fc: sum(1 for f in all_findings if getattr(f, 'finding_class', 'security') == fc)
            for fc in {getattr(f, 'finding_class', 'security') for f in all_findings}
        },
        # v0.2 enrichment
        findings_by_category={
            cat: sum(1 for f in all_findings if f.category.value == cat)
            for cat in {f.category.value for f in all_findings}
        },
        blast_radius_distribution=sorted(
            [br.agent_count for br in getattr(result, 'blast_radii', [])],
            reverse=True,
        ),
        guardrail_linked_count=sum(
            1 for e in (result.graph.edges if result.graph else [])
            if e.edge_type.value in ("gated_by", "filtered_by")
        ),
        regulatory_surface=sorted({
            flag
            for p in (result.graph.uncontrolled_paths if result.graph else [])
            for flag in p.regulatory_flags
        }),
        schema_version="0.2",
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


def _compute_archetype_class(capabilities: list[Capability], result: ScanResult | None = None) -> str:
    """Classify the project into a human-readable archetype based on capabilities.

    Archetypes (checked in priority order):
    - multi_agent_orchestrator: 2+ agent nodes
    - code_agent: has code_exec capabilities
    - email_processor: has email/gmail data sources AND outbound
    - data_pipeline: has database/internal data sources AND outbound
    - rag_chatbot: has database/vector_db sources, no outbound to external
    - research_agent: has outbound (search) but no sensitive data sources
    - custom: doesn't match any pattern
    """
    kinds = {c.kind for c in capabilities if c.confidence != Confidence.HEURISTIC}
    if not kinds:
        return "custom"

    # Check agent count
    agent_count = len(getattr(result, 'agent_definitions', [])) if result else 0
    if agent_count >= 2:
        return "multi_agent_orchestrator"

    # Check code exec
    if "code_exec" in kinds:
        return "code_agent"

    # Check for email/messaging sources
    has_email_source = False
    has_db_source = False
    has_outbound = "outbound" in kinds
    email_keywords = ("gmail", "email", "mail", "smtp", "o365", "slack", "messaging")
    db_keywords = ("sql", "postgres", "mongo", "sqlite", "chromadb", "pinecone", "weaviate", "redis", "database")

    for cap in capabilities:
        lib_lower = cap.library.lower()
        fn_lower = cap.function_name.lower()
        combined = lib_lower + " " + fn_lower
        if cap.kind == "data_access":
            if any(kw in combined for kw in email_keywords):
                has_email_source = True
            if any(kw in combined for kw in db_keywords):
                has_db_source = True

    if has_email_source and has_outbound:
        return "email_processor"

    if has_db_source and has_outbound:
        return "data_pipeline"

    if has_db_source and not has_outbound:
        return "rag_chatbot"

    if has_outbound and not has_email_source and not has_db_source:
        return "research_agent"

    return "custom"


def _validate_profile(profile: TelemetryProfile) -> TelemetryProfile:
    """Validate that a telemetry profile contains no prohibited fields.

    Defensive, not blocking — logs warnings but never crashes.
    """
    # Check hash lengths
    if profile.topology_signature_hash and len(profile.topology_signature_hash) != 16:
        logger.warning("topology_signature_hash is not 16 chars: %s", profile.topology_signature_hash)
    valid_archetypes = (
        "email_processor", "rag_chatbot", "research_agent", "code_agent",
        "data_pipeline", "multi_agent_orchestrator", "custom", "",
    )
    if profile.archetype_class and profile.archetype_class not in valid_archetypes:
        logger.warning("Unknown archetype_class: %s", profile.archetype_class)

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


# ═══════════════════════════════════════════════════════════════════════
# ScanProfile builder (enterprise intelligence schema)
# ═══════════════════════════════════════════════════════════════════════

def build_scan_profile(
    result: ScanResult,
    previous_profile: ScanProfile | None = None,
) -> ScanProfile:
    """Build a full ScanProfile from a ScanResult.

    This is the enterprise intelligence profile with ~120 fields.
    Runs alongside build_profile() — does NOT replace it.
    """
    from stratum.graph.models import NodeType, EdgeType

    p = ScanProfile()
    graph = result.graph
    all_findings = result.top_paths + result.signals
    finding_id_set = set(f.id for f in all_findings)
    agents = getattr(result, "agent_definitions", [])
    crews = getattr(result, "crew_definitions", [])
    blast_radii = getattr(result, "blast_radii", [])

    # ── Identity ──
    p.scan_id = result.scan_id
    p.topology_signature = _compute_topology_hash(result)
    p.scan_timestamp = result.timestamp
    p.scanner_version = __version__

    # ── Architecture ──
    p.archetype = _compute_archetype_class(result.capabilities, result)
    p.archetype_confidence = 0.9
    p.frameworks = list(result.detected_frameworks)
    p.framework_versions = _detect_framework_versions(result.directory)
    p.agent_count = len(agents)
    p.crew_count = len(crews)
    p.files_scanned = result.files_scanned
    p.is_monorepo = len(crews) > 3

    p.crew_sizes = sorted(
        [len(c.agent_names) for c in crews], reverse=True
    )
    crew_proc: dict[str, int] = {}
    for c in crews:
        pt = c.process_type or "unknown"
        crew_proc[pt] = crew_proc.get(pt, 0) + 1
    p.crew_process_types = crew_proc
    p.avg_crew_size = (
        round(sum(p.crew_sizes) / len(p.crew_sizes), 1)
        if p.crew_sizes else 0.0
    )
    p.has_hierarchical_crew = any(
        c.process_type == "hierarchical" for c in crews
    )
    p.has_delegation = any(
        c.delegation_enabled or c.has_manager for c in crews
    )
    if graph is not None:
        p.max_chain_depth = graph.risk_surface.max_chain_depth

    # ── Tool inventory ──
    all_tools: set[str] = set()
    tool_assignments = 0
    for a in agents:
        for t in a.tool_names:
            all_tools.add(t)
            tool_assignments += 1

    p.tool_names = sorted(all_tools)
    p.tool_count = len(all_tools)
    p.tool_categories = categorize_tools(list(all_tools))
    p.libraries = sorted(set(c.library for c in result.capabilities if c.library))
    p.capability_counts = {
        "outbound": result.outbound_count,
        "data_access": result.data_access_count,
        "code_exec": result.code_exec_count,
        "destructive": result.destructive_count,
        "financial": result.financial_count,
    }
    p.outbound_to_data_ratio = round(
        result.outbound_count / max(result.data_access_count, 1), 2
    )
    p.tool_reuse_ratio = round(
        len(all_tools) / max(tool_assignments, 1), 2
    )

    # Per-crew tool sharing (dedup crews to avoid double-counting)
    max_sharing = 0
    tools_shared_3 = 0
    seen_crew_names: set[str] = set()
    for crew in crews:
        if crew.name in seen_crew_names:
            continue
        seen_crew_names.add(crew.name)
        crew_agents = set(crew.agent_names)
        tool_agent_count: dict[str, int] = {}
        for a in agents:
            if a.name in crew_agents:
                for t in a.tool_names:
                    tool_agent_count[t] = tool_agent_count.get(t, 0) + 1
        for count in tool_agent_count.values():
            max_sharing = max(max_sharing, count)
            if count >= 3:
                tools_shared_3 += 1
    p.max_tool_sharing = max_sharing
    p.tools_shared_by_3_plus = tools_shared_3

    # ── External services ──
    if graph is not None:
        p.external_services = sorted(set(
            n.label for n in graph.nodes.values()
            if n.node_type == NodeType.EXTERNAL_SERVICE
        ))
        p.data_sources = sorted(set(
            n.label for n in graph.nodes.values()
            if n.node_type == NodeType.DATA_STORE
        ))
    p.external_service_count = len(p.external_services)
    p.data_source_count = len(p.data_sources)

    # Service pattern flags
    all_tools_lower = {t.lower() for t in all_tools}
    libs_lower = {lib.lower() for lib in p.libraries}
    p.has_email_integration = any(
        "gmail" in t or "outlook" in t for t in all_tools_lower
    )
    p.has_messaging_integration = any(
        "slack" in l or "teams" in l for l in libs_lower
    )
    p.has_web_scraping = (
        any("scrape" in t for t in all_tools_lower)
        or "requests" in libs_lower
    )
    p.has_database_integration = any(
        "pg" in t or "mongo" in t or "chroma" in t
        for t in all_tools_lower
    )
    p.has_file_system_access = any("file" in t for t in all_tools_lower)
    p.has_financial_tools = any(
        "sec" in t or "calculator" in t or "finance" in t
        for t in all_tools_lower
    )
    p.has_code_execution = result.code_exec_count > 0

    # ── Risk profile ──
    p.risk_score = result.risk_score
    p.risk_scores_per_crew = _compute_per_crew_scores(all_findings, crews)
    p.risk_score_breakdown = _compute_risk_score_breakdown(
        result.top_paths, result.signals, result.guardrails,
    )

    p.finding_ids = sorted(set(f.id for f in all_findings))
    p.finding_count = len(all_findings)
    sev_counts: dict[str, int] = {}
    cat_counts: dict[str, int] = {}
    for f in all_findings:
        sv = f.severity.value.lower()
        sev_counts[sv] = sev_counts.get(sv, 0) + 1
        cv = f.category.value.lower()
        cat_counts[cv] = cat_counts.get(cv, 0) + 1
    p.findings_by_severity = sev_counts
    p.findings_by_category = cat_counts

    # v4: findings by class
    class_counts: dict[str, int] = {}
    for f in all_findings:
        fc = getattr(f, 'finding_class', 'security')
        class_counts[fc] = class_counts.get(fc, 0) + 1
    p.findings_by_class = class_counts

    # Anti-pattern flags
    p.has_unguarded_data_external = "STRATUM-001" in finding_id_set
    p.has_destructive_no_gate = "STRATUM-002" in finding_id_set
    p.has_blast_radius_3_plus = any(
        fid.startswith("STRATUM-CR05") for fid in finding_id_set
    )
    p.has_control_bypass = any(
        fid.startswith("STRATUM-CR06") for fid in finding_id_set
    )
    p.has_unvalidated_chain = "STRATUM-CR02" in finding_id_set
    p.has_shared_tool_bridge = "STRATUM-CR01" in finding_id_set
    p.has_no_error_handling = "STRATUM-008" in finding_id_set
    p.has_no_timeout = "STRATUM-009" in finding_id_set
    p.has_no_checkpointing = "STRATUM-010" in finding_id_set
    p.has_no_audit_trail = "STRATUM-BR03" in finding_id_set
    p.has_unreviewed_external_comms = "STRATUM-BR01" in finding_id_set
    p.has_no_cost_controls = "STRATUM-OP02" in finding_id_set

    # Incident matching
    incidents = getattr(result, "incident_matches", [])
    p.incident_matches = [
        {"id": m.incident_id, "confidence": m.confidence}
        for m in incidents
    ]
    p.incident_match_count = len(p.incident_matches)
    p.matches_echoleak = any(
        m.incident_id == "ECHOLEAK-2025" and m.confidence >= 0.75
        for m in incidents
    )
    p.matches_any_breach = any(m.confidence >= 0.75 for m in incidents)

    # ── Blast radius ──
    p.blast_radii = [
        {
            "tool": br.source_label,
            "tool_category": categorize_single_tool(br.source_label),
            "agent_count": br.agent_count,
            "external_count": br.external_count,
            "crew_hash": (
                hashlib.sha256(br.crew_name.encode()).hexdigest()[:8]
                if br.crew_name else ""
            ),
        }
        for br in blast_radii
    ]
    p.blast_radius_count = len(blast_radii)
    p.max_blast_radius = max(
        (br.agent_count for br in blast_radii), default=0
    )
    p.total_blast_surface = sum(br.agent_count for br in blast_radii)
    br_counts = [br.agent_count for br in blast_radii]
    p.blast_radius_distribution = (
        {str(k): br_counts.count(k) for k in set(br_counts)}
        if br_counts else {}
    )

    # ── Control maturity ──
    p.guardrail_count = len(result.guardrails)
    guard_kind_counts: dict[str, int] = {}
    for g in result.guardrails:
        guard_kind_counts[g.kind] = guard_kind_counts.get(g.kind, 0) + 1
    p.guardrail_types = guard_kind_counts
    p.guardrail_linked_count = sum(
        1 for g in result.guardrails if g.covers_tools
    )
    p.guardrail_coverage_ratio = round(
        p.guardrail_linked_count / max(p.guardrail_count, 1), 2
    )

    if graph is not None:
        p.control_coverage_pct = round(
            graph.risk_surface.control_coverage_pct, 1
        )

    p.has_hitl = any(g.kind == "hitl" for g in result.guardrails)
    p.has_structured_output = any(
        "output_pydantic" in g.detail for g in result.guardrails
    )
    p.has_checkpointing = result.checkpoint_type != "none"
    p.checkpoint_type = result.checkpoint_type
    p.has_observability = "TELEMETRY-003" not in finding_id_set
    p.has_rate_limiting = "STRATUM-OP02" not in finding_id_set
    p.has_error_handling = any(
        c.has_error_handling for c in result.capabilities
    )
    handled = sum(1 for c in result.capabilities if c.has_error_handling)
    p.error_handling_ratio = round(
        handled / max(len(result.capabilities), 1), 2
    )
    p.has_input_validation = any(
        c.has_input_validation for c in result.capabilities
    )
    p.has_output_filtering = any(
        g.kind == "output_filter" for g in result.guardrails
    )

    p.maturity_score, p.maturity_level = compute_maturity_score(
        has_hitl=p.has_hitl,
        has_structured_output=p.has_structured_output,
        has_observability=p.has_observability,
        has_error_handling=p.has_error_handling,
        error_handling_ratio=p.error_handling_ratio,
        checkpoint_type=p.checkpoint_type,
        has_checkpointing=p.has_checkpointing,
        has_input_validation=p.has_input_validation,
        has_rate_limiting=p.has_rate_limiting,
        has_output_filtering=p.has_output_filtering,
        guardrail_coverage_ratio=p.guardrail_coverage_ratio,
    )

    # ── Data flow ──
    if graph is not None:
        surface = graph.risk_surface
        p.sensitive_data_types = list(surface.sensitive_data_types)
        p.uncontrolled_path_count = surface.uncontrolled_path_count
        p.max_path_hops = surface.max_path_hops
        p.trust_boundary_crossings = surface.trust_boundary_crossings
        p.downward_crossings = surface.downward_crossings

    p.has_pii_flow = (
        "personal" in p.sensitive_data_types
        and p.uncontrolled_path_count > 0
    )
    p.has_financial_flow = "financial" in p.sensitive_data_types
    p.has_credential_flow = "credentials" in p.sensitive_data_types

    # Path pattern flags
    if graph is not None:
        ext_labels = {
            n.label.lower()
            for n in graph.nodes.values()
            if n.node_type == NodeType.EXTERNAL_SERVICE
        }
        p.has_inbox_to_outbound = (
            p.has_email_integration
            and any("gmail" in lbl or "email" in lbl for lbl in ext_labels)
        )
        _scrape_terms = ("scrape", "website")
        p.has_scrape_to_action = (
            p.has_web_scraping
            and p.external_service_count > 0
            and any(
                any(t in graph.nodes.get(e.source, GraphNode_stub).label.lower()
                    for t in _scrape_terms)
                for e in graph.edges
                if e.edge_type in (EdgeType.SENDS_TO, EdgeType.TOOL_OF)
            )
        )
        p.has_db_to_external = (
            p.has_database_integration and p.uncontrolled_path_count > 0
        )
        p.has_file_to_external = (
            p.has_file_system_access
            and any(
                "file" in graph.nodes.get(e.source, GraphNode_stub).label.lower()
                and e.edge_type == EdgeType.SHARES_WITH
                for e in graph.edges
            )
        )

    # ── Regulatory ──
    reg = compute_regulatory_exposure(
        has_financial_tools=p.has_financial_tools,
        has_credential_flow=p.has_credential_flow,
        has_pii_flow=p.has_pii_flow,
        has_observability=p.has_observability,
        has_structured_output=p.has_structured_output,
        has_hitl=p.has_hitl,
        has_no_error_handling=p.has_no_error_handling,
        has_input_validation=p.has_input_validation,
        has_no_audit_trail=p.has_no_audit_trail,
        uncontrolled_path_count=p.uncontrolled_path_count,
        maturity_score=p.maturity_score,
    )
    p.applicable_regulations = reg["applicable_regulations"]
    p.eu_ai_act_risk_level = reg["eu_ai_act_risk_level"]
    p.eu_ai_act_articles = reg["eu_ai_act_articles"]
    p.eu_ai_act_gap_count = reg["eu_ai_act_gap_count"]
    p.gdpr_relevant = reg["gdpr_relevant"]
    p.gdpr_articles = reg["gdpr_articles"]
    p.nist_ai_rmf_functions = reg["nist_ai_rmf_functions"]
    p.compliance_gap_count = reg["compliance_gap_count"]

    # ── Graph topology ──
    if graph is not None:
        p.node_count = len(graph.nodes)
        p.edge_count = len(graph.edges)
        n = p.node_count
        p.edge_density = round(
            p.edge_count / (n * (n - 1)), 4
        ) if n > 1 else 0.0

        p.agent_to_agent_edges = sum(
            1 for e in graph.edges
            if e.edge_type in (EdgeType.FEEDS_INTO, EdgeType.DELEGATES_TO)
        )
        p.guardrail_edges = sum(
            1 for e in graph.edges
            if e.edge_type in (EdgeType.GATED_BY, EdgeType.FILTERED_BY)
        )

        # Degree stats
        degrees: dict[str, int] = {}
        for e in graph.edges:
            degrees[e.source] = degrees.get(e.source, 0) + 1
            degrees[e.target] = degrees.get(e.target, 0) + 1
        if degrees:
            p.avg_node_degree = round(
                sum(degrees.values()) / len(degrees), 2
            )
            p.max_node_degree = max(degrees.values())

        # Isolated agents — only count data-flow edges, not tool_of
        agent_node_ids = set(
            nid for nid, node in graph.nodes.items()
            if node.node_type == NodeType.AGENT
        )
        data_flow_types = {
            EdgeType.FEEDS_INTO, EdgeType.SHARES_TOOL, EdgeType.SHARES_WITH,
            EdgeType.READS_FROM, EdgeType.SENDS_TO, EdgeType.WRITES_TO,
            EdgeType.GATED_BY, EdgeType.FILTERED_BY, EdgeType.DELEGATES_TO,
        }
        connected_agents: set[str] = set()
        for e in graph.edges:
            if e.edge_type in data_flow_types:
                if e.source in agent_node_ids:
                    connected_agents.add(e.source)
                if e.target in agent_node_ids:
                    connected_agents.add(e.target)
        p.isolated_agent_count = len(agent_node_ids - connected_agents)

    # ── Project identity + connectable surfaces ──
    p.project_name = os.path.basename(os.path.abspath(result.directory))
    p.project_hash = _compute_project_hash(result.directory)
    p.framework_parse_quality = getattr(result, "framework_parse_quality", "unknown")
    p.scan_source = "cli"

    # Git context (best-effort)
    git_remote = _detect_git_remote(result.directory)
    if git_remote:
        p.repo_url = git_remote
        # org_id from remote: github.com/org/repo → org
        parts = git_remote.rstrip("/").replace(".git", "").split("/")
        if len(parts) >= 2:
            p.org_id = parts[-2]
    git_branch, git_sha = _detect_git_ref(result.directory)
    p.branch = git_branch
    p.commit_sha = git_sha

    # LLM models
    llm_models = getattr(result, "llm_models", [])
    p.llm_models = llm_models
    providers = sorted(set(m["provider"] for m in llm_models))
    p.llm_providers = providers
    p.llm_model_count = len(llm_models)
    p.has_multiple_providers = len(providers) > 1

    # Env var names
    env_detected = getattr(result, "env_var_names_detected", [])
    p.env_var_names = env_detected
    p.env_var_names_specific = [
        e for e in env_detected if e.get("specificity") == "specific"
    ]

    # Provider inference from env vars (v5)
    if not llm_models:
        env_var_names = [e.get("name", "") for e in env_detected]
        inferred = infer_providers_from_env(env_var_names, llm_models)
        if inferred:
            p.llm_providers_inferred = inferred
            p.llm_providers = [ip["provider"] for ip in inferred]

    # Vector stores
    vs = getattr(result, "vector_stores_detected", [])
    p.vector_stores = vs
    p.has_vector_store = len(vs) > 0

    # ── Delta ──
    if previous_profile is not None:
        p.has_previous_scan = True
        p.previous_risk_score = previous_profile.risk_score
        p.risk_score_delta = p.risk_score - previous_profile.risk_score
        prev_ids = set(previous_profile.finding_ids)
        curr_ids = set(p.finding_ids)
        p.new_finding_ids = sorted(curr_ids - prev_ids)
        p.resolved_finding_ids = sorted(prev_ids - curr_ids)
        p.new_finding_count = len(p.new_finding_ids)
        p.resolved_finding_count = len(p.resolved_finding_ids)
        p.maturity_score_delta = p.maturity_score - previous_profile.maturity_score

    # ── What-if ──
    p.what_if_controls = compute_what_if_controls(
        all_findings, result.capabilities, result.guardrails
    )
    if p.what_if_controls:
        p.top_recommendation = p.what_if_controls[0]["control"]
        p.top_recommendation_impact = p.what_if_controls[0]["score_reduction"]

    return p


# ---------------------------------------------------------------------------
# Helpers for telemetry fixes (10/10 patch)
# ---------------------------------------------------------------------------

def _build_crew_directory_map(crews: list) -> dict[str, str]:
    """Map directory prefixes (first 2 path components) to crew names.

    ``flows/email_auto_responder_flow`` → ``EmailFilterCrew``
    ``crews/stock_analysis`` → ``StockAnalysisCrew``
    """
    crew_dirs: dict[str, str] = {}
    for crew in crews:
        sf = getattr(crew, "source_file", "") or ""
        if not sf:
            continue
        parts = sf.replace("\\", "/").split("/")
        if len(parts) >= 2:
            root = "/".join(parts[:2]).lower()
            crew_dirs[root] = crew.name
    return crew_dirs


def _compute_per_crew_scores(all_findings: list, crews: list) -> list[int]:
    """Attribute findings to crews by directory matching, return sorted scores."""
    crew_dir_map = _build_crew_directory_map(crews)
    crew_names = set(c.name for c in crews)
    sev_weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
    crew_scores: dict[str, int] = {}

    for f in all_findings:
        crew_name = ""
        evidence = f.evidence if hasattr(f, "evidence") else []
        title = f.title if hasattr(f, "title") else ""

        # Strategy 1: crew name in evidence strings
        evidence_str = str(evidence)
        for name in crew_names:
            if name in evidence_str:
                crew_name = name
                break

        # Strategy 2: file path directory match
        if not crew_name:
            for ev in evidence:
                ev_clean = ev.replace("\\", "/").lower()
                parts = ev_clean.split("/")
                if len(parts) >= 2:
                    ev_root = "/".join(parts[:2])
                    if ev_root in crew_dir_map:
                        crew_name = crew_dir_map[ev_root]
                        break

        # Strategy 3: crew name in title
        if not crew_name:
            for name in crew_names:
                if name in title:
                    crew_name = name
                    break

        if crew_name:
            sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            w = sev_weights.get(sev_val, 0)
            crew_scores[crew_name] = crew_scores.get(crew_name, 0) + w

    return sorted([min(s, 100) for s in crew_scores.values()], reverse=True)


def _compute_risk_score_breakdown(
    findings: list, signals: list, guardrails: list,
) -> dict[str, int]:
    """Decompose the risk score into component parts."""
    sev_map = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}

    base = 0
    for f in findings:
        sv = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        base += sev_map.get(sv, 0)

    signal_score = 0
    for s in signals:
        sv = s.severity.value if hasattr(s.severity, "value") else str(s.severity)
        signal_score += sev_map.get(sv, 0)

    # Bonus: no real guardrails
    guardrail_kinds = set(
        getattr(g, "kind", "") or "" for g in guardrails
    )
    bonus_no_guardrails = 10 if guardrail_kinds <= {"validation", ""} else 0

    # Bonus: no HITL
    bonus_no_hitl = 5 if "hitl" not in guardrail_kinds else 0

    raw = base + signal_score + bonus_no_guardrails + bonus_no_hitl
    final = max(0, min(raw, 100))

    return {
        "base_severity": base,
        "signal_severity": signal_score,
        "bonus_no_real_guardrails": bonus_no_guardrails,
        "bonus_no_hitl": bonus_no_hitl,
        "raw_total": raw,
        "final_capped": final,
    }


def _detect_framework_versions(directory: str) -> dict[str, str]:
    """Parse requirements.txt and pyproject.toml for framework versions."""
    import os
    import re

    versions: dict[str, str] = {}
    target_packages = {
        "crewai", "langchain", "langchain-core", "langchain-community",
        "langgraph", "autogen", "openai", "anthropic",
    }

    # Find requirements files (limit depth to avoid scanning too deep)
    req_files: list[str] = []
    for root, dirs, files in os.walk(directory):
        # Limit depth to 3 levels
        depth = root.replace(directory, "").count(os.sep)
        if depth > 3:
            dirs.clear()
            continue
        for fname in files:
            if fname in ("requirements.txt", "pyproject.toml"):
                req_files.append(os.path.join(root, fname))

    for req_file in req_files:
        try:
            with open(req_file, "r", encoding="utf-8") as f:
                content = f.read()

            if req_file.endswith("requirements.txt"):
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    for sep in ("==", ">=", "~=", "<=", ">", "<"):
                        if sep in line:
                            name, version = line.split(sep, 1)
                            name = name.strip().lower()
                            version = version.strip().split(",")[0].strip()
                            if name in target_packages and name not in versions:
                                versions[name] = version
                            break

            elif req_file.endswith("pyproject.toml"):
                for pkg in target_packages:
                    if pkg in versions:
                        continue
                    patterns = [
                        rf'"{re.escape(pkg)}[><=~!]*([0-9][0-9.]*)"',
                        rf"'{re.escape(pkg)}[><=~!]*([0-9][0-9.]*)'",
                        rf'{re.escape(pkg)}\s*=\s*"[><=~!]*([0-9][0-9.]*)"',
                    ]
                    for pattern in patterns:
                        match = re.search(pattern, content, re.IGNORECASE)
                        if match:
                            versions[pkg] = match.group(1)
                            break
        except (OSError, UnicodeDecodeError):
            continue

    return versions


class _GraphNodeStub:
    """Fallback for missing graph node lookups."""
    label = ""


GraphNode_stub = _GraphNodeStub()


# ---------------------------------------------------------------------------
# Project identity helpers (Sprint 1: CHAIN-PATCH)
# ---------------------------------------------------------------------------

def _compute_project_hash(directory: str) -> str:
    """Stable identifier for a project. Does NOT change when code changes.

    Based on git remote URL (preferred) or directory name (fallback).
    """
    remote_url = _detect_git_remote(directory)
    if remote_url:
        # Normalize: strip .git suffix, lowercase
        remote_url = remote_url.lower().rstrip("/")
        if remote_url.endswith(".git"):
            remote_url = remote_url[:-4]
        return hashlib.sha256(remote_url.encode()).hexdigest()[:16]

    # Fallback: directory name only (less reliable)
    dir_name = os.path.basename(os.path.abspath(directory))
    return hashlib.sha256(dir_name.encode()).hexdigest()[:16]


def _detect_git_remote(directory: str) -> str:
    """Detect git remote origin URL from .git/config or git CLI."""
    # Try reading .git/config directly (fast, no subprocess)
    git_config = os.path.join(directory, ".git", "config")
    if os.path.isfile(git_config):
        try:
            with open(git_config, encoding="utf-8", errors="ignore") as f:
                content = f.read()
            in_remote_origin = False
            for line in content.splitlines():
                stripped = line.strip()
                if stripped == '[remote "origin"]':
                    in_remote_origin = True
                    continue
                if in_remote_origin:
                    if stripped.startswith("["):
                        break
                    if stripped.startswith("url ="):
                        return stripped.split("=", 1)[1].strip()
        except OSError:
            pass

    # Fallback: try git CLI
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=directory, capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    return ""


def _detect_git_ref(directory: str) -> tuple[str, str]:
    """Detect current git branch and commit SHA.

    Returns (branch, commit_sha). Both may be empty strings on failure.
    """
    branch = ""
    sha = ""

    # Try .git/HEAD for branch
    head_file = os.path.join(directory, ".git", "HEAD")
    if os.path.isfile(head_file):
        try:
            with open(head_file, encoding="utf-8") as f:
                content = f.read().strip()
            if content.startswith("ref: refs/heads/"):
                branch = content[len("ref: refs/heads/"):]
                # Try to resolve the SHA
                ref_file = os.path.join(directory, ".git", content[5:])
                if os.path.isfile(ref_file):
                    with open(ref_file, encoding="utf-8") as f:
                        sha = f.read().strip()[:12]
            elif len(content) >= 12:
                # Detached HEAD
                sha = content[:12]
        except OSError:
            pass

    # Fallback: try git CLI
    if not branch:
        try:
            result = subprocess.run(
                ["git", "branch", "--show-current"],
                cwd=directory, capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                branch = result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

    if not sha:
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--short=12", "HEAD"],
                cwd=directory, capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                sha = result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

    return branch, sha
