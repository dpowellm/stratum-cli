""".stratum.yml config loader for Bucket B reliability findings.

Phase 11: Bucket B findings require configuration data that cannot be
inferred from code alone. The .stratum.yml file provides:
- Agent objective declarations (for OC-001 conflict detection)
- SLA/regulatory thresholds (for AB findings)
- Data freshness requirements (for SI-002)
- Business priority declarations

Schema:
    stratum:
      agents:
        <agent_name>:
          objective: <string>
          domain: <string>
          business_priority: critical | high | medium | low
          duty_class: request | approve | execute | review | reconcile
          sla:
            max_latency_ms: <int>
            max_error_rate: <float>
      data_stores:
        <store_name>:
          freshness_ttl_seconds: <int>
          domain: <string>
      regulatory:
        frameworks: [<string>]
        thresholds:
          daily_decision_limit: <int>
          requires_audit_trail: <bool>
      monitoring:
        volume_alert_threshold: <int>
        drift_detection: <bool>
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class AgentConfig:
    """Configuration for a single agent from .stratum.yml."""
    name: str
    objective: str = ""
    domain: str = ""
    business_priority: str = ""
    duty_class: str = ""
    sla_max_latency_ms: int = 0
    sla_max_error_rate: float = 0.0


@dataclass
class DataStoreConfig:
    """Configuration for a data store from .stratum.yml."""
    name: str
    freshness_ttl_seconds: int = 0
    domain: str = ""


@dataclass
class RegulatoryConfig:
    """Regulatory configuration from .stratum.yml."""
    frameworks: list[str] = field(default_factory=list)
    daily_decision_limit: int = 0
    requires_audit_trail: bool = False


@dataclass
class MonitoringConfig:
    """Monitoring configuration from .stratum.yml."""
    volume_alert_threshold: int = 0
    drift_detection: bool = False


@dataclass
class StratumConfig:
    """Parsed .stratum.yml configuration."""
    agents: dict[str, AgentConfig] = field(default_factory=dict)
    data_stores: dict[str, DataStoreConfig] = field(default_factory=dict)
    regulatory: RegulatoryConfig = field(default_factory=RegulatoryConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    has_config: bool = False


def load_stratum_config(project_dir: str) -> StratumConfig:
    """Load .stratum.yml from project directory.

    Returns StratumConfig with has_config=True if file exists and parses,
    otherwise returns empty config with has_config=False.
    """
    config = StratumConfig()

    # Look for .stratum.yml or .stratum.yaml
    for filename in (".stratum.yml", ".stratum.yaml"):
        config_path = os.path.join(project_dir, filename)
        if os.path.exists(config_path):
            try:
                import yaml
            except ImportError:
                logger.debug("PyYAML not installed, skipping .stratum.yml")
                return config

            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    raw = yaml.safe_load(f)
            except Exception as e:
                logger.warning("Failed to parse %s: %s", filename, e)
                return config

            if not isinstance(raw, dict):
                return config

            # Parse the 'stratum' key
            stratum = raw.get("stratum", raw)
            if not isinstance(stratum, dict):
                return config

            config.has_config = True
            _parse_agents(stratum, config)
            _parse_data_stores(stratum, config)
            _parse_regulatory(stratum, config)
            _parse_monitoring(stratum, config)
            return config

    return config


def _parse_agents(stratum: dict, config: StratumConfig) -> None:
    """Parse agents section."""
    agents_raw = stratum.get("agents", {})
    if not isinstance(agents_raw, dict):
        return

    for name, agent_raw in agents_raw.items():
        if not isinstance(agent_raw, dict):
            continue

        sla = agent_raw.get("sla", {})
        if not isinstance(sla, dict):
            sla = {}

        config.agents[str(name)] = AgentConfig(
            name=str(name),
            objective=str(agent_raw.get("objective", "")),
            domain=str(agent_raw.get("domain", "")),
            business_priority=str(agent_raw.get("business_priority", "")),
            duty_class=str(agent_raw.get("duty_class", "")),
            sla_max_latency_ms=int(sla.get("max_latency_ms", 0)),
            sla_max_error_rate=float(sla.get("max_error_rate", 0.0)),
        )


def _parse_data_stores(stratum: dict, config: StratumConfig) -> None:
    """Parse data_stores section."""
    stores_raw = stratum.get("data_stores", {})
    if not isinstance(stores_raw, dict):
        return

    for name, store_raw in stores_raw.items():
        if not isinstance(store_raw, dict):
            continue
        config.data_stores[str(name)] = DataStoreConfig(
            name=str(name),
            freshness_ttl_seconds=int(store_raw.get("freshness_ttl_seconds", 0)),
            domain=str(store_raw.get("domain", "")),
        )


def _parse_regulatory(stratum: dict, config: StratumConfig) -> None:
    """Parse regulatory section."""
    reg_raw = stratum.get("regulatory", {})
    if not isinstance(reg_raw, dict):
        return

    thresholds = reg_raw.get("thresholds", {})
    if not isinstance(thresholds, dict):
        thresholds = {}

    config.regulatory = RegulatoryConfig(
        frameworks=list(reg_raw.get("frameworks", [])),
        daily_decision_limit=int(thresholds.get("daily_decision_limit", 0)),
        requires_audit_trail=bool(thresholds.get("requires_audit_trail", False)),
    )


def _parse_monitoring(stratum: dict, config: StratumConfig) -> None:
    """Parse monitoring section."""
    mon_raw = stratum.get("monitoring", {})
    if not isinstance(mon_raw, dict):
        return

    config.monitoring = MonitoringConfig(
        volume_alert_threshold=int(mon_raw.get("volume_alert_threshold", 0)),
        drift_detection=bool(mon_raw.get("drift_detection", False)),
    )


def apply_config_to_graph(config: StratumConfig, graph) -> None:
    """Apply .stratum.yml config data to enriched graph nodes.

    This bridges Bucket B: config data populates node fields that
    enrichment couldn't infer from code alone.
    """
    if not config.has_config or not graph:
        return

    from stratum.graph.models import NodeType

    # Apply agent configs
    for nid, node in graph.nodes.items():
        if node.node_type != NodeType.AGENT:
            continue

        # Match by label (case-insensitive)
        label_lower = node.label.lower().replace(" ", "_").replace("-", "_")
        matched_config = None
        for name, agent_cfg in config.agents.items():
            cfg_name = name.lower().replace(" ", "_").replace("-", "_")
            if cfg_name == label_lower or cfg_name in label_lower or label_lower in cfg_name:
                matched_config = agent_cfg
                break

        if not matched_config:
            continue

        if matched_config.objective and not node.objective_tag:
            node.objective_tag = matched_config.objective
        if matched_config.domain and not node.agent_domain:
            node.agent_domain = matched_config.domain
        if matched_config.business_priority and not node.business_priority:
            node.business_priority = matched_config.business_priority
        if matched_config.duty_class and not node.duty_class:
            node.duty_class = matched_config.duty_class

    # Apply data store configs
    for nid, node in graph.nodes.items():
        if node.node_type != NodeType.DATA_STORE:
            continue

        label_lower = node.label.lower().replace(" ", "_").replace("-", "_")
        for name, ds_cfg in config.data_stores.items():
            cfg_name = name.lower().replace(" ", "_").replace("-", "_")
            if cfg_name == label_lower or cfg_name in label_lower or label_lower in cfg_name:
                if ds_cfg.freshness_ttl_seconds and not node.freshness_mechanism:
                    node.freshness_mechanism = "ttl"
                if ds_cfg.domain and not node.store_domain:
                    node.store_domain = ds_cfg.domain
                break
