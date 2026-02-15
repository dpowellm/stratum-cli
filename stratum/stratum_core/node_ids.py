"""Canonical node ID generation logic.

All node IDs are deterministic strings derived from stable properties.
Both stratum-cli and stratum-lab must produce identical IDs for the same entity.
"""
from __future__ import annotations

import re


def _slugify(name: str) -> str:
    """Convert a name to a URL-safe slug."""
    return re.sub(r"[^a-z0-9_]", "_", name.lower().strip()).strip("_")


def capability_node_id(class_name: str, kind: str) -> str:
    return f"cap_{_slugify(class_name)}_{kind}"


def agent_node_id(agent_name: str) -> str:
    return f"agent_{_slugify(agent_name)}"


def data_store_node_id(store_name: str) -> str:
    return f"ds_{_slugify(store_name)}"


def service_node_id(service_name: str) -> str:
    return f"ext_{_slugify(service_name)}"


def mcp_node_id(server_name: str) -> str:
    return f"mcp_{_slugify(server_name)}"


def guardrail_node_id(kind: str, line_number: int) -> str:
    return f"guard_{kind}_{line_number}"


def observability_node_id(sink_name: str) -> str:
    return f"obs_{_slugify(sink_name)}"
