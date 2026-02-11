"""Regulatory surface mapping for risk paths."""
from __future__ import annotations

from stratum.graph.models import GraphEdge


REGULATORY_MAP: list[dict] = [
    {
        "id": "gdpr_35",
        "label": "GDPR Art. 35",
        "description": "Data Protection Impact Assessment required",
        "triggers": {
            "data_sensitivity": ["personal"],
            "dest_trust": ["external"],
            "missing_controls": ["output_filter"],
        },
    },
    {
        "id": "eu_ai_14",
        "label": "EU AI Act Art. 14",
        "description": "Human oversight requirement",
        "triggers": {
            "data_sensitivity": ["personal", "financial"],
            "missing_controls": ["hitl"],
        },
    },
    {
        "id": "eu_ai_9",
        "label": "EU AI Act Art. 9",
        "description": "Risk management system required",
        "triggers": {
            "data_sensitivity": ["personal", "financial", "credentials"],
            "dest_trust": ["external"],
        },
    },
    {
        "id": "nist_map_1_5",
        "label": "NIST AI RMF MAP 1.5",
        "description": "Intended data use documentation",
        "triggers": {
            "data_sensitivity": ["personal", "financial"],
            "dest_trust": ["external"],
            "missing_controls": ["output_filter"],
        },
    },
    {
        "id": "nist_govern_1_2",
        "label": "NIST AI RMF GOVERN 1.2",
        "description": "Human oversight in AI risk management",
        "triggers": {
            "data_sensitivity": ["financial"],
            "missing_controls": ["hitl"],
        },
    },
    {
        "id": "sox_itgc",
        "label": "SOX ITGC",
        "description": "IT General Controls for financial systems",
        "triggers": {
            "data_sensitivity": ["financial"],
            "dest_trust": ["external"],
            "missing_controls": ["hitl", "validation"],
        },
    },
    {
        "id": "pci_dss_6",
        "label": "PCI DSS Req. 6",
        "description": "Secure development for payment systems",
        "triggers": {
            "data_sensitivity": ["financial"],
        },
    },
    {
        "id": "hipaa_safeguards",
        "label": "HIPAA Technical Safeguards",
        "description": "Access controls and audit trails for health data",
        "triggers": {
            "data_sensitivity": ["personal"],
            "missing_controls": ["output_filter", "hitl"],
        },
    },
]


def compute_regulatory_flags(
    sensitivity: str,
    dest_trust: str,
    missing_controls: list[str],
    path_edges: list[GraphEdge],
) -> list[str]:
    """Check which regulatory frameworks flag this risk path.

    Returns list of human-readable regulatory labels.
    """
    flags: list[str] = []
    for rule in REGULATORY_MAP:
        triggers = rule["triggers"]
        match = True

        if "data_sensitivity" in triggers:
            if sensitivity not in triggers["data_sensitivity"]:
                match = False

        if "dest_trust" in triggers:
            if dest_trust not in triggers["dest_trust"]:
                match = False

        if "missing_controls" in triggers:
            if not any(mc in triggers["missing_controls"] for mc in missing_controls):
                match = False

        if match:
            flags.append(rule["label"])

    return flags
