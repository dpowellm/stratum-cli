"""Portability risk rules.

Detects vendor lock-in signals: single-provider coupling,
single-provider guardrails, and proprietary agent configs.
"""
from __future__ import annotations

import ast
import logging

from stratum.models import (
    Confidence, Finding, GuardrailSignal, RiskCategory, Severity,
)
from stratum.knowledge.learning_patterns import (
    MODEL_PROVIDERS, ABSTRACTION_LIBRARIES, PROPRIETARY_AGENT_IMPORTS,
)
from stratum.research.owasp import get_owasp

logger = logging.getLogger(__name__)


def evaluate(
    py_files: list[tuple[str, str]],
    guardrails: list[GuardrailSignal],
    telemetry_context: dict,
) -> list[Finding]:
    """Run portability risk rules."""
    findings: list[Finding] = []

    detected_models = telemetry_context.get("model_providers", [])
    unique_model_providers = {m["provider"] for m in detected_models}
    model_parents = {m["parent"] for m in detected_models}

    # Check for abstraction libraries
    has_abstraction = False
    has_proprietary_config = False
    proprietary_format = ""

    for file_path, content in py_files:
        try:
            tree = ast.parse(content)
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    if top in ABSTRACTION_LIBRARIES:
                        has_abstraction = True
            elif isinstance(node, ast.ImportFrom) and node.module:
                top = node.module.split(".")[0]
                if top in ABSTRACTION_LIBRARIES:
                    has_abstraction = True
                # Check proprietary imports
                for prop_import, prop_name in PROPRIETARY_AGENT_IMPORTS.items():
                    if node.module.startswith(prop_import):
                        has_proprietary_config = True
                        proprietary_format = prop_name

    # PORTABILITY-001: No abstraction layer
    if len(unique_model_providers) == 1 and not has_abstraction and model_parents:
        provider = list(unique_model_providers)[0]
        owasp_id, owasp_name = get_owasp("PORTABILITY-001")
        findings.append(Finding(
            id="PORTABILITY-001",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            category=RiskCategory.OPERATIONAL,
            title="Direct SDK calls to single model provider",
            path=f"All model calls use {provider} SDK directly",
            description=(
                f"All model calls use {provider} SDK directly with no abstraction "
                f"layer. Switching providers requires rewriting agent code."
            ),
            evidence=[m.get("file", "") for m in detected_models[:3]],
            remediation=(
                "Consider an abstraction: "
                "LiteLLM (drop-in OpenAI-compatible wrapper), "
                "LangChain (provider-agnostic interface), "
                "or a custom wrapper."
            ),
            owasp_id=owasp_id,
            owasp_name=owasp_name,
            finding_class="governance",
        ))

    # PORTABILITY-002: Single provider guardrails
    if guardrails:
        # Check if all guardrails come from one vendor
        guard_sources = set()
        for g in guardrails:
            if "nemo" in g.detail.lower():
                guard_sources.add("NVIDIA")
            elif "guardrails" in g.detail.lower() and "nemo" not in g.detail.lower():
                guard_sources.add("Guardrails AI")
            elif g.detail in ("InputGuardrail", "OutputGuardrail"):
                guard_sources.add("OpenAI")

        if len(guard_sources) == 1:
            provider = list(guard_sources)[0]
            owasp_id, owasp_name = get_owasp("PORTABILITY-002")
            findings.append(Finding(
                id="PORTABILITY-002",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                category=RiskCategory.OPERATIONAL,
                title="All safety controls depend on single provider",
                path=f"All detected guardrails use {provider}",
                description=(
                    f"All detected guardrails use {provider}. Provider outage or "
                    f"policy change removes all safety controls simultaneously."
                ),
                evidence=[f"{g.source_file}:{g.line_number}" for g in guardrails[:3]],
                remediation=(
                    "Add a local guardrail layer that works regardless of provider: "
                    "Guardrails AI (open source), NeMo Guardrails (NVIDIA), "
                    "or custom regex/rule-based pre-filter."
                ),
                owasp_id=owasp_id,
                owasp_name=owasp_name,
                finding_class="governance",
            ))

    # PORTABILITY-003: Non-portable agent config
    if has_proprietary_config:
        owasp_id, owasp_name = get_owasp("PORTABILITY-003")
        findings.append(Finding(
            id="PORTABILITY-003",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            category=RiskCategory.OPERATIONAL,
            title="Agent config in proprietary format",
            path=f"Agent defined via {proprietary_format}",
            description=(
                f"Agent is defined via {proprietary_format} with no open-standard equivalent. "
                f"Migration to an alternative requires significant rework."
            ),
            evidence=["(proprietary agent format detected)"],
            remediation=(
                "Document your agent's behavior spec independently of the provider: "
                "tool definitions, system prompt, guardrail rules."
            ),
            owasp_id=owasp_id,
            owasp_name=owasp_name,
            finding_class="governance",
        ))

    return findings
